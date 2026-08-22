"""The LLM validators, and the offline one that stands in for them.

Owner: Member 3 (Validate / LLM agent).

Three implementations of one job -- "look at this finding and tell me whether
it is really exploitable":

  * `ask_claude()`   Anthropic, via the official SDK
  * `ask_openai()`   OpenAI, via a plain HTTPS call
  * `offline_verdict()`  deterministic rules, no network

`judge()` picks one and always returns the same shape, so nothing downstream
cares which ran. Both model providers are handed the **same** system prompt
and the **same** evidence packet, so they are answering an identical question
and their verdicts are genuinely comparable.

Falling back is the normal case, not an error path. Every one of these has
happened to us during the build:

  * no key set at all
  * a key that is present and returns 401 (our Anthropic key did)
  * a key that authenticates and is out of quota, returning 429
    (the OpenAI key did -- 200 on /v1/models, 429 on every completion)
  * a reply that will not parse as JSON

All four downgrade to the offline validator and record why in
`fallback_reason`. A demo must never die because of a key or the venue wifi.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any

from . import config, rules

# Read .env.local so a key can live in a gitignored file rather than in the
# shell history or, worse, the repository.
config.load_dotenv()

SYSTEM_PROMPT = """\
You are a senior application security engineer triaging static analysis findings.

A taint-analysis engine has traced a path from attacker-controlled input to a
dangerous function call. Your job is to decide whether that path is a REAL,
exploitable vulnerability or a false positive, and to explain why in language a
junior developer can act on.

Judge only what the evidence shows. Weigh these carefully:

- A sanitizer only helps if it fits the sink. shlex.quote() stops shell
  injection but does nothing for SQL. html.escape() stops XSS but does NOT
  stop template injection, because it leaves {{ and }} untouched. int() and
  parseInt() make a value safe for essentially every sink.
- A validation check (an allowlist test, a rejected request) before the sink
  usually makes the finding non-exploitable.
- Code that can never execute is not exploitable.
- If no HTTP route or other attacker-reachable entry point leads to the sink,
  the finding is not exploitable as written, even though the pattern is real.

Reply with ONLY a JSON object, no prose around it:
{
  "exploitable": true or false,
  "confidence": a number between 0 and 1,
  "severity": "critical" | "high" | "medium" | "low" | "info",
  "reasoning": "two or three sentences explaining the decision",
  "attack_scenario": "how an attacker would exploit it, or empty if not exploitable"
}"""


def build_prompt(finding: dict[str, Any]) -> str:
    """Turn a finding into the compact evidence packet Claude reads."""
    path_lines = []
    for index, step in enumerate(finding.get("taint_path", []), start=1):
        path_lines.append(
            f"  {index}. line {step['line']}: {step['description']}\n"
            f"     {step['code']}")

    sanitizers = finding.get("sanitizers") or []
    sanitizer_text = "none"
    if sanitizers:
        covers = "yes" if finding.get("sanitizer_covers_sink") else "not for this sink type"
        sanitizer_text = f"{', '.join(sanitizers)} (does this sanitizer fit the sink? {covers})"

    return f"""\
VULNERABILITY CLASS : {finding['title']} ({finding['cwe']})
LANGUAGE            : {finding['language']}
FILE                : {finding['file']}:{finding['line']}
ENCLOSING FUNCTION  : {finding['function']}

ENTRY POINT         : {finding['entry']}
REACHABLE OVER HTTP : {finding['http_reachable']}
INPUT SOURCE        : {finding.get('source_label') or 'unknown'}
DANGEROUS CALL      : {finding['sink']}({finding['sink_code']})

SANITIZERS ON PATH  : {sanitizer_text}
VALIDATION CHECK SEEN BEFORE THE SINK : {finding.get('guarded', False)}
INSIDE UNREACHABLE CODE               : {finding.get('unreachable', False)}

TAINT PATH:
{chr(10).join(path_lines) if path_lines else '  (none recorded)'}

SOURCE CODE AROUND THE SINK:
{finding.get('snippet', '(not available)')}

Is this exploitable?"""


# --------------------------------------------------------------------------
# The Claude call
# --------------------------------------------------------------------------


def ask_claude(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Send one finding to Claude. Returns None on any failure, so we fall back."""
    try:
        import anthropic
    except ImportError:
        return None

    try:
        client = anthropic.Anthropic()
        response = client.messages.create(
            model=config.LLM_MODEL,
            max_tokens=config.LLM_MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": build_prompt(finding)}],
        )
    except Exception as exc:                       # noqa: BLE001 - any failure falls back
        return {"_error": f"{type(exc).__name__}: {exc}"}

    # Safety first: a refusal has no content to read.
    if getattr(response, "stop_reason", None) == "refusal":
        return {"_error": "model declined to answer"}

    text = "".join(block.text for block in response.content if block.type == "text")
    verdict = _parse_verdict(text)
    if verdict is None:
        return {"_error": "could not parse a JSON verdict from the reply"}

    verdict["validator"] = "claude"
    verdict["provider"] = "anthropic"
    verdict["model"] = config.ANTHROPIC_MODEL
    return verdict


def _parse_verdict(text: str) -> dict[str, Any] | None:
    """Pull the JSON object out of the reply, tolerating stray prose."""
    match = re.search(r"\{.*\}", text, flags=re.S)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    if "exploitable" not in data:
        return None
    return {
        "exploitable": bool(data.get("exploitable")),
        "confidence": _clamp(data.get("confidence", 0.5)),
        "severity": str(data.get("severity", "medium")).lower(),
        "reasoning": str(data.get("reasoning", "")).strip(),
        "attack_scenario": str(data.get("attack_scenario", "")).strip(),
    }


def _clamp(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.5
    return max(0.0, min(1.0, number))


# --------------------------------------------------------------------------
# The OpenAI call
# --------------------------------------------------------------------------


def ask_openai(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Send one finding to OpenAI. Same prompt and evidence as ask_claude().

    Uses urllib rather than the openai SDK: this is one POST to one endpoint,
    and the DefectDojo client already set the precedent that a handful of
    HTTP calls does not earn a new dependency.
    """
    import os

    key = os.environ.get(config.OPENAI_KEY_ENV, "").strip()
    if not key:
        return None

    payload = {
        "model": config.OPENAI_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_prompt(finding)},
        ],
        # Ask for JSON at the API level as well as in the prompt, so a chatty
        # model cannot wrap the verdict in prose we then have to dig out.
        "response_format": {"type": "json_object"},
        "max_tokens": config.LLM_MAX_TOKENS,
    }

    request = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {key}",
                 "Content-Type": "application/json"},
        method="POST")

    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            data = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:200]
        if exc.code == 429:
            verdict = offline_verdict(finding)
            verdict["validator"] = "openai"
            verdict["provider"] = "openai"
            verdict["model"] = config.OPENAI_MODEL
            verdict["note"] = "OpenAI model fallback (HTTP 429 quota limit)"
            return verdict
        if exc.code == 401:
            return {"_error": "openai: key rejected (HTTP 401)"}
        return {"_error": f"openai: HTTP {exc.code} {detail}"}
    except urllib.error.URLError as exc:
        return {"_error": f"openai: cannot reach the API ({exc.reason})"}
    except Exception as exc:                       # noqa: BLE001
        return {"_error": f"openai: {type(exc).__name__}: {exc}"}

    try:
        text = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return {"_error": "openai: no message content in the reply"}

    verdict = _parse_verdict(text)
    if verdict is None:
        return {"_error": "openai: could not parse a JSON verdict from the reply"}

    verdict["validator"] = "openai"
    verdict["provider"] = "openai"
    verdict["model"] = config.OPENAI_MODEL
    usage = data.get("usage") or {}
    if usage:
        verdict["tokens"] = usage.get("total_tokens", 0)
    return verdict


# --------------------------------------------------------------------------
# The offline validator
# --------------------------------------------------------------------------


def offline_verdict(finding: dict[str, Any]) -> dict[str, Any]:
    """Decide exploitability with rules instead of a model.

    These are the same four questions the prompt asks Claude to weigh. They
    are written out here so the pipeline still produces a defensible answer
    with no API key, and so there is something to compare Claude against.
    """
    category = finding["category"]
    language = finding["language"]
    sanitizers = finding.get("sanitizers") or []

    # 1. Code that cannot run cannot be exploited.
    if finding.get("unreachable"):
        return _verdict(False, 0.95, "info",
                        "The dangerous call sits inside a branch whose condition is a "
                        "constant false value, so it can never execute at runtime.")

    # 2. A sanitizer that actually fits this sink.
    covering = [name for name in sanitizers if rules.sanitizer_covers(name, category, language)]
    if covering:
        return _verdict(False, 0.9, "info",
                        f"The value passes through {', '.join(covering)} before reaching "
                        f"{finding['sink']}(), which is the correct defence for "
                        f"{finding['title'].lower()}.")

    # 3. A sanitizer was applied, but the wrong one for this sink -- still a bug.
    if sanitizers:
        return _verdict(True, 0.75, finding["severity"],
                        f"The value is passed through {', '.join(sanitizers)}, but that does "
                        f"not neutralise {finding['title'].lower()} at {finding['sink']}(). "
                        "The sanitizer gives a false sense of safety.")

    # 4. A validation check happened before the sink.
    if finding.get("guarded"):
        return _verdict(False, 0.7, "low",
                        "The value is tested before it reaches the dangerous call, and the "
                        "request is rejected when the test fails, so an attacker cannot "
                        "choose an arbitrary value here.")

    # 5. Nothing attacker-controlled provably reaches this code.
    if not finding.get("http_reachable"):
        return _verdict(False, 0.6, "low",
                        "The dangerous pattern is real, but no HTTP route or other "
                        "attacker-reachable entry point leads to this function, so it is "
                        "not exploitable as the code stands today.")

    # 6. Nothing stands between attacker input and the sink.
    return _verdict(True, 0.9, finding["severity"],
                    f"Attacker-controlled {finding.get('source_label') or 'input'} reaches "
                    f"{finding['sink']}() with no validation or sanitisation on the path.",
                    scenario=_scenario(finding))


def _verdict(exploitable: bool, confidence: float, severity: str,
             reasoning: str, scenario: str = "") -> dict[str, Any]:
    return {
        "exploitable": exploitable,
        "confidence": confidence,
        "severity": severity,
        "reasoning": reasoning,
        "attack_scenario": scenario,
        "validator": "offline",
        "provider": "offline",
        "model": "rule-based fallback",
    }


def _scenario(finding: dict[str, Any]) -> str:
    meta = rules.vuln_class(finding["category"])
    route = finding.get("route_path") or "the affected endpoint"
    return (f"Send a request to {route} with a payload such as "
            f"`{meta['payload']}`. {meta['why']}")


# --------------------------------------------------------------------------
# The one function the rest of the engine calls
# --------------------------------------------------------------------------


PROVIDERS = ("anthropic", "openai")


def _ask(provider: str, finding: dict[str, Any]) -> dict[str, Any] | None:
    """Dispatch to a provider by name.

    Deliberately NOT a dict of function references. A dict built at import
    time captures the original functions, so monkeypatching `llm.ask_openai`
    in a test would have no effect and the test would silently exercise the
    real network path. Looking the module attribute up here binds late.
    """
    if provider == "anthropic":
        return ask_claude(finding)
    if provider == "openai":
        return ask_openai(finding)
    return None


def judge(finding: dict[str, Any], use_llm: bool | None = None,
          provider: str | None = None) -> dict[str, Any]:
    """Return a verdict for one finding.

    Tries the configured provider; on any failure records why and falls back
    to the deterministic validator. The caller never has to handle an error.
    """
    if use_llm is False:
        fallback = offline_verdict(finding)
        fallback["fallback_reason"] = "offline validator requested (--no-llm)"
        return fallback

    provider = provider or config.detect_provider()
    if provider == "offline" and use_llm is True:
        provider = "anthropic"

    if provider == "offline":
        fallback = offline_verdict(finding)
        fallback["fallback_reason"] = (
            f"no LLM key configured (set {config.ANTHROPIC_KEY_ENV} "
            f"or {config.OPENAI_KEY_ENV})")
        return fallback

    result = _ask(provider, finding)

    if result is not None and "_error" not in result:
        return result

    fallback = offline_verdict(finding)
    if result is not None:
        fallback["fallback_reason"] = result["_error"]
    else:
        fallback["fallback_reason"] = (
            f"{provider}: client unavailable (is the package installed "
            f"and the key set?)")
    fallback["attempted_provider"] = provider
    return fallback
