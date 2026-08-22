"""STAGE 4 of 4 -- PROVE.

Owner: Member 5 (Prove + Integrations).

A confirmed finding is still just a claim until someone can reproduce it.
This stage attaches two things to every confirmed finding:

  * a proof-of-concept request, built from the route and parameter the taint
    path actually recorded -- not a generic example,
  * a suggested fix, with the exact line to change.

The fix is GENERATED here but never APPLIED. It goes into the approval queue
(engine/approvals.py) and a human has to say yes. That is the human-approval
gate the problem statement asks for, and it is the right default: an
auto-applied "fix" to a security finding is how you turn one bug into two.
"""

from __future__ import annotations

import shlex
from typing import Any

from . import rules

DEFAULT_HOST = "http://localhost:5001"

# The parameter a route reads, worked out from the taint path. Falls back to
# a sensible name per vulnerability class when we cannot tell.
FALLBACK_PARAM = {
    "command_injection": "cmd",
    "code_injection": "expr",
    "sql_injection": "id",
    "ssti": "name",
    "ssrf": "url",
    "path_traversal": "file",
    "xss": "name",
    "open_redirect": "next",
    "deserialization": "data",
    "nosql_injection": "filter",
}

# How to turn a suggested fix into an actual code change, per class.
FIX_TEMPLATES = {
    "command_injection": {
        "python": ("import shlex", "os.system(\"...\" + shlex.quote(VALUE))",
                   "or better: subprocess.run([\"cmd\", VALUE], shell=False)"),
        "javascript": ("const { execFile } = require('child_process')",
                       "execFile('cmd', [VALUE])",
                       "execFile does not spawn a shell, so metacharacters are inert"),
    },
    "sql_injection": {
        "python": ("", "cursor.execute(\"SELECT ... WHERE id = ?\", (VALUE,))",
                   "the driver keeps the value out of the SQL text"),
        "javascript": ("", "db.query('SELECT ... WHERE id = ?', [VALUE])",
                       "the driver keeps the value out of the SQL text"),
    },
    "path_traversal": {
        "python": ("import os", "open(os.path.join(BASE, os.path.basename(VALUE)))",
                   "then check the resolved path is still inside BASE"),
        "javascript": ("const path = require('path')",
                       "fs.readFileSync(path.join(BASE, path.basename(VALUE)))",
                       "then check the resolved path is still inside BASE"),
    },
    "ssrf": {
        "python": ("", "if urlparse(VALUE).hostname not in ALLOWED_HOSTS: abort(400)",
                   "allowlist the hosts you are willing to call"),
        "javascript": ("", "if (!ALLOWED_HOSTS.includes(new URL(VALUE).hostname)) return res.status(400).send()",
                       "allowlist the hosts you are willing to call"),
    },
    "xss": {
        "python": ("import html", "html.escape(VALUE)", "escape before it reaches the response"),
        "javascript": ("const escapeHtml = require('escape-html')", "escapeHtml(VALUE)",
                       "escape before it reaches the response"),
    },
    "open_redirect": {
        "python": ("", "if not VALUE.startswith('/'): abort(400)",
                   "only redirect to paths on your own host"),
        "javascript": ("", "if (!VALUE.startsWith('/')) return res.status(400).send()",
                       "only redirect to paths on your own host"),
    },
    "deserialization": {
        "python": ("import json", "json.loads(VALUE)  # or yaml.safe_load(VALUE)",
                   "never unpickle data that came from a request"),
        "javascript": ("", "JSON.parse(VALUE)", "never deserialise attacker data into objects"),
    },
    "code_injection": {
        "python": ("import ast", "ast.literal_eval(VALUE)",
                   "literal_eval parses data and refuses to run code"),
        "javascript": ("", "JSON.parse(VALUE)", "do not eval strings that came from a request"),
    },
    "ssti": {
        "python": ("", "render_template('page.html', name=VALUE)",
                   "render a fixed template and pass the value in as context"),
        "javascript": ("", "res.render('page', { name: VALUE })",
                       "render a fixed template and pass the value in as context"),
    },
}


def prove(findings: list[dict[str, Any]], host: str = DEFAULT_HOST) -> list[dict[str, Any]]:
    """Attach a PoC and a suggested fix to every confirmed finding."""
    for finding in findings:
        if finding.get("status") != "confirmed":
            continue
        finding["poc"] = build_poc(finding, host)
        finding["suggested_fix"] = build_fix(finding)
        finding["fix_status"] = "pending_approval"      # never applied automatically
        finding["stage"] = "prove"
    return findings


# --------------------------------------------------------------------------
# Proof of concept
# --------------------------------------------------------------------------


def build_poc(finding: dict[str, Any], host: str = DEFAULT_HOST) -> dict[str, Any]:
    """A concrete request that demonstrates the finding."""
    meta = rules.vuln_class(finding["category"])
    payload = meta["payload"]
    parameter = _parameter_name(finding)
    route = finding.get("route_path") or ""
    methods = finding.get("route_methods") or ["GET"]
    method = methods[0].upper()

    if not route:
        # Not reachable over HTTP -- describe the call instead of faking a URL.
        return {
            "reachable": False,
            "kind": "direct-call",
            "command": f"# no HTTP route reaches {finding['function']}(); "
                       f"call it directly with: {finding['function']}({payload!r})",
            "payload": payload,
            "parameter": parameter,
            "expected": meta["why"],
            "note": "This finding has no attacker-reachable entry point in the code as it "
                    "stands. The PoC is shown for completeness only.",
        }

    # shlex.quote, not an f-string with quotes around it. Several payloads
    # contain single quotes of their own (`' OR '1'='1' -- `), and pasting
    # those into a hand-quoted shell command produces a broken command that
    # proves nothing.
    argument = shlex.quote(f"{parameter}={payload}")
    url = shlex.quote(f"{host}{route}")

    if finding["category"] == "deserialization" and finding.get("source_label") == "HTTP raw body":
        command = (f"curl -X {method} {url} "
                   f"--data-binary @payload.bin   # payload.bin contains: {payload}")
    elif method == "GET":
        command = f"curl -G {url} --data-urlencode {argument}"
    else:
        command = f"curl -X {method} {url} --data-urlencode {argument}"

    return {
        "reachable": True,
        "kind": "http",
        "method": method,
        "url": f"{host}{route}",
        "parameter": parameter,
        "payload": payload,
        "command": command,
        "expected": _expected_result(finding, meta),
        "note": "Run this against a local instance of the service only.",
    }


def _parameter_name(finding: dict[str, Any]) -> str:
    """Recover the query/form parameter from the taint path.

    The first step of the path is the line that read the input, e.g.
    `host = request.args.get("host")`. The name in quotes is what we want.
    """
    for step in finding.get("taint_path", []):
        code = step.get("code", "")
        for opening, closing in (('"', '"'), ("'", "'")):
            if opening in code:
                start = code.index(opening) + 1
                remainder = code[start:]
                if closing in remainder:
                    candidate = remainder[:remainder.index(closing)]
                    # A parameter name, not a whole SQL statement or a URL.
                    if candidate and " " not in candidate and len(candidate) < 40:
                        return candidate
        break
    return FALLBACK_PARAM.get(finding["category"], "input")


def _expected_result(finding: dict[str, Any], meta: dict[str, Any]) -> str:
    category = finding["category"]
    if category == "command_injection":
        return "The output of `id` appears in the response or the server logs."
    if category == "sql_injection":
        return "Rows are returned that the query should not have matched."
    if category == "code_injection":
        return "The injected Python expression is evaluated by the server."
    if category == "ssti":
        return "The response contains 49, proving the template engine evaluated 7*7."
    if category == "ssrf":
        return "The response contains cloud instance metadata from 169.254.169.254."
    if category == "path_traversal":
        return "The response contains the contents of /etc/passwd."
    if category == "xss":
        return "The script tag is reflected unescaped into the HTML response."
    if category == "open_redirect":
        return "The response is a 302 pointing at the attacker's domain."
    if category == "deserialization":
        return "The object's __reduce__ runs during unpickling and executes a command."
    return meta["why"]


# --------------------------------------------------------------------------
# Suggested fix
# --------------------------------------------------------------------------


def build_fix(finding: dict[str, Any]) -> dict[str, Any]:
    """A specific, reviewable change -- not a link to an OWASP page."""
    meta = rules.vuln_class(finding["category"])
    language = finding.get("language", "python")
    template = FIX_TEMPLATES.get(finding["category"], {}).get(language)

    if template is None:
        return {
            "file": finding["file"],
            "line": finding["line"],
            "current": finding["sink_code"],
            "guidance": meta["fix"],
            "import_needed": "",
            "replacement": "",
            "explanation": meta["fix"],
            "auto_applicable": False,
        }

    import_needed, replacement, explanation = template
    tainted = _tainted_variable(finding)
    return {
        "file": finding["file"],
        "line": finding["line"],
        "current": finding["sink_code"],
        "import_needed": import_needed,
        "replacement": replacement.replace("VALUE", tainted),
        "explanation": explanation,
        "guidance": meta["fix"],
        # We can describe the change precisely, but applying it still needs a
        # human -- variable names and surrounding logic differ every time.
        "auto_applicable": False,
    }


def _tainted_variable(finding: dict[str, Any]) -> str:
    """The variable that carries the attacker's value into the sink."""
    steps = finding.get("taint_path", [])
    for step in reversed(steps):
        description = step.get("description", "")
        if description.startswith("value flows into `"):
            return description.split("`")[1]
    return "user_value"
