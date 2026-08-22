"""Cross-repository deduplication.

Owner: Member 4 (Dedupe + Baseline).

The same mistake gets copied between services. If four teams each built a
"/ping" endpoint by concatenating a query parameter into a shell command,
that is ONE thing to fix and one ticket to raise -- not four.

The trick is choosing what to hash. We deliberately do NOT hash the file
path, the line number, the variable names, or the exact function called,
because none of those are the same across two services. We hash the SHAPE of
the vulnerability:

    CWE  +  where the input came from  +  what the code did with it

So this Python line:
    os.system("ping -c 1 " + host)              # host from request.args

and this JavaScript line:
    child_process.exec("ping -c 1 " + host)     # host from req.query

produce the same fingerprint, because both are "CWE-78, HTTP query string,
concatenated into a call". Cross-language matching is the point -- a
microservice estate is rarely written in one language.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# Things that differ between two copies of the same bug and must be erased
# before hashing.
# The [fFrRbBuU]{0,2} prefix matters: without it, the `f` of a Python
# f-string is left behind and the identifier pass glues it to the placeholder
# ("f0" is a valid identifier), so an f-string and a JS template literal --
# the same vulnerability written twice -- get different shapes and never
# cluster together.
RE_STRING = re.compile(r"""[fFrRbBuU]{0,2}(['"`])(?:\\.|(?!\1).)*\1""")
RE_HOLE = re.compile(r"\$?\{[^{}]*\}")          # ${x} in JS, {x} in a Python f-string
RE_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$.]*")
RE_SPACE = re.compile(r"\s+")

# The placeholders are digits on purpose. An earlier version used the words
# STR and NAME, and the identifier pass then matched STR and rewrote it to
# NAME -- so "os.system(x)" and 'os.system("literal")' collapsed to the same
# shape and unrelated findings clustered together. Digits cannot be matched by
# the identifier pattern, which starts with a letter, _ or $.
STRING_TOKEN = "0"
NAME_TOKEN = "1"


def _replace_string(match: re.Match) -> str:
    """A string literal becomes `0`. One with a hole in it becomes `0+1`.

    An f-string and a template literal are just concatenation with nicer
    syntax, so they must reduce to the same shape as `"..." + x`. Without
    this, the Python `f"... {id}"` SQL injection and the JavaScript
    `` `... ${id}` `` one would never match each other.
    """
    literal = match.group(0)
    if RE_HOLE.search(literal):
        return f"{STRING_TOKEN}+{NAME_TOKEN}"
    return STRING_TOKEN


def code_shape(code: str) -> str:
    """Reduce a line of code to its structural skeleton.

    >>> code_shape('os.system("ping -c 1 " + host)')
    '1(0+1)'
    >>> code_shape('child_process.exec("ping -c 1 " + host)')
    '1(0+1)'
    >>> code_shape('os.system(cmd)')
    '1(1)'
    """
    text = RE_STRING.sub(_replace_string, code)
    text = RE_IDENTIFIER.sub(NAME_TOKEN, text)
    text = RE_SPACE.sub("", text)
    # A dotted chain (os.system) is one name, and adjacent literals are one literal.
    while f"{NAME_TOKEN}.{NAME_TOKEN}" in text:
        text = text.replace(f"{NAME_TOKEN}.{NAME_TOKEN}", NAME_TOKEN)
    while STRING_TOKEN * 2 in text:
        text = text.replace(STRING_TOKEN * 2, STRING_TOKEN)
    return text


def fingerprint(finding: dict[str, Any]) -> str:
    """The identity of a vulnerability PATTERN, independent of where it lives."""
    parts = [
        finding.get("cwe", ""),
        finding.get("category", ""),
        _normalise_source(finding.get("source_label", "")),
        code_shape(finding.get("sink_code", "")),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _normalise_source(label: str) -> str:
    """`HTTP query string` and `HTTP form body` are both "HTTP request data"."""
    lowered = label.lower()
    if lowered.startswith("http"):
        return "http-request"
    if "parameter" in lowered:
        return "function-parameter"
    return lowered or "unknown"


def cluster(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Group findings by fingerprint and report what collapsed.

    Every finding gets a `fingerprint` and a `cluster_size` written onto it,
    so the dashboard can show "this exact pattern also appears in 2 other
    services" next to a finding.
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        key = fingerprint(finding)
        finding["fingerprint"] = key
        groups.setdefault(key, []).append(finding)

    clusters = []
    for key, members in groups.items():
        repos = sorted({member.get("repo", "") for member in members})
        for member in members:
            member["cluster_size"] = len(members)
            member["cluster_repos"] = repos
        clusters.append({
            "fingerprint": key,
            "category": members[0]["category"],
            "cwe": members[0]["cwe"],
            "title": members[0]["title"],
            "severity": members[0]["severity"],
            "count": len(members),
            "repos": repos,
            "cross_repo": len(repos) > 1,
            "shape": code_shape(members[0].get("sink_code", "")),
            "locations": [
                {"repo": m.get("repo", ""), "file": m["file"],
                 "line": m["line"], "id": m["id"], "language": m.get("language", "")}
                for m in members
            ],
        })

    clusters.sort(key=lambda c: (-c["count"], c["category"]))
    total = len(findings)
    unique = len(clusters)

    return {
        "clusters": clusters,
        "summary": {
            "findings_before": total,
            "clusters_after": unique,
            "duplicates_removed": total - unique,
            "reduction_rate": round((total - unique) / total, 4) if total else 0.0,
            "cross_repo_clusters": sum(1 for c in clusters if c["cross_repo"]),
        },
    }
