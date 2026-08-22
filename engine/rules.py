"""The rule tables: where attacker data comes from, where it must never go,
and what cleans it on the way.

Owner: Member 2 (Scan / Taint engine).

This file is DATA, not logic. Adding a new vulnerability class means adding
rows here -- the taint engine in stage2_scan.py does not change. That is why
it can be written on Day 1, before the engine exists.

Matching is deliberately simple. A pattern matches a dotted call name when:
    exact match          "os.system"      matches "os.system"
    method suffix        "execute"        matches "cursor.execute", "db.execute"
    attribute prefix     "request.args"   matches "request.args.get"
"""

from typing import Any

# --------------------------------------------------------------------------
# Vulnerability classes -- one row per class, used by every later stage.
# --------------------------------------------------------------------------

VULN_CLASSES: dict[str, dict[str, Any]] = {
    "command_injection": {
        "title": "OS Command Injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021 Injection",
        "severity": "critical",
        "payload": "; id",
        "why": "The value is passed to a shell, so shell metacharacters run as commands.",
        "fix": "Never build a shell string. Pass a list of arguments to subprocess.run() "
               "with shell=False, or wrap the value in shlex.quote().",
    },
    "code_injection": {
        "title": "Code Injection",
        "cwe": "CWE-94",
        "owasp": "A03:2021 Injection",
        "severity": "critical",
        "payload": "__import__('os').system('id')",
        "why": "The value is evaluated as source code by the interpreter.",
        "fix": "Remove eval/exec. Use ast.literal_eval() for data, or an explicit "
               "dispatch dictionary for behaviour.",
    },
    "sql_injection": {
        "title": "SQL Injection",
        "cwe": "CWE-89",
        "owasp": "A03:2021 Injection",
        "severity": "critical",
        "payload": "' OR '1'='1' -- ",
        "why": "The value becomes part of the SQL statement instead of a value in it.",
        "fix": "Use a parameterised query: cursor.execute('... WHERE id = ?', (value,)).",
    },
    "ssti": {
        "title": "Server-Side Template Injection",
        "cwe": "CWE-1336",
        "owasp": "A03:2021 Injection",
        "severity": "critical",
        "payload": "{{ 7*7 }}",
        "why": "The value is compiled as a template, which can reach Python objects.",
        "fix": "Render a fixed template file and pass the value in as a context variable.",
    },
    "deserialization": {
        "title": "Insecure Deserialization",
        "cwe": "CWE-502",
        "owasp": "A08:2021 Software and Data Integrity Failures",
        "severity": "critical",
        "payload": "<pickled object with __reduce__ running os.system>",
        "why": "Deserialising attacker data can construct arbitrary objects and run code.",
        "fix": "Use json.loads() or yaml.safe_load(). Never unpickle untrusted input.",
    },
    "ssrf": {
        "title": "Server-Side Request Forgery",
        "cwe": "CWE-918",
        "owasp": "A10:2021 SSRF",
        "severity": "high",
        "payload": "http://169.254.169.254/latest/meta-data/",
        "why": "The server fetches a URL the attacker chose, reaching internal services.",
        "fix": "Validate the URL against an allowlist of hosts and reject private IP ranges.",
    },
    "path_traversal": {
        "title": "Path Traversal",
        "cwe": "CWE-22",
        "owasp": "A01:2021 Broken Access Control",
        "severity": "high",
        "payload": "../../../../etc/passwd",
        "why": "The value is used as a file path, so '..' escapes the intended directory.",
        "fix": "Take os.path.basename() of the value and resolve the final path, "
               "checking it is still inside the intended base directory.",
    },
    "xss": {
        "title": "Cross-Site Scripting",
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection",
        "severity": "high",
        "payload": "<script>alert(1)</script>",
        "why": "The value is written into the HTML response without escaping.",
        "fix": "HTML-escape the value (html.escape / escape-html) before rendering it.",
    },
    "open_redirect": {
        "title": "Open Redirect",
        "cwe": "CWE-601",
        "owasp": "A01:2021 Broken Access Control",
        "severity": "medium",
        "payload": "https://evil.example.com",
        "why": "The server redirects the browser to a location the attacker chose.",
        "fix": "Only redirect to paths on your own host, or check against an allowlist.",
    },
    "nosql_injection": {
        "title": "NoSQL Injection",
        "cwe": "CWE-943",
        "owasp": "A03:2021 Injection",
        "severity": "high",
        "payload": '{"$ne": null}',
        "why": "The value becomes part of the query document, not a value inside it.",
        "fix": "Cast the value to a string and validate its shape before querying.",
    },
}


# --------------------------------------------------------------------------
# SOURCES -- where attacker-controlled data enters the program.
# --------------------------------------------------------------------------

SOURCES: list[dict[str, Any]] = [
    # ---- Python / Flask / Django / FastAPI
    {"pattern": "request.args", "lang": "python", "label": "HTTP query string"},
    {"pattern": "request.form", "lang": "python", "label": "HTTP form body"},
    {"pattern": "request.values", "lang": "python", "label": "HTTP query or form"},
    {"pattern": "request.json", "lang": "python", "label": "HTTP JSON body"},
    {"pattern": "request.data", "lang": "python", "label": "HTTP raw body"},
    {"pattern": "request.get_json", "lang": "python", "label": "HTTP JSON body"},
    {"pattern": "request.cookies", "lang": "python", "label": "HTTP cookie"},
    {"pattern": "request.headers", "lang": "python", "label": "HTTP header"},
    {"pattern": "request.files", "lang": "python", "label": "HTTP file upload"},
    {"pattern": "request.query_params", "lang": "python", "label": "HTTP query string"},
    {"pattern": "request.GET", "lang": "python", "label": "HTTP query string"},
    {"pattern": "request.POST", "lang": "python", "label": "HTTP form body"},
    {"pattern": "input", "lang": "python", "label": "stdin"},
    {"pattern": "sys.argv", "lang": "python", "label": "command-line argument"},
    {"pattern": "os.environ", "lang": "python", "label": "environment variable"},

    # ---- JavaScript / Express
    {"pattern": "req.query", "lang": "javascript", "label": "HTTP query string"},
    {"pattern": "req.body", "lang": "javascript", "label": "HTTP request body"},
    {"pattern": "req.params", "lang": "javascript", "label": "HTTP path parameter"},
    {"pattern": "req.headers", "lang": "javascript", "label": "HTTP header"},
    {"pattern": "req.cookies", "lang": "javascript", "label": "HTTP cookie"},
    {"pattern": "request.query", "lang": "javascript", "label": "HTTP query string"},
    {"pattern": "request.body", "lang": "javascript", "label": "HTTP request body"},
    {"pattern": "process.argv", "lang": "javascript", "label": "command-line argument"},
    {"pattern": "location.search", "lang": "javascript", "label": "browser URL"},
    {"pattern": "window.location", "lang": "javascript", "label": "browser URL"},
]


# --------------------------------------------------------------------------
# SINKS -- where attacker-controlled data must never arrive unescaped.
#
#   category      which VULN_CLASSES row this belongs to
#   args          which argument positions are dangerous ([] means "any")
#   requires_kwarg  only dangerous when this keyword argument is present,
#                   e.g. subprocess.run(..., shell=True)
# --------------------------------------------------------------------------

SINKS: list[dict[str, Any]] = [
    # ---- Python: command execution
    {"pattern": "os.system", "category": "command_injection", "lang": "python", "args": [0]},
    {"pattern": "os.popen", "category": "command_injection", "lang": "python", "args": [0]},
    {"pattern": "subprocess.call", "category": "command_injection", "lang": "python",
     "args": [0], "requires_kwarg": ("shell", "True")},
    {"pattern": "subprocess.run", "category": "command_injection", "lang": "python",
     "args": [0], "requires_kwarg": ("shell", "True")},
    {"pattern": "subprocess.Popen", "category": "command_injection", "lang": "python",
     "args": [0], "requires_kwarg": ("shell", "True")},
    {"pattern": "subprocess.check_output", "category": "command_injection", "lang": "python",
     "args": [0], "requires_kwarg": ("shell", "True")},

    # ---- Python: code execution
    {"pattern": "eval", "category": "code_injection", "lang": "python", "args": [0]},
    {"pattern": "exec", "category": "code_injection", "lang": "python", "args": [0]},

    # ---- Python: SQL
    {"pattern": "execute", "category": "sql_injection", "lang": "python", "args": [0]},
    {"pattern": "executemany", "category": "sql_injection", "lang": "python", "args": [0]},
    {"pattern": "executescript", "category": "sql_injection", "lang": "python", "args": [0]},
    {"pattern": "text", "category": "sql_injection", "lang": "python", "args": [0]},

    # ---- Python: templates
    {"pattern": "render_template_string", "category": "ssti", "lang": "python", "args": [0]},
    {"pattern": "Template", "category": "ssti", "lang": "python", "args": [0]},

    # ---- Python: deserialization
    {"pattern": "pickle.loads", "category": "deserialization", "lang": "python", "args": [0]},
    {"pattern": "pickle.load", "category": "deserialization", "lang": "python", "args": [0]},
    {"pattern": "cPickle.loads", "category": "deserialization", "lang": "python", "args": [0]},
    {"pattern": "marshal.loads", "category": "deserialization", "lang": "python", "args": [0]},
    {"pattern": "yaml.load", "category": "deserialization", "lang": "python", "args": [0]},
    {"pattern": "dill.loads", "category": "deserialization", "lang": "python", "args": [0]},

    # ---- Python: outbound requests (SSRF)
    {"pattern": "requests.get", "category": "ssrf", "lang": "python", "args": [0]},
    {"pattern": "requests.post", "category": "ssrf", "lang": "python", "args": [0]},
    {"pattern": "requests.put", "category": "ssrf", "lang": "python", "args": [0]},
    {"pattern": "requests.delete", "category": "ssrf", "lang": "python", "args": [0]},
    {"pattern": "requests.head", "category": "ssrf", "lang": "python", "args": [0]},
    {"pattern": "urlopen", "category": "ssrf", "lang": "python", "args": [0]},
    {"pattern": "httpx.get", "category": "ssrf", "lang": "python", "args": [0]},

    # ---- Python: filesystem
    {"pattern": "open", "category": "path_traversal", "lang": "python", "args": [0]},
    {"pattern": "send_file", "category": "path_traversal", "lang": "python", "args": [0]},
    {"pattern": "os.remove", "category": "path_traversal", "lang": "python", "args": [0]},
    {"pattern": "shutil.copy", "category": "path_traversal", "lang": "python", "args": [0, 1]},

    # ---- Python: response rendering
    {"pattern": "Markup", "category": "xss", "lang": "python", "args": [0]},
    {"pattern": "mark_safe", "category": "xss", "lang": "python", "args": [0]},
    {"pattern": "redirect", "category": "open_redirect", "lang": "python", "args": [0]},

    # ---- JavaScript: command execution
    {"pattern": "child_process.exec", "category": "command_injection", "lang": "javascript", "args": [0]},
    {"pattern": "child_process.execSync", "category": "command_injection", "lang": "javascript", "args": [0]},
    {"pattern": "exec", "category": "command_injection", "lang": "javascript", "args": [0]},
    {"pattern": "execSync", "category": "command_injection", "lang": "javascript", "args": [0]},

    # ---- JavaScript: code execution
    {"pattern": "eval", "category": "code_injection", "lang": "javascript", "args": [0]},
    {"pattern": "Function", "category": "code_injection", "lang": "javascript", "args": [0]},
    {"pattern": "vm.runInNewContext", "category": "code_injection", "lang": "javascript", "args": [0]},

    # ---- JavaScript: SQL / NoSQL
    {"pattern": "db.query", "category": "sql_injection", "lang": "javascript", "args": [0]},
    {"pattern": "connection.query", "category": "sql_injection", "lang": "javascript", "args": [0]},
    {"pattern": "pool.query", "category": "sql_injection", "lang": "javascript", "args": [0]},
    {"pattern": "knex.raw", "category": "sql_injection", "lang": "javascript", "args": [0]},
    {"pattern": "sequelize.query", "category": "sql_injection", "lang": "javascript", "args": [0]},
    {"pattern": "collection.find", "category": "nosql_injection", "lang": "javascript", "args": [0]},

    # ---- JavaScript: outbound requests
    {"pattern": "axios.get", "category": "ssrf", "lang": "javascript", "args": [0]},
    {"pattern": "axios.post", "category": "ssrf", "lang": "javascript", "args": [0]},
    {"pattern": "fetch", "category": "ssrf", "lang": "javascript", "args": [0]},
    {"pattern": "http.get", "category": "ssrf", "lang": "javascript", "args": [0]},

    # ---- JavaScript: filesystem
    {"pattern": "fs.readFile", "category": "path_traversal", "lang": "javascript", "args": [0]},
    {"pattern": "fs.readFileSync", "category": "path_traversal", "lang": "javascript", "args": [0]},
    {"pattern": "fs.writeFileSync", "category": "path_traversal", "lang": "javascript", "args": [0]},
    {"pattern": "res.sendFile", "category": "path_traversal", "lang": "javascript", "args": [0]},

    # ---- JavaScript: response rendering
    {"pattern": "res.send", "category": "xss", "lang": "javascript", "args": [0]},
    {"pattern": "res.write", "category": "xss", "lang": "javascript", "args": [0]},
    {"pattern": "res.redirect", "category": "open_redirect", "lang": "javascript", "args": [0]},
]


# --------------------------------------------------------------------------
# SANITIZERS -- calls that make a value safe for some categories.
#
# IMPORTANT DESIGN CHOICE: a sanitizer does NOT delete the taint. It records
# itself on the taint path and the finding is still reported by Stage 2.
# Stage 3 (the LLM, or the offline fallback) then decides whether the
# sanitizer actually neutralises this specific sink and suppresses the
# finding with a written reason.
#
# That is the whole point of the project: pattern matching alone reports it,
# reasoning suppresses it. Killing the taint here would hide the evidence.
# --------------------------------------------------------------------------

SANITIZERS: list[dict[str, Any]] = [
    # ---- Python
    {"pattern": "shlex.quote", "lang": "python", "neutralizes": ["command_injection"]},
    {"pattern": "int", "lang": "python", "neutralizes": ["*"]},
    {"pattern": "float", "lang": "python", "neutralizes": ["*"]},
    {"pattern": "bool", "lang": "python", "neutralizes": ["*"]},
    {"pattern": "uuid.UUID", "lang": "python", "neutralizes": ["*"]},
    {"pattern": "html.escape", "lang": "python", "neutralizes": ["xss"]},
    {"pattern": "escape", "lang": "python", "neutralizes": ["xss"]},
    {"pattern": "quote_plus", "lang": "python", "neutralizes": ["ssrf", "open_redirect"]},
    {"pattern": "os.path.basename", "lang": "python", "neutralizes": ["path_traversal"]},
    {"pattern": "secure_filename", "lang": "python", "neutralizes": ["path_traversal"]},
    {"pattern": "yaml.safe_load", "lang": "python", "neutralizes": ["deserialization"]},
    {"pattern": "json.loads", "lang": "python", "neutralizes": ["deserialization"]},
    {"pattern": "ast.literal_eval", "lang": "python", "neutralizes": ["code_injection"]},

    # ---- JavaScript
    {"pattern": "parseInt", "lang": "javascript", "neutralizes": ["*"]},
    {"pattern": "parseFloat", "lang": "javascript", "neutralizes": ["*"]},
    {"pattern": "Number", "lang": "javascript", "neutralizes": ["*"]},
    {"pattern": "encodeURIComponent", "lang": "javascript", "neutralizes": ["ssrf", "open_redirect", "xss"]},
    {"pattern": "escapeHtml", "lang": "javascript", "neutralizes": ["xss"]},
    {"pattern": "path.basename", "lang": "javascript", "neutralizes": ["path_traversal"]},
    {"pattern": "shellQuote", "lang": "javascript", "neutralizes": ["command_injection"]},
    {"pattern": "mysql.escape", "lang": "javascript", "neutralizes": ["sql_injection"]},
]


# --------------------------------------------------------------------------
# Matching helpers -- the only logic in this file.
# --------------------------------------------------------------------------


def matches(name: str, pattern: str) -> bool:
    """Does a dotted name match a rule pattern?

    >>> matches("os.system", "os.system")
    True
    >>> matches("cursor.execute", "execute")      # method on any object
    True
    >>> matches("request.args.get", "request.args")  # attribute of a source
    True
    >>> matches("my_execute", "execute")          # not a dotted part
    False
    """
    if not name:
        return False
    if name == pattern:
        return True
    if name.endswith("." + pattern):
        return True
    if name.startswith(pattern + "."):
        return True
    return False


def find_source(name: str, lang: str) -> dict[str, Any] | None:
    """Return the SOURCES row this name matches, or None."""
    for rule in SOURCES:
        if rule["lang"] == lang and matches(name, rule["pattern"]):
            return rule
    return None


def find_sink(name: str, lang: str) -> dict[str, Any] | None:
    """Return the SINKS row this call name matches, or None."""
    for rule in SINKS:
        if rule["lang"] == lang and matches(name, rule["pattern"]):
            return rule
    return None


def find_sanitizer(name: str, lang: str) -> dict[str, Any] | None:
    """Return the SANITIZERS row this call name matches, or None."""
    for rule in SANITIZERS:
        if rule["lang"] == lang and matches(name, rule["pattern"]):
            return rule
    return None


def sanitizer_covers(sanitizer_name: str, category: str, lang: str) -> bool:
    """Does this sanitizer actually make a value safe for this vulnerability class?

    `int()` is safe for everything -- an integer cannot carry a shell
    metacharacter. `html.escape()` stops XSS but does nothing for SQL
    injection. Stage 3 uses this to justify a suppression.
    """
    rule = find_sanitizer(sanitizer_name, lang)
    if rule is None:
        return False
    covered = rule["neutralizes"]
    return "*" in covered or category in covered


def vuln_class(category: str) -> dict[str, Any]:
    """Look up the metadata row for a vulnerability class."""
    return VULN_CLASSES.get(category, {
        "title": category, "cwe": "CWE-000", "owasp": "unknown",
        "severity": "medium", "payload": "<payload>", "why": "", "fix": "",
    })
