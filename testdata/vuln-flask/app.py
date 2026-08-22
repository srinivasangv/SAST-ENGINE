"""Deliberately vulnerable Flask service -- the primary scan target.

DO NOT DEPLOY THIS. Every route below is intentionally broken.

Each vulnerability is tagged with a marker comment:
    VULN-<n>   a real, exploitable vulnerability -> the scanner must find it
    DECOY-<n>  code that a pattern-matching scanner flags but that is NOT
               exploitable -> Stage 2 will report it, Stage 3 must suppress it

testdata/ground_truth.json is the machine-readable version of these markers
and is what tests/test_accuracy.py grades the scanner against.
"""

import html
import os
import pickle
import shlex
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, Markup, redirect, render_template_string, request

app = Flask(__name__)
DB = sqlite3.connect("app.db", check_same_thread=False)

ALLOWED_REPORTS = {"daily", "weekly", "monthly"}


# ==========================================================================
# REAL VULNERABILITIES
# ==========================================================================

@app.route("/ping")
def ping():
    """VULN-1  Command injection. `?host=x;id` runs `id` on the server."""
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "pinged"


@app.route("/backup", methods=["POST"])
def backup():
    """VULN-2  Command injection through subprocess with shell=True."""
    target = request.form["target"]
    subprocess.run("tar -czf backup.tgz " + target, shell=True)
    return "backed up"


@app.route("/calc")
def calc():
    """VULN-3  Code injection. The query string is evaluated as Python."""
    expression = request.args.get("expr")
    result = eval(expression)
    return str(result)


@app.route("/user")
def get_user():
    """VULN-4  SQL injection built with an f-string."""
    user_id = request.args.get("id")
    cursor = DB.cursor()
    cursor.execute(f"SELECT name, email FROM users WHERE id = {user_id}")
    return str(cursor.fetchall())


@app.route("/greet")
def greet():
    """VULN-5  Server-side template injection. `?name={{7*7}}` renders 49."""
    name = request.args.get("name")
    page = "<h1>Hello " + name + "</h1>"
    return render_template_string(page)


@app.route("/session", methods=["POST"])
def load_session():
    """VULN-6  Insecure deserialization. Unpickling attacker bytes runs code."""
    blob = request.data
    session = pickle.loads(blob)
    return str(session)


@app.route("/fetch")
def fetch_url():
    """VULN-7  SSRF. The server will fetch the cloud metadata endpoint for you."""
    url = request.args.get("url")
    response = requests.get(url)
    return response.text


@app.route("/download")
def download():
    """VULN-8  Path traversal. `?file=../../etc/passwd` escapes the directory."""
    filename = request.args.get("file")
    with open("/srv/files/" + filename) as handle:
        return handle.read()


@app.route("/config", methods=["POST"])
def load_config():
    """VULN-9  Deserialization through yaml.load with the unsafe loader."""
    raw = request.form["config"]
    parsed = yaml.load(raw)
    return str(parsed)


@app.route("/go")
def go():
    """VULN-10  Open redirect. The attacker chooses where your users land."""
    destination = request.args.get("next")
    return redirect(destination)


@app.route("/report")
def report():
    """VULN-11  Command injection reached through a helper function.

    The dangerous call is not in this function -- it is one call away. This
    is what the inter-procedural part of the taint engine is for.
    """
    name = request.args.get("name")
    return build_report(name)


def build_report(report_name):
    """Called from /report with attacker-controlled data."""
    os.system("generate-report --name " + report_name)
    return "report queued"


# ==========================================================================
# DECOYS -- reported by Stage 2, must be suppressed by Stage 3
# ==========================================================================

@app.route("/safe-ping")
def safe_ping():
    """DECOY-1  Sanitised with shlex.quote, which is exactly right for a shell."""
    host = request.args.get("host")
    quoted = shlex.quote(host)
    os.system("ping -c 1 " + quoted)
    return "pinged safely"


@app.route("/order")
def order():
    """DECOY-2  Cast to int before it reaches SQL. An integer cannot inject."""
    order_id = int(request.args.get("id"))
    cursor = DB.cursor()
    cursor.execute("SELECT * FROM orders WHERE id = " + str(order_id))
    return str(cursor.fetchall())


@app.route("/generate")
def generate():
    """DECOY-3  Checked against an allowlist before use."""
    kind = request.args.get("kind")
    if kind not in ALLOWED_REPORTS:
        return "unknown report", 400
    os.system("generate --kind " + kind)
    return "generated"


@app.route("/legacy")
def legacy():
    """DECOY-4  Dead code. The branch can never execute."""
    command = request.args.get("cmd")
    if False:
        os.system(command)
    return "legacy endpoint disabled"


def debug_shell(command):
    """DECOY-5  A helper with no caller anywhere in the codebase.

    A scanner that treats every parameter as user input reports this. There
    is no HTTP path that reaches it, so it is not exploitable as written.
    """
    os.system(command)


@app.route("/escape")
def escape_name():
    """DECOY-6  HTML-escaped before being marked safe, which stops XSS.

    Note for reviewers: an earlier version of this decoy passed the escaped
    value to render_template_string(). That was wrong -- html.escape() does
    not escape `{{` or `}}`, so template injection still worked and the
    "decoy" was a real vulnerability. Markup() is an XSS sink, and
    html.escape() genuinely neutralises it, so this one is a true decoy.
    """
    name = request.args.get("name")
    safe = html.escape(name)
    return Markup("<p>" + safe + "</p>")


if __name__ == "__main__":
    app.run(port=5001)
