"""A small Flask service written correctly.

This is the false-positive control. It handles user input on every route,
uses a database, runs a subprocess, reads files, and makes an outbound HTTP
request -- all the things that trip a naive scanner -- but every one of them
is done safely.

The rule for this file is absolute: ANY finding the engine reports here after
Stage 3 validation is a false positive. tests/test_accuracy.py asserts zero.
"""

import html
import os
import subprocess
from pathlib import Path

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

FILES_ROOT = Path("/srv/files").resolve()
ALLOWED_HOSTS = {"api.internal.example.com", "status.internal.example.com"}


@app.route("/ping")
def ping():
    """Safe: the host never reaches a shell. No shell=True, arguments are a list."""
    host = request.args.get("host", "")
    if not host.replace(".", "").replace("-", "").isalnum():
        return jsonify(error="invalid host"), 400
    subprocess.run(["ping", "-c", "1", host], check=False)
    return jsonify(status="ok")


@app.route("/user")
def get_user():
    """Safe: a parameterised query. The value can never become SQL."""
    user_id = request.args.get("id", "")
    cursor = _db().cursor()
    cursor.execute("SELECT name, email FROM users WHERE id = ?", (user_id,))
    return jsonify(rows=cursor.fetchall())


@app.route("/greet")
def greet():
    """Safe: the value is HTML-escaped before it goes into the response."""
    name = request.args.get("name", "")
    return "<h1>Hello " + html.escape(name) + "</h1>"


@app.route("/download")
def download():
    """Safe: the path is resolved and checked to be inside the base directory."""
    requested = request.args.get("file", "")
    candidate = (FILES_ROOT / os.path.basename(requested)).resolve()
    if not str(candidate).startswith(str(FILES_ROOT)):
        return jsonify(error="forbidden"), 403
    return candidate.read_text()


@app.route("/status")
def status():
    """Safe: only hosts on the allowlist are ever contacted."""
    host = request.args.get("host", "")
    if host not in ALLOWED_HOSTS:
        return jsonify(error="host not allowed"), 400
    response = requests.get("https://" + host + "/status", timeout=5)
    return jsonify(upstream=response.status_code)


@app.route("/report")
def report():
    """Safe: the value selects a fixed command, it never becomes part of one."""
    kind = request.args.get("kind", "daily")
    commands = {
        "daily": ["generate-report", "--daily"],
        "weekly": ["generate-report", "--weekly"],
    }
    if kind not in commands:
        return jsonify(error="unknown report"), 400
    subprocess.run(commands[kind], check=False)
    return jsonify(status="queued")


def _db():
    import sqlite3
    return sqlite3.connect("safe.db", check_same_thread=False)


if __name__ == "__main__":
    app.run(port=5002)
