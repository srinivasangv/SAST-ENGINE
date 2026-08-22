// Deliberately vulnerable Express service -- the second scan target.
//
// DO NOT DEPLOY THIS. Every route below is intentionally broken.
//
// Markers work the same way as in the Flask app:
//     VULN-<n>   a real vulnerability the scanner must find
//     DECOY-<n>  reported by Stage 2, must be suppressed by Stage 3
//
// VULN-12 is a deliberate DUPLICATE of VULN-1 in testdata/vuln-flask/app.py:
// the same "user input concatenated into a shell command" pattern, in a
// different language and a different service. Stage 3's dedupe step must
// collapse the two into a single cross-repo cluster.

const express = require("express");
const child_process = require("child_process");
const fs = require("fs");
const axios = require("axios");
const path = require("path");

const app = express();
const db = require("./db");

const ALLOWED_REGIONS = ["us-east", "eu-west", "ap-south"];

// ==========================================================================
// REAL VULNERABILITIES
// ==========================================================================

// VULN-12  Command injection. Same pattern as VULN-1 in the Flask service.
app.get("/ping", (req, res) => {
  const host = req.query.host;
  child_process.exec("ping -c 1 " + host);
  res.send("pinged");
});

// VULN-13  SQL injection via template literal.
app.get("/user", (req, res) => {
  const id = req.query.id;
  db.query(`SELECT name, email FROM users WHERE id = ${id}`);
  res.send("ok");
});

// VULN-14  SSRF. The server fetches whatever URL the caller supplies.
app.get("/fetch", (req, res) => {
  const url = req.query.url;
  axios.get(url);
  res.send("fetched");
});

// VULN-15  Path traversal reading an arbitrary file.
app.get("/download", (req, res) => {
  const name = req.query.file;
  const contents = fs.readFileSync("/srv/files/" + name);
  res.send(contents);
});

// VULN-16  Open redirect.
app.get("/go", (req, res) => {
  const next = req.query.next;
  res.redirect(next);
});

// VULN-17  Reflected XSS -- the value is written straight into the response.
app.get("/greet", (req, res) => {
  const name = req.query.name;
  res.send("<h1>Hello " + name + "</h1>");
});

// ==========================================================================
// DECOYS
// ==========================================================================

// DECOY-7  Cast to a number before it reaches SQL.
app.get("/order", (req, res) => {
  const id = parseInt(req.query.id);
  db.query("SELECT * FROM orders WHERE id = " + id);
  res.send("ok");
});

// DECOY-8  URL-encoded before being used as a redirect target.
app.get("/track", (req, res) => {
  const target = encodeURIComponent(req.query.target);
  res.redirect("/r?to=" + target);
});

// DECOY-9  Filename reduced to its basename, so ".." cannot escape.
app.get("/asset", (req, res) => {
  const raw = req.query.file;
  const safe = path.basename(raw);
  const contents = fs.readFileSync("/srv/assets/" + safe);
  res.send(contents);
});

// DECOY-10  Checked against an allowlist before use.
app.get("/region", (req, res) => {
  const region = req.query.region;
  if (ALLOWED_REGIONS.indexOf(region) === -1) {
    res.send("unknown region");
    return;
  }
  child_process.exec("deploy --region " + region);
  res.send("deploying");
});

app.listen(3001);
