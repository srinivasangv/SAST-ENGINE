# QA Log

Every defect found during the build, and what happened to it. Kept live —
add a row the moment you find something, not at the end of the day.

**Rules**
- Critical and high must be **closed** before the Day 5 code freeze.
- Medium and low that survive the freeze go on the "known limitations" slide.
- A bug found by a test gets the test name in the Notes column, so the
  regression is guarded.

| ID | Severity | Module | Owner | Status | Description | Resolution |
|---|---|---|---|---|---|---|
| QA-001 | **High** | testdata / rules | M7 | ✅ closed | DECOY-6 passed `html.escape(name)` into `render_template_string()` and was labelled "not exploitable". That is wrong — `html.escape` escapes `& < > " '` but leaves `{{` and `}}` untouched, so `?name={{7*7}}` still executes. The corpus contained a real SSTI mislabelled as a decoy, which would have made the accuracy numbers wrong in our favour. | Changed the decoy to use `Markup()`, which `html.escape` genuinely does neutralise. Added `test_sanitizer_only_covers_the_right_sinks` asserting `sanitizer_covers("html.escape", "ssti") is False`. |
| QA-002 | **High** | dedupe | M4 | ✅ closed | `code_shape()` used the words `STR` and `NAME` as placeholders. The identifier pass then matched `STR` and rewrote it to `NAME`, so `os.system(x)` and `os.system("literal")` produced the same shape and unrelated findings clustered together. | Switched the placeholders to digits (`0`, `1`), which cannot match an identifier pattern (it must start with a letter, `_` or `$`). Guarded by `test_placeholders_cannot_be_re_matched_as_identifiers`. |
| QA-003 | **High** | js_parser | M5 | ✅ closed | VULN-13, the SQL injection in `db.query(\`... ${id}\`)`, was missed entirely. String literals are blanked before scanning for identifiers so that words inside strings are not read as variables — but that also blanked the `${id}` hole, which is real code. | Interpolation contents are extracted and appended to the scannable text before the identifier pass. Guarded by the VULN-13 row in the accuracy test. |
| QA-004 | **Medium** | dedupe | M4 | ✅ closed | A Python f-string and a JavaScript template literal expressing the same SQL injection produced different shapes (`1(1+1)` vs `1(0+1)`), so the two never clustered. The `f` prefix was left outside the string match and the identifier pass glued it to the placeholder (`f0` is a valid identifier). | The string pattern now consumes the `[fFrRbBuU]{0,2}` prefix. Guarded by `test_fstring_and_template_literal_have_one_shape`. |
| QA-005 | **Medium** | stage2_scan | M2 | ✅ closed | `contents = fs.readFileSync(userPath)` marked `contents` as attacker-controlled, so every later use produced a second, noisier finding chained off the first. Two spurious XSS findings appeared in the Express app. | A sink consumes the tainted value; its return value is no longer treated as attacker data. Documented in the `_evaluate` comment. |
| QA-006 | **Medium** | stage2_scan / prove | M2, M5 | ✅ closed | VULN-11 is found inside `build_report()`, a helper with no route of its own, so the finding lost the route and its PoC read "no HTTP route reaches build_report()" — useless to a developer. | `TaintPath` now carries `route_path` and `route_methods` from where the taint started, and `_emit` prefers those. PoC is now `curl -G .../report --data-urlencode 'name=; id'`. Guarded by `test_inter_procedural_taint_reaches_a_helper`. |
| QA-007 | **Medium** | prove | M5 | ✅ closed | PoC commands were built by wrapping the payload in hand-written single quotes. Payloads that contain single quotes of their own (`' OR '1'='1' -- `) produced a broken shell command that proved nothing. | The whole `param=payload` argument is passed through `shlex.quote()`. |
| QA-008 | **Medium** | baseline | M4 | ✅ closed | Semgrep's `flask.security.open-redirect` rule was being scored as a path traversal, because the category-hint table listed `path_traversal` before `open_redirect` with `"open-"` as a hint. The overlap column was wrong as a result. | Reordered the hint table most-specific-first and removed the over-broad `"open-"` hint. Comment added explaining that order is load-bearing. |
| QA-009 | Low | tests | M7 | ✅ closed | `test_stage3_is_perfect_on_the_corpus[safe-app]` failed asserting `precision == 1.0`. With zero findings, precision is 0/0 — undefined, not zero. The test was wrong, not the engine. | The assertion is now guarded on `tp + fp > 0`, and safe-app instead asserts that nothing at all was reported. |
| QA-010 | Low | scan.py | M6 | ✅ closed | `SyntaxError: f-string: expecting '='` — a format spec was nested inside a function call inside an f-string (`{paint(x:<9, c)}`). | Replaced with `.ljust(9)` before the call. |
| QA-011 | Low | scan.py | M6 | ✅ closed | The CLI printed "same pattern in vuln-flask" for a cluster whose members were all in one repository, implying a cross-repo duplicate where there was none. | The message now distinguishes "N times in this repository" from "across repo-a, repo-b". |
| QA-014 | **Critical** | joern_engine | M1 | ✅ closed | Every Joern data-flow query returned **zero flows**, silently. A Joern traversal is a single-use iterator: `val src = cpg.call...` followed by `println(src.size)` for a log line consumes it, so the `reachableByFlows` that ran next received an exhausted iterator and found nothing — with no error and no warning. Cost most of an afternoon because the query looked correct. | Every traversal in the generated script is now a `def`, so each use rebuilds it. Guarded by `test_the_script_uses_def_not_val_for_traversals`. |
| QA-015 | **High** | joern_engine | M1 | ✅ closed | Putting `get` in the Joern **sink** name list made the entire query return nothing. `requests.get` is an SSRF sink but `request.args.get` is a source; with `get` in both sets the flow engine produced no results at all. | SSRF is matched by `methodFullName` in a separate query. `get` and `post` are banned from `SINK_NAMES`, asserted by `test_get_is_not_a_sink_name`. |
| QA-016 | **High** | joern_engine | M1 | ✅ closed | Every SQL injection Joern found came back labelled **CWE-94 code injection** instead of CWE-89. The classifier checked `pattern in receiver` as a plain substring, and `"exec"` is a substring of `"cursor.execute"` — so the `exec` rule matched first. Wrong CWE means the wrong fix. | The classifier now uses `rules.matches()`, which is dotted-segment aware, before any substring fallback. |
| QA-017 | **High** | joern_engine | M1 | ✅ closed | On the Joern path, DECOY-3 (allowlist guard) and DECOY-4 (`if False:` dead code) survived validation and were reported as real. Joern's flow output carries no guard or reachability information, so `to_findings` was setting both flags to False and the deterministic validator had nothing to suppress on. | Added `structural_flags()` — one cheap `ast` pass over the file recovers both facts. Joern supplies the data flow, the AST supplies the structure. Joern-engine precision went from 84.6% to 100%. |
| QA-018 | Medium | joern_engine | M5 | ✅ closed | Joern classified JavaScript's `child_process.exec` as Python's `exec` (code injection rather than command injection), because the classifier was hardcoded to `language="python"`. | Added `detect_language()` and threaded the language through classification, source matching and sanitizer matching. |
| QA-019 | Medium | defectdojo | M5 | ✅ closed | Every import failed with `HTTP 400: Not allowed fields are present: ['duplicate']`. The Generic Findings Import schema rejects a `duplicate` key — DefectDojo decides duplication itself via engagement deduplication. | Removed the field; cluster information travels as a tag instead. |
| QA-020 | Low | joern install | M1 | ✅ closed | Joern would not start: `Permission denied` on `bin/repl-bridge`, then again on `frontends/pysrc2cpg/bin/pysrc2cpg`. Python's `zipfile` does not preserve the executable bit, and the release ships as a zip. | Documented in setup: `find . -type d -name bin -exec chmod -R +x {} \;` after extracting. |
| QA-013 | **High** | store / API | M6 | ✅ closed | Re-scanning the same repository inflated every dashboard count. Finding ids are stable by design, so five scans of one repo produced 55 findings in the Findings tab, 55 entries in the approval queue, and a dedupe "reduction" of 84% that was really the same finding counted five times. Found during the final full-stack verification, not by a test. | `store.all_findings()` now keeps only the newest occurrence of each finding id (`latest_only=True`), so an approval recorded today is not hidden behind a stale copy in an older scan file. Guarded by `TestRescanDoesNotDuplicate`. |
| QA-012 | Low | ui | M7 | ✅ closed | A stray token in `styles.css` (`--medium: #ffd champagne;`) made the custom property invalid, so medium-severity badges fell back to an unstyled colour. | Corrected to `#f3d34a`. |

---

## Open items carried to "known limitations"

None are open. The items below were assessed and **accepted as limitations**
rather than fixed, and appear in [qa.md §6](qa.md#6-known-limitations) and on
the deck.

| ID | Severity | Area | Why we accepted it |
|---|---|---|---|
| LIM-1 | Medium | js_parser | Multi-line call arguments are not handled. Fixing it properly means tree-sitter or a Node subprocess, which breaks the "simple scripts, no heavy frameworks" constraint. Python is the primary target and Semgrep covers JavaScript in the baseline column. |
| LIM-2 | Medium | stage3_validate | One API call per finding. Correct but slow and costly at scale. Batching is the first thing to do after the hackathon. |
| LIM-3 | Low | stage2_scan | Inter-procedural depth is capped at 2 and resolved by name within a single repository. Deeper analysis needs a real call graph across files. |
| LIM-4 | Low | stage2_scan | Loop bodies are walked twice rather than to a fixpoint. Two passes settle every case in the corpus; it is not proven in general. |

---

## Environment notes

| Note | Detail |
|---|---|
| ENV-1 | The `ANTHROPIC_API_KEY` present in the build environment returned `401 API key is invalid`. The engine caught it, fell back to the offline validator, and recorded `fallback_reason` on every verdict — so the fallback path was proven under a **real** failure rather than a simulated one. All published metrics were produced by the offline validator; the Claude path is wired and unit-tested but has not been measured end to end against the corpus. Re-run `python scan.py testdata/vuln-flask` with a working key before the demo to populate the Claude column. |
| ENV-2 | Semgrep downloads `p/security-audit` from its registry on first use. Do this once before the demo — an offline venue means the comparison silently degrades to "unavailable". |
