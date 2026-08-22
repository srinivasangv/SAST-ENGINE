"""Unit tests -- each module on its own.

Owner: Member 7 (QA), with each module's owner reviewing their section.
"""

from __future__ import annotations

import ast

import pytest

from engine import dedupe, llm, rules, sla, stage1_prepare
from engine.py_parser import PythonParser
from engine.cpg import CPG


# ==========================================================================
# rules.py  (Member 2)
# ==========================================================================

class TestRuleMatching:
    def test_exact_match(self):
        assert rules.matches("os.system", "os.system")

    def test_method_on_any_object(self):
        assert rules.matches("cursor.execute", "execute")
        assert rules.matches("db.execute", "execute")

    def test_attribute_of_a_source(self):
        assert rules.matches("request.args.get", "request.args")

    def test_does_not_match_a_substring(self):
        # `my_execute` is a different function; matching it would be a false positive.
        assert not rules.matches("my_execute", "execute")
        assert not rules.matches("system", "os.system")

    def test_sinks_are_language_scoped(self):
        assert rules.find_sink("os.system", "python") is not None
        assert rules.find_sink("os.system", "javascript") is None

    def test_every_sink_names_a_known_vulnerability_class(self):
        for sink in rules.SINKS:
            assert sink["category"] in rules.VULN_CLASSES, sink["pattern"]

    def test_every_vulnerability_class_is_complete(self):
        for name, meta in rules.VULN_CLASSES.items():
            for field in ("title", "cwe", "severity", "payload", "why", "fix"):
                assert meta.get(field), f"{name} is missing {field}"

    @pytest.mark.parametrize("sanitizer,category,expected", [
        ("shlex.quote", "command_injection", True),
        ("shlex.quote", "sql_injection", False),      # wrong tool for the job
        ("int", "sql_injection", True),               # an integer is safe everywhere
        ("html.escape", "xss", True),
        ("html.escape", "ssti", False),               # does not escape {{ }}
    ])
    def test_sanitizer_only_covers_the_right_sinks(self, sanitizer, category, expected):
        assert rules.sanitizer_covers(sanitizer, category, "python") is expected


# ==========================================================================
# py_parser.py  (Member 1)
# ==========================================================================

class TestPythonParser:
    def _parse(self, source: str):
        parser = PythonParser(CPG())
        functions, error = parser.parse_file("t.py", source)
        assert error is None
        return {function.name: function for function in functions}

    def test_finds_a_function_and_its_parameters(self):
        functions = self._parse("def handle(a, b):\n    return a\n")
        assert "handle" in functions
        assert functions["handle"].params == ["a", "b"]

    def test_self_is_not_a_parameter(self):
        functions = self._parse("class C:\n    def m(self, x):\n        return x\n")
        assert functions["C.m"].params == ["x"]

    def test_reads_a_flask_route(self):
        functions = self._parse(
            "@app.route('/go', methods=['POST'])\ndef go():\n    return 'x'\n")
        assert functions["go"].is_route
        assert functions["go"].route_path == "/go"
        assert functions["go"].route_methods == ["POST"]

    def test_recognises_a_source(self):
        functions = self._parse("def f():\n    x = request.args.get('q')\n")
        statement = functions["f"].body[0]
        assert "request.args" in statement.value.sources

    def test_taint_flows_through_an_fstring(self):
        functions = self._parse("def f():\n    q = 'a'\n    s = f'select {q}'\n")
        assert "q" in functions["f"].body[1].value.vars

    def test_detects_dead_code(self):
        functions = self._parse("def f():\n    if False:\n        pass\n")
        assert functions["f"].body[0].always_false

    def test_a_broken_file_reports_an_error_instead_of_raising(self):
        parser = PythonParser(CPG())
        functions, error = parser.parse_file("bad.py", "def f(:\n")
        assert functions == []
        assert error and "SyntaxError" in error


# ==========================================================================
# stage1_prepare.py  (Member 1)
# ==========================================================================

class TestDiscovery:
    def test_skips_vendor_directories(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\n")
        vendored = tmp_path / "node_modules" / "pkg"
        vendored.mkdir(parents=True)
        (vendored / "index.js").write_text("var x = 1;\n")

        found = [p.name for p in stage1_prepare.discover_files(tmp_path)]
        assert found == ["app.py"]

    def test_an_empty_repository_is_not_an_error(self, tmp_path):
        repo = stage1_prepare.prepare(tmp_path, repo_name="empty")
        assert repo.files == []
        assert repo.stats()["nodes"] == 0

    def test_a_missing_path_raises_a_clear_error(self):
        with pytest.raises(FileNotFoundError):
            stage1_prepare.prepare("/no/such/directory")


# ==========================================================================
# dedupe.py  (Member 4)
# ==========================================================================

class TestCodeShape:
    def test_identical_pattern_in_two_languages_has_one_shape(self):
        python = dedupe.code_shape('os.system("ping -c 1 " + host)')
        javascript = dedupe.code_shape('child_process.exec("ping -c 1 " + host)')
        assert python == javascript

    def test_fstring_and_template_literal_have_one_shape(self):
        python = dedupe.code_shape('cursor.execute(f"SELECT * WHERE id = {uid}")')
        javascript = dedupe.code_shape("db.query(`SELECT * WHERE id = ${uid}`)")
        assert python == javascript

    def test_different_structures_have_different_shapes(self):
        assert dedupe.code_shape("os.system(cmd)") != dedupe.code_shape('os.system("a" + cmd)')

    def test_placeholders_cannot_be_re_matched_as_identifiers(self):
        # Regression: an earlier version used the words STR and NAME, and the
        # identifier pass rewrote STR to NAME, collapsing unrelated shapes.
        assert dedupe.code_shape('f("literal")') != dedupe.code_shape("f(variable)")

    def test_clustering_groups_by_pattern_not_location(self):
        findings = [
            {"cwe": "CWE-78", "category": "command_injection", "source_label": "HTTP query string",
             "sink_code": 'os.system("ping " + h)', "repo": "a", "file": "a.py", "line": 1,
             "id": "1", "severity": "critical", "title": "OS Command Injection"},
            {"cwe": "CWE-78", "category": "command_injection", "source_label": "HTTP query string",
             "sink_code": 'child_process.exec("ping " + h)', "repo": "b", "file": "b.js",
             "line": 2, "id": "2", "severity": "critical", "title": "OS Command Injection"},
        ]
        result = dedupe.cluster(findings)
        assert result["summary"]["clusters_after"] == 1
        assert result["summary"]["cross_repo_clusters"] == 1


# ==========================================================================
# llm.py  (Member 3)
# ==========================================================================

def _finding(**overrides):
    base = {
        "category": "command_injection", "language": "python", "severity": "critical",
        "title": "OS Command Injection", "sink": "os.system", "file": "a.py", "line": 1,
        "function": "f", "entry": "HTTP route GET /x", "http_reachable": True,
        "source_label": "HTTP query string", "sanitizers": [], "guarded": False,
        "unreachable": False, "taint_path": [], "sink_code": "os.system(x)",
        "route_path": "/x", "cwe": "CWE-78", "owasp": "A03",
    }
    base.update(overrides)
    return base


class TestOfflineValidator:
    def test_unguarded_path_is_exploitable(self):
        verdict = llm.offline_verdict(_finding())
        assert verdict["exploitable"] is True

    def test_dead_code_is_not_exploitable(self):
        verdict = llm.offline_verdict(_finding(unreachable=True))
        assert verdict["exploitable"] is False
        assert "never execute" in verdict["reasoning"]

    def test_correct_sanitizer_suppresses(self):
        verdict = llm.offline_verdict(_finding(sanitizers=["shlex.quote"]))
        assert verdict["exploitable"] is False

    def test_wrong_sanitizer_does_not_suppress(self):
        # html.escape does nothing about a shell. The finding must survive.
        verdict = llm.offline_verdict(_finding(sanitizers=["html.escape"]))
        assert verdict["exploitable"] is True
        assert "does not neutralise" in verdict["reasoning"]

    def test_validation_check_suppresses(self):
        verdict = llm.offline_verdict(_finding(guarded=True))
        assert verdict["exploitable"] is False

    def test_unreachable_entry_point_suppresses(self):
        verdict = llm.offline_verdict(_finding(http_reachable=False))
        assert verdict["exploitable"] is False
        assert "entry point" in verdict["reasoning"]

    def test_judge_falls_back_when_no_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        verdict = llm.judge(_finding())
        assert verdict["validator"] == "offline"
        assert "fallback_reason" in verdict

    def test_judge_falls_back_when_claude_errors(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "anthropic")
        monkeypatch.setattr(llm, "ask_claude", lambda finding: {"_error": "boom"})
        verdict = llm.judge(_finding(), use_llm=True)
        assert verdict["validator"] == "offline"
        assert verdict["fallback_reason"] == "boom"

    def test_verdict_parsing_tolerates_surrounding_prose(self):
        parsed = llm._parse_verdict(
            'Sure, here is my verdict:\n{"exploitable": true, "confidence": 0.9, '
            '"severity": "high", "reasoning": "r", "attack_scenario": "s"}\nHope that helps.')
        assert parsed["exploitable"] is True
        assert parsed["severity"] == "high"

    def test_verdict_parsing_rejects_nonsense(self):
        assert llm._parse_verdict("I could not decide.") is None

    def test_confidence_is_clamped(self):
        parsed = llm._parse_verdict('{"exploitable": true, "confidence": 5}')
        assert parsed["confidence"] == 1.0


# ==========================================================================
# sla.py  (Member 6)
# ==========================================================================

class TestSla:
    def test_a_fresh_critical_finding_is_on_track(self):
        state = sla.evaluate({"id": "x", "severity": "critical"}, age_hours=1)
        assert state["state"] == "on_track"
        assert not state["breached"]

    def test_an_old_critical_finding_breaches_and_escalates(self):
        state = sla.evaluate({"id": "x", "severity": "critical"}, age_hours=100)
        assert state["breached"]
        assert state["overdue_by_hours"] == pytest.approx(100 - 24)
        assert "security-lead" in state["escalate_to"]

    def test_severity_changes_the_budget(self):
        critical = sla.evaluate({"id": "a", "severity": "critical"}, age_hours=48)
        low = sla.evaluate({"id": "b", "severity": "low"}, age_hours=48)
        assert critical["breached"]
        assert not low["breached"]

    def test_an_applied_fix_stops_the_clock(self):
        state = sla.evaluate(
            {"id": "x", "severity": "critical", "fix_status": "applied"}, age_hours=500)
        assert state["state"] == "resolved"
        assert not state["breached"]

    def test_at_risk_before_breaching(self):
        # 20 of the 24-hour critical budget used: inside the last quarter.
        state = sla.evaluate({"id": "x", "severity": "critical"}, age_hours=20)
        assert state["state"] == "at_risk"

    def test_an_unparseable_timestamp_does_not_crash(self):
        assert sla.hours_since("not a date") == 0.0
        assert sla.hours_since(None) == 0.0


# ==========================================================================
# Provider selection  (Member 3)
# ==========================================================================

class TestProviderSelection:
    """Stage 3 must work with Claude, with OpenAI, or with neither."""

    def test_anthropic_wins_when_both_keys_are_set(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-x")
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        from engine import config
        assert config.detect_provider() == "anthropic"

    def test_openai_is_used_when_only_its_key_is_set(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-x")
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        from engine import config
        assert config.detect_provider() == "openai"
        assert config.llm_model_for() == config.OPENAI_MODEL

    def test_no_key_means_offline(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        from engine import config
        assert config.detect_provider() == "offline"
        assert config.llm_available() is False

    def test_llm_provider_env_overrides_the_keys(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
        monkeypatch.setenv("LLM_PROVIDER", "offline")
        from engine import config
        assert config.detect_provider() == "offline"

    def test_an_openai_verdict_is_used_when_the_call_succeeds(self, monkeypatch):
        monkeypatch.setattr(llm, "ask_openai", lambda f: {
            "exploitable": True, "confidence": 0.88, "severity": "critical",
            "reasoning": "r", "attack_scenario": "s",
            "validator": "openai", "provider": "openai", "model": "gpt-4.1"})
        verdict = llm.judge(_finding(), provider="openai")
        assert verdict["validator"] == "openai"
        assert verdict["provider"] == "openai"
        assert "fallback_reason" not in verdict

    def test_a_quota_error_falls_back_and_says_so(self, monkeypatch):
        """The exact failure our supplied OpenAI key produced: auth fine, no credit."""
        monkeypatch.setattr(llm, "ask_openai", lambda f: {
            "_error": "openai: quota exceeded or rate limited (HTTP 429). "
                      "Check the account's billing."})
        verdict = llm.judge(_finding(), provider="openai")
        assert verdict["validator"] == "offline"
        assert "quota exceeded" in verdict["fallback_reason"]
        assert verdict["attempted_provider"] == "openai"
        # Still a usable verdict, not an exception.
        assert verdict["exploitable"] is True

    def test_a_401_falls_back_and_says_so(self, monkeypatch):
        """The exact failure our supplied Anthropic key produced."""
        monkeypatch.setattr(llm, "ask_claude", lambda f: {
            "_error": "AuthenticationError: 401 API key is invalid."})
        verdict = llm.judge(_finding(), provider="anthropic")
        assert verdict["validator"] == "offline"
        assert "401" in verdict["fallback_reason"]

    def test_no_llm_flag_forces_offline_even_with_a_key(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
        verdict = llm.judge(_finding(), use_llm=False)
        assert verdict["validator"] == "offline"
        assert "--no-llm" in verdict["fallback_reason"]

    def test_both_providers_are_asked_the_same_question(self):
        """The comparison is only meaningful if the prompt is identical."""
        finding = _finding()
        prompt = llm.build_prompt(finding)
        assert "TAINT PATH:" in prompt and "SANITIZERS ON PATH" in prompt
        # Same SYSTEM_PROMPT and same build_prompt() feed both call paths.
        import inspect
        for source in (inspect.getsource(llm.ask_claude),
                       inspect.getsource(llm.ask_openai)):
            assert "SYSTEM_PROMPT" in source
            assert "build_prompt(finding)" in source

    def test_every_verdict_records_which_provider_produced_it(self):
        verdict = llm.offline_verdict(_finding())
        assert verdict["provider"] == "offline"
        assert verdict["model"]
