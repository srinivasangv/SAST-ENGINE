"""Accuracy against the hand-labelled oracle.

Owner: Member 7 (QA) with Member 4 (metrics).

This is the file that turns "our scanner is good" into a number. It grades the
engine against testdata/ground_truth.json and asserts thresholds, so a change
that quietly loses recall or leaks false positives fails the build instead of
showing up on stage.
"""

from __future__ import annotations

import pytest

from engine import baseline


# ==========================================================================
# Per-repository accuracy
# ==========================================================================

class TestAccuracy:
    @pytest.mark.parametrize("repo_name", ["vuln-flask", "vuln-express", "safe-app"])
    def test_stage3_is_perfect_on_the_corpus(self, repo_name, all_scans, ground_truth):
        """After validation: every real bug found, nothing false reported."""
        scan = all_scans[repo_name]
        score = baseline.grade(scan["confirmed"], repo_name, ground_truth)

        assert score["false_positives"] == 0, (
            f"{repo_name}: false positives {score['detail']['false_positives']}")
        assert score["false_negatives"] == 0, (
            f"{repo_name}: missed {score['detail']['false_negatives']}")

        # Precision and recall are undefined when there is nothing to divide by.
        # safe-app is exactly that case: it should report nothing at all, which
        # is a pass, not a precision of zero.
        if score["true_positives"] + score["false_positives"] > 0:
            assert score["precision"] == 1.0
        else:
            assert scan["confirmed"] == [], "no findings expected for this repo"
        if score["true_positives"] + score["false_negatives"] > 0:
            assert score["recall"] == 1.0

    @pytest.mark.parametrize("repo_name", ["vuln-flask", "vuln-express"])
    def test_stage2_finds_everything_but_is_noisy(self, repo_name, all_scans, ground_truth):
        """Pattern matching alone has perfect recall and poor precision.

        This is the premise of the whole project. If Stage 2 ever became
        precise on its own, Stage 3 would have nothing to do -- and if it lost
        recall, Stage 3 could not recover it.
        """
        scan = all_scans[repo_name]
        score = baseline.grade(scan["raw"], repo_name, ground_truth)

        assert score["recall"] == 1.0, "Stage 2 must not miss a real vulnerability"
        assert score["false_positives"] > 0, (
            "Stage 2 is expected to be noisy -- if it is not, the decoys are "
            "not doing their job")

    def test_validation_removes_every_false_positive(self, all_scans, ground_truth):
        before = after = 0
        for repo_name in ("vuln-flask", "vuln-express", "safe-app"):
            scan = all_scans[repo_name]
            before += baseline.grade(scan["raw"], repo_name, ground_truth)["false_positives"]
            after += baseline.grade(scan["confirmed"], repo_name, ground_truth)["false_positives"]

        assert before == 11, "the corpus should contain 11 decoys"
        assert after == 0
        assert (before - after) / before == 1.0

    def test_recall_is_not_traded_away_for_precision(self, all_scans, ground_truth):
        """Suppressing everything would give perfect precision and be useless."""
        for repo_name in ("vuln-flask", "vuln-express"):
            scan = all_scans[repo_name]
            raw = baseline.grade(scan["raw"], repo_name, ground_truth)
            validated = baseline.grade(scan["confirmed"], repo_name, ground_truth)
            assert validated["recall"] >= raw["recall"], (
                f"{repo_name}: validation lost a real vulnerability")


# ==========================================================================
# Aggregate metrics for the report and the deck
# ==========================================================================

class TestReportedMetrics:
    def test_overall_numbers(self, all_scans, ground_truth, capsys):
        totals = {"tp": 0, "fp": 0, "fn": 0, "raw": 0, "confirmed": 0}

        for repo_name in ("vuln-flask", "vuln-express", "safe-app"):
            scan = all_scans[repo_name]
            score = baseline.grade(scan["confirmed"], repo_name, ground_truth)
            totals["tp"] += score["true_positives"]
            totals["fp"] += score["false_positives"]
            totals["fn"] += score["false_negatives"]
            totals["raw"] += len(scan["raw"])
            totals["confirmed"] += len(scan["confirmed"])

        precision = totals["tp"] / (totals["tp"] + totals["fp"])
        recall = totals["tp"] / (totals["tp"] + totals["fn"])
        suppression = (totals["raw"] - totals["confirmed"]) / totals["raw"]

        # Printed with -s so the numbers on the slides come from a test run.
        print(f"\n  corpus totals: {totals}")
        print(f"  precision {precision:.1%}  recall {recall:.1%}  "
              f"suppression {suppression:.1%}")

        assert totals["tp"] == 17, "17 real vulnerabilities are planted in the corpus"
        assert precision == 1.0
        assert recall == 1.0
        assert suppression == pytest.approx(11 / 28)


# ==========================================================================
# Semgrep comparison (skipped automatically when Semgrep is unavailable)
# ==========================================================================

@pytest.mark.skipif(not baseline.semgrep_available(), reason="semgrep is not installed")
class TestAgainstSemgrep:
    """Semgrep is now the SECONDARY baseline -- Joern is the primary one.

    These tests therefore pass with_semgrep=True explicitly; a default
    comparison no longer runs Semgrep at all.
    """

    def test_semgrep_runs_and_returns_findings(self, repos):
        result = baseline.run_semgrep(repos["vuln-flask"])
        assert result["available"], result.get("error")
        assert len(result["findings"]) > 0

    def test_we_beat_the_baseline_on_precision_and_recall(self, all_scans, repos, ground_truth):
        scan = all_scans["vuln-flask"]
        comparison = baseline.compare(
            "vuln-flask", repos["vuln-flask"], scan["raw"], scan["confirmed"],
            ground_truth, with_semgrep=True)

        if not comparison["semgrep"]["available"]:
            pytest.skip(f"semgrep unavailable: {comparison['semgrep'].get('error')}")

        semgrep = comparison["semgrep"]["score"]
        ours = comparison["stage3_after_validation"]["score"]

        print(f"\n  semgrep : precision {semgrep['precision']:.1%} "
              f"recall {semgrep['recall']:.1%}")
        print(f"  ours    : precision {ours['precision']:.1%} "
              f"recall {ours['recall']:.1%}")

        assert ours["precision"] >= semgrep["precision"]
        assert ours["recall"] >= semgrep["recall"]

    def test_the_suppression_headline_is_real(self, all_scans, repos, ground_truth):
        scan = all_scans["vuln-flask"]
        comparison = baseline.compare(
            "vuln-flask", repos["vuln-flask"], scan["raw"], scan["confirmed"],
            ground_truth, with_semgrep=True)
        suppression = comparison["suppression"]

        assert suppression["false_positives_before"] > 0
        assert suppression["false_positives_after"] == 0
        assert suppression["fp_suppression_rate"] == 1.0
        assert suppression["precision_gain"] > 0
        assert suppression["recall_change"] == 0.0
