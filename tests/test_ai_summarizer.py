"""Tests for the AI summarizer module (unit tests — no actual API calls)."""

from regulatory_alerts.core.ai_summarizer import (
    _calculate_relevance_score,
    _calculate_cost,
)


class TestCalculateRelevanceScore:
    def test_enforcement_action_high_score(self):
        score = _calculate_relevance_score("enforcement_action", ["enforcement"], "SEC charges")
        assert score >= 0.9

    def test_press_release_baseline(self):
        score = _calculate_relevance_score("press_release", ["reporting"], "Monthly report")
        assert score == 0.5

    def test_urgency_keywords_boost(self):
        normal = _calculate_relevance_score("guidance", ["securities"], "New guidance")
        urgent = _calculate_relevance_score("guidance", ["securities"], "Emergency halt order")
        assert urgent > normal

    def test_crypto_topic_boost(self):
        without = _calculate_relevance_score("proposed_rule", ["securities"], "Rule")
        with_crypto = _calculate_relevance_score("proposed_rule", ["crypto"], "Rule")
        assert with_crypto > without

    def test_max_score_capped_at_1(self):
        score = _calculate_relevance_score(
            "enforcement_action",
            ["crypto", "fraud", "enforcement"],
            "Emergency halt and freeze of assets",
        )
        assert score <= 1.0

    def test_unknown_doc_type_baseline(self):
        score = _calculate_relevance_score("unknown_type", [], "Something")
        assert score == 0.5


class TestCalculateCost:
    def test_basic_cost(self):
        cost = _calculate_cost(input_tokens=1000, output_tokens=200)
        # 1000 * $0.000001 + 200 * $0.000005 = $0.001 + $0.001 = $0.002
        assert float(cost) == pytest.approx(0.002, abs=1e-6)

    def test_zero_tokens(self):
        cost = _calculate_cost(0, 0)
        assert float(cost) == 0.0


# Need pytest for approx
import pytest  # noqa: E402
