import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path


class _NoOpLogger:
    def info(self, *_args, **_kwargs):
        pass

    def warning(self, *_args, **_kwargs):
        pass

    def error(self, *_args, **_kwargs):
        pass

    def debug(self, *_args, **_kwargs):
        pass


sys.modules.setdefault("loguru", types.SimpleNamespace(logger=_NoOpLogger()))

from src.analysis.assessment import determine_threat_level, recommended_actions
from src.analysis.hybrid_reasoning import HybridReasoningEngine, LLMReasoner, RuleEngine
from src.utils.path_guard import DEFAULT_DATA_DIR, UnsafePathError, resolve_log_path
from src.utils.text_sanitize import clean_emoji_characters


class TextSanitizeTests(unittest.TestCase):
    def test_keeps_chinese_and_strips_emoji(self):
        cleaned = clean_emoji_characters("SQL注入攻击🔥分析")
        self.assertIn("SQL注入攻击", cleaned)
        self.assertNotIn("🔥", cleaned)

    def test_does_not_reduce_to_ascii_only(self):
        cleaned = clean_emoji_characters("载荷：' OR '1'='1")
        self.assertIn("载荷", cleaned)


class PathGuardTests(unittest.TestCase):
    def test_allows_checked_in_sample(self):
        resolved = resolve_log_path("sample.csv")
        self.assertEqual(resolved, (DEFAULT_DATA_DIR / "sample.csv").resolve())

    def test_rejects_urls(self):
        with self.assertRaises(UnsafePathError):
            resolve_log_path("https://example.com/alerts.xlsx")

    def test_rejects_path_escape(self):
        with self.assertRaises(UnsafePathError):
            resolve_log_path("../README.md")


class AssessmentTests(unittest.TestCase):
    def test_threat_levels(self):
        self.assertEqual(determine_threat_level(9.0), "critical")
        self.assertEqual(determine_threat_level(7.0), "high")
        self.assertEqual(determine_threat_level(5.0), "medium")
        self.assertEqual(determine_threat_level(1.0), "low")
        self.assertEqual(determine_threat_level("bad"), "unknown")

    def test_high_risk_sql_actions_are_non_empty(self):
        actions = recommended_actions("sql_injection", 8.5, 0.9)
        self.assertTrue(actions)
        self.assertTrue(any("IP" in item or "WAF" in item or "database" in item.lower() for item in actions))


class RuleEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = RuleEngine()

    def test_union_select_is_sql_injection(self):
        result = self.engine.analyze("' UNION SELECT * FROM users --", "unknown")
        self.assertEqual(result["attack_type"], "sql_injection")
        self.assertGreaterEqual(result["risk_score"], 8.0)
        self.assertLessEqual(result["confidence"], 1.0)
        self.assertTrue(result["matched_rules"].get("sql_injection"))

    def test_xss_is_not_classified_as_sql_because_of_select_in_unrelated_text(self):
        result = self.engine.analyze("<script>alert(1)</script>", "xss")
        self.assertEqual(result["attack_type"], "xss")
        self.assertNotIn("sql_injection", result["matched_rules"])

    def test_or_equals_one_payload_matches_sql(self):
        result = self.engine.analyze("' OR '1'='1", "unknown")
        self.assertEqual(result["attack_type"], "sql_injection")
        self.assertTrue(any("or_injection" in item or "Pattern match" in item for item in result["evidence"]))


class LlmParseTests(unittest.TestCase):
    def setUp(self):
        self.reasoner = LLMReasoner()

    def test_empty_response_is_fallback_confidence(self):
        parsed = self.reasoner._parse_llm_response("", "SQL Injection")
        self.assertLessEqual(parsed["confidence"], 0.3)
        self.assertTrue(parsed.get("from_fallback"))

    def test_extracts_first_json_object_not_greedy_span(self):
        text = 'prefix {"attack_type": "XSS", "confidence": 0.6, "risk_score": 4, "analysis": "ok {nested}"} trailing {not json}'
        parsed = self.reasoner._parse_llm_response(text, "xss")
        self.assertEqual(parsed["attack_type"], "XSS")
        self.assertAlmostEqual(parsed["confidence"], 0.6)


class FusionFallbackTests(unittest.TestCase):
    def test_fallback_llm_does_not_dominate_rule_result(self):
        engine = HybridReasoningEngine()
        rule_result = {
            "attack_type": "sql_injection",
            "confidence": 0.8,
            "risk_score": 8.5,
            "evidence": ["Pattern match: union\\s+select"],
        }
        llm_result = {
            "attack_type": "Unknown",
            "confidence": 0.85,
            "risk_score": 7.5,
            "analysis": "Real Qwen2-7B Model Analysis: ",
            "llm_response": None,
            "from_fallback": True,
        }
        fused = engine._fuse_results(rule_result, llm_result)
        self.assertEqual(fused["attack_type"], "sql_injection")
        self.assertLess(fused["confidence"], 0.85)


@unittest.skipUnless(importlib.util.find_spec("numpy"), "numpy is required for IntelligentRouter")
class IntelligentRouterKeywordTests(unittest.TestCase):
    def test_error_log_is_not_sql_because_of_bare_or(self):
        from src.agents.intelligent_router import IntelligentRouter

        router = IntelligentRouter()
        scores = router.calculate_keyword_match_score({
            "payload": "application error in command handler",
            "attack_type": "unknown",
            "raw_log": "error",
        })
        self.assertLess(scores.get("web_attack", 1.0), 0.5)


class RouterAgentTests(unittest.TestCase):
    def test_sql_payload_routes_to_web_attack(self):
        from src.agents.router_agent import RouterAgent

        router = RouterAgent("test_router")
        self.assertTrue(router.initialize())
        result = router.process({
            "attack_type": "SQL Injection",
            "payload": "' UNION SELECT * FROM users --",
            "raw_log": "",
        })
        self.assertTrue(result.success)
        self.assertEqual(result.result["selected_route"], "web_attack")


@unittest.skipUnless(importlib.util.find_spec("pandas"), "pandas is required for AlertLogParser")
class LogParserSampleTests(unittest.TestCase):
    def test_sample_csv_parses(self):
        from src.parsers.log_parser import AlertLogParser

        parser = AlertLogParser()
        alerts = parser.parse_excel_log(str(Path("data/sample.csv")))
        self.assertGreaterEqual(len(alerts), 1)
        self.assertTrue(any("SQL" in alert.attack_type or "sql" in alert.attack_type.lower() or "注入" in alert.attack_type for alert in alerts))


if __name__ == "__main__":
    unittest.main()
