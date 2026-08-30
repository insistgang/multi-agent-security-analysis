#!/usr/bin/env python3
"""
Hybrid Reasoning Engine
Combining LLM inference with rule-based analysis
"""

#  - 
import sys
import os

# UTF-8
if sys.platform == 'win32':
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    os.environ['PYTHONLEGACYWINDOWSSTDIO'] = '0'

# 
def safe_print(*args, **kwargs):
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        cleaned_args = []
        for arg in args:
            if isinstance(arg, str):
                # ASCII
                cleaned = ''.join(c for c in arg if ord(c) < 128)
                cleaned_args.append(cleaned)
            else:
                cleaned_args.append(str(arg))
        print(*cleaned_args, **kwargs)

import json
import logging
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from src.utils.text_sanitize import clean_emoji_characters

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ReasoningResult:
    """Reasoning result"""
    attack_type: str
    confidence: float
    risk_score: float
    evidence: List[str]
    analysis_details: str
    reasoning_path: List[str]
    matched_rules: Dict[str, Any]
    llm_response: Optional[str] = None

class RuleEngine:
    """Rule engine"""

    def __init__(self):
        """Initialize rule base"""
        self.rules = self._load_rules()

    def _load_rules(self) -> Dict[str, Any]:
        """Load security rules"""
        return {
            "sql_injection": {
                "patterns": [
                    r"union\s+select",
                    r"or\s+1\s*=\s*1",
                    r"or\s+'?1'?\s*=\s*'?1'?",
                    r"'\s*or\s+'",
                    r"drop\s+table",
                    r"insert\s+into",
                    r"delete\s+from",
                    r"update\s+.*set",
                    r"exec\s*\(",
                    r"script\s*>",
                    r"waitfor\s+delay"
                ],
                "keywords": [
                    "union", "select", "drop", "insert", "delete",
                    "update", "exec", "script", "waitfor", "delay"
                ],
                "risk_factors": {
                    "union_select": (r"union\s+select", 8.5),
                    "or_injection": (r"or\s+'?1'?\s*=\s*'?1'?", 7.0),
                    "drop_table": (r"drop\s+table", 9.5),
                    "exec_script": (r"exec\s*\(", 9.0),
                }
            },
            "xss": {
                "patterns": [
                    r"<script[^>]*>",
                    r"javascript:",
                    r"onload\s*=",
                    r"onerror\s*=",
                    r"onclick\s*=",
                    r"alert\s*\(",
                    r"document\.cookie",
                    r"window\.location"
                ],
                "keywords": [
                    "script", "javascript", "alert", "cookie", "location",
                    "onload", "onerror", "onclick"
                ],
                "risk_factors": {
                    "script_tag": (r"<script", 7.5),
                    "javascript_protocol": (r"javascript:", 8.0),
                    "cookie_access": (r"document\.cookie", 8.5),
                }
            },
            "command_injection": {
                "patterns": [
                    r";\s*[;&|`$]",
                    r"cmd\.exe",
                    r"/bin/sh",
                    r"eval\s*\(",
                    r"system\s*\(",
                    r"passthru\s*\(",
                    r"exec\s*\(",
                    r"shell_exec\s*\("
                ],
                "keywords": [
                    "cmd", "shell", "eval", "system", "exec", "passthru"
                ],
                "risk_factors": {
                    "direct_command": (r"(;|\||&&|`|\$\()", 9.0),
                    "shell_execution": (r"(cmd\.exe|/bin/sh|system\s*\()", 8.5),
                }
            }
        }

    def _candidate_families(self, attack_type: str) -> List[str]:
        attack = (attack_type or "unknown").lower()
        if attack in ("unknown", "", "none"):
            return list(self.rules.keys())
        if "xss" in attack or "cross-site" in attack or "script" in attack:
            return ["xss"]
        if "sql" in attack or ("injection" in attack and "command" not in attack):
            return ["sql_injection"]
        if "command" in attack or "rce" in attack or "shell" in attack:
            return ["command_injection"]
        return list(self.rules.keys())

    def analyze(self, payload: str, attack_type: str) -> Dict[str, Any]:
        """Use rule engine to analyze payload"""
        import re

        if not payload:
            return {
                "matched_rules": {},
                "confidence": 0.0,
                "risk_score": 5.0,
                "evidence": [],
                "attack_type": attack_type or "Unknown",
            }

        payload_lower = payload.lower()
        matched_rules = {}
        evidence = []
        max_risk_score = 5.0
        family_hits = {}

        for rule_name in self._candidate_families(attack_type):
            rule_config = self.rules[rule_name]
            family_score = 0.0

            for pattern in rule_config["patterns"]:
                if re.search(pattern, payload_lower, re.IGNORECASE):
                    matched_rules[rule_name] = True
                    family_score = max(family_score, 6.0)
                    evidence.append(f"Pattern match: {pattern}")

            for factor, factor_spec in rule_config["risk_factors"].items():
                if isinstance(factor_spec, tuple):
                    factor_pattern, score = factor_spec
                else:
                    factor_pattern, score = re.escape(str(factor).replace("_", r"\s+")), float(factor_spec)
                if re.search(factor_pattern, payload_lower, re.IGNORECASE):
                    matched_rules[rule_name] = True
                    family_score = max(family_score, float(score))
                    max_risk_score = max(max_risk_score, float(score))
                    evidence.append(f"Risk factor: {factor}")

            if rule_name in matched_rules:
                for keyword in rule_config["keywords"]:
                    if keyword and keyword.lower() in payload_lower:
                        evidence.append(f"Keyword match: {keyword}")
                        family_score = max(family_score, 5.5)

            if rule_name in matched_rules:
                family_hits[rule_name] = family_score

        if any(char in payload for char in "'\";\\/&|`") and not matched_rules:
            matched_rules["suspicious_chars"] = True
            evidence.append("Suspicious characters detected")

        confidence = min(0.9, len([k for k in matched_rules if k != "suspicious_chars"]) * 0.3)
        if matched_rules:
            confidence = max(confidence, 0.4)
            if len(evidence) > 3:
                confidence *= 1.2
            if max_risk_score > 7.0:
                confidence = min(confidence, 0.95)
        confidence = max(0.0, min(1.0, confidence))

        if family_hits:
            detected_type = max(family_hits, key=family_hits.get)
            max_risk_score = min(10.0, max(max_risk_score, family_hits[detected_type]))
        elif matched_rules:
            detected_type = attack_type or "Unknown"
        else:
            detected_type = attack_type or "Unknown"
            max_risk_score = 5.0

        return {
            "matched_rules": matched_rules,
            "confidence": confidence,
            "risk_score": max_risk_score,
            "evidence": evidence,
            "attack_type": detected_type,
        }

class LLMReasoner:
    """LLM reasoner"""

    def __init__(self):
        """Initialize reasoning templates"""
        self.templates = self._load_templates()

    def _load_templates(self) -> Dict[str, str]:
        """Load reasoning templates"""
        return {
            "sql_injection": """
As a cybersecurity expert, please analyze the following potential SQL injection attack:

[Alert Information]
Attack Type: {attack_type}
Payload: {payload}
Source IP: {source_ip}
Target IP: {target_ip}
Protocol: {protocol}
Threat Level: {threat_level}

Please analyze from the following perspectives:
1. What SQL injection characteristics are contained in the payload?
2. What type of SQL injection is this (UNION query, boolean blind, time blind, etc.)?
3. What is the complexity and harm level of the attack?
4. What is the possible intent of the attacker?

Please return analysis results in JSON format:
{{
    "attack_type": "SQL Injection Attack",
    "attack_subtype": "Specific subtype",
    "confidence": 0.95,
    "risk_score": 8.5,
    "intent": "Data theft/System control/Other",
    "target": "Database/Authentication system/Other",
    "analysis": "Detailed analysis description"
}}
""",
            "xss": """
As a web security expert, please analyze the following potential XSS attack:

[Alert Information]
Attack Type: {attack_type}
Payload: {payload}
Source IP: {source_ip}
Target IP: {target_ip}
Protocol: {protocol}
Threat Level: {threat_level}

Please analyze from the following perspectives:
1. What XSS characteristics are contained in the payload?
2. What type of XSS is this (reflected, stored, DOM-based)?
3. What is the target and possible impact of the attack?
4. What is the technical complexity of the attack?

Please return analysis results in JSON format:
{{
    "attack_type": "XSS Cross-site Scripting Attack",
    "attack_subtype": "Specific subtype",
    "confidence": 0.90,
    "risk_score": 7.5,
    "target": "Session hijacking/Cookie theft/Other",
    "impact": "Data leakage/Session compromise/Other",
    "analysis": "Detailed analysis description"
}}
""",
            "general": """
As a cybersecurity expert, please analyze the following security alert:

[Alert Information]
Attack Type: {attack_type}
Payload: {payload}
Source IP: {source_ip}
Target IP: {target_ip}
Protocol: {protocol}
Threat Level: {threat_level}

Please analyze:
1. What type of network attack is this?
2. What are the technical characteristics and complexity of the attack payload?
3. What are the possible harms and impact scope of the attack?
4. What is the technical skill level assessment of the attacker?

Please return analysis results in JSON format:
{{
    "attack_type": "Attack Type",
    "attack_subtype": "Specific subtype",
    "confidence": 0.85,
    "risk_score": 6.5,
    "intent": "Attack intent",
    "target": "Attack target",
    "analysis": "Detailed analysis description"
}}
"""
        }

    def analyze(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Use LLM for reasoning"""
        try:
            # Preprocess alert data
            attack_type = alert_data.get('attack_type', 'unknown')
            attack_type_l = str(attack_type).lower()
            payload = alert_data.get('payload', '')
            source_ip = alert_data.get('source_ip', 'unknown')
            target_ip = alert_data.get('target_ip', 'unknown')
            protocol = alert_data.get('protocol', 'unknown')
            threat_level = alert_data.get('threat_level', 'unknown')

            template = self.templates['general']
            if 'sql' in attack_type_l or ('injection' in attack_type_l and 'command' not in attack_type_l):
                template = self.templates['sql_injection']
            elif 'xss' in attack_type_l or 'cross-site' in attack_type_l or 'script' in attack_type_l:
                template = self.templates['xss']

            # Build reasoning prompt
            prompt = template.format(
                attack_type=alert_data.get('attack_type', 'unknown'),
                payload=alert_data.get('payload', ''),
                source_ip=alert_data.get('source_ip', 'unknown'),
                target_ip=alert_data.get('target_ip', 'unknown'),
                protocol=alert_data.get('protocol', 'unknown'),
                threat_level=alert_data.get('threat_level', 'unknown')
            )

            safe_print("\n[Hybrid Reasoning Engine] Qwen2-7B")

            try:
                from src.models.llm_inference_gpu import get_gpu_llm
                llm = get_gpu_llm()
            except Exception as gpu_error:
                safe_print(f"[WARN] GPU LLM unavailable: {clean_emoji_characters(str(gpu_error))}")
                from src.models.llm_inference import get_llm_inference
                llm = get_llm_inference()

            try:
                response = llm.generate_response(prompt, max_new_tokens=512, temperature=0.3)
                response_clean = clean_emoji_characters(response or "")
                if not response_clean.strip():
                    safe_print("[FALLBACK] Empty model response, using rule-friendly fallback")
                    return self.get_fallback_result(alert_data)
                safe_print("[SUCCESS] Qwen2-7B")
            except Exception as e:
                error_msg_clean = clean_emoji_characters(str(e))
                safe_print(f"[ERROR] {error_msg_clean}")
                return self.get_fallback_result(alert_data)

            parsed_result = self._parse_llm_response(response_clean, attack_type)
            if parsed_result.get("confidence", 0) <= 0.3 and not parsed_result.get("analysis"):
                return self.get_fallback_result(alert_data)
            parsed_result['llm_response'] = response_clean
            parsed_result['from_fallback'] = False
            return parsed_result

        except Exception as e:
            # emoji
            error_msg_clean = clean_emoji_characters(str(e))
            logger.error(f"LLM reasoning failed: {error_msg_clean}")
            safe_print(f"[ERROR] : Qwen2-7B! !")
            # 
            return self.get_fallback_result(alert_data)

  
    def _simulate_llm_response(self, attack_type: str, payload: str) -> Dict[str, Any]:
        """Simulate LLM reasoning results"""
        if 'sql' in attack_type.lower() or 'union' in payload.lower():
            return {
                "attack_type": "SQL Injection Attack",
                "attack_subtype": "UNION-based SQL Injection",
                "confidence": 0.95,
                "risk_score": 8.5,
                "intent": "Data theft",
                "target": "Database",
                "analysis": "Payload contains UNION SELECT statement, attacker trying to union query to get sensitive data, high technical complexity"
            }
        elif 'or' in payload.lower() and '1' in payload.lower():
            return {
                "attack_type": "SQL Injection Attack",
                "attack_subtype": "Boolean Blind Injection",
                "confidence": 0.85,
                "risk_score": 7.0,
                "intent": "Authentication bypass",
                "target": "Authentication system",
                "analysis": "Payload uses classic OR injection trying to bypass authentication, medium complexity SQL injection attack"
            }
        elif 'drop' in payload.lower() or 'delete' in payload.lower():
            return {
                "attack_type": "SQL Injection Attack",
                "attack_subtype": "Destructive SQL Injection",
                "confidence": 0.90,
                "risk_score": 9.5,
                "intent": "Data destruction",
                "target": "Database integrity",
                "analysis": "Payload contains destructive SQL commands, attacker trying to delete data or table structures, extremely harmful"
            }

        # XSS analysis
        elif 'xss' in attack_type.lower() or 'script' in payload.lower():
            if '<script>' in payload.lower():
                return {
                    "attack_type": "XSS Cross-site Scripting Attack",
                    "attack_subtype": "Reflected XSS",
                    "confidence": 0.90,
                    "risk_score": 7.5,
                    "target": "Session hijacking",
                    "impact": "Data leakage",
                    "analysis": "Payload contains JavaScript script tags and alert function, typical reflected XSS attack"
                }
            elif 'cookie' in payload.lower():
                return {
                    "attack_type": "XSS Cross-site Scripting Attack",
                    "attack_subtype": "Stored XSS",
                    "confidence": 0.85,
                    "risk_score": 8.0,
                    "target": "Cookie theft",
                    "impact": "Session compromise",
                    "analysis": "Payload trying to access document.cookie, goal is to steal user session information"
                }

        # General analysis
        return {
            "attack_type": attack_type or "Unknown Attack",
            "attack_subtype": "Further analysis needed",
            "confidence": 0.70,
            "risk_score": 6.0,
            "intent": "To be confirmed",
            "target": "To be confirmed",
            "analysis": f"Detected suspicious payload: {payload[:100]}, further analysis needed to confirm attack type and intent"
        }

    def _extract_json_object(self, text: str) -> Optional[Dict[str, Any]]:
        """Parse the first JSON object in `text` without greedy brace matching."""
        if not text:
            return None
        decoder = json.JSONDecoder()
        for index, char in enumerate(text):
            if char != "{":
                continue
            try:
                obj, _ = decoder.raw_decode(text[index:])
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                return obj
        return None

    def _parse_llm_response(self, response: str, attack_type: str) -> Dict[str, Any]:
        """Parse real LLM model response"""
        if not response or not str(response).strip():
            return {
                "attack_type": attack_type or "Unknown Attack",
                "attack_subtype": "Analysis Failed",
                "confidence": 0.3,
                "risk_score": 5.0,
                "intent": "Unknown",
                "target": "Unknown",
                "analysis": "Empty model response",
                "from_fallback": True,
            }

        try:
            result = self._extract_json_object(response)
            if result:
                confidence = float(result.get("confidence", 0.7))
                risk_score = float(result.get("risk_score", 6.0))
                return {
                    "attack_type": result.get("attack_type", attack_type or "Unknown Attack"),
                    "attack_subtype": result.get("attack_subtype", "AI Analysis Result"),
                    "confidence": max(0.0, min(1.0, confidence)),
                    "risk_score": max(0.0, min(10.0, risk_score)),
                    "intent": result.get("intent", "To be confirmed"),
                    "target": result.get("target", "To be confirmed"),
                    "analysis": result.get("analysis", response[:200]),
                }

            response_lower = response.lower()
            if "sql" in response_lower and "injection" in response_lower:
                attack_subtype = "SQL Injection Attack"
                if "union" in response_lower:
                    attack_subtype = "UNION-based SQL Injection"
                elif "drop" in response_lower or "delete" in response_lower:
                    attack_subtype = "Destructive SQL Injection"
            elif "xss" in response_lower or "cross-site" in response_lower:
                attack_subtype = "XSS Cross-site Scripting Attack"
            elif "command" in response_lower and "injection" in response_lower:
                attack_subtype = "Command Injection Attack"
            else:
                attack_subtype = "Unstructured model analysis"

            return {
                "attack_type": attack_type or "Unknown Attack",
                "attack_subtype": attack_subtype,
                "confidence": 0.55,
                "risk_score": 6.0,
                "intent": "To be confirmed",
                "target": "To be confirmed",
                "analysis": response[:300],
            }

        except Exception as e:
            print(f"[WARNING] LLM response parsing failed: {e}")
            return {
                "attack_type": attack_type or "Unknown Attack",
                "attack_subtype": "Parse Failed",
                "confidence": 0.3,
                "risk_score": 5.0,
                "intent": "Unknown",
                "target": "Unknown",
                "analysis": f"Failed to parse model response: {str(e)}",
                "from_fallback": True,
            }

    def get_fallback_result(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get fallback reasoning result"""
        return {
            "attack_type": alert_data.get('attack_type', 'Unknown Attack'),
            "attack_subtype": "Analysis Failed",
            "confidence": 0.3,
            "risk_score": 5.0,
            "intent": "Unknown",
            "target": "Unknown",
            "analysis": "LLM reasoning temporarily unavailable, using fallback analysis method",
            "llm_response": None,
            "from_fallback": True,
        }

class HybridReasoningEngine:
    """Hybrid reasoning engine"""

    def __init__(self):
        self.rule_engine = RuleEngine()
        self.llm_reasoner = LLMReasoner()
        self.fusion_weights = {
            'rule_weight': 0.2,
            'llm_weight': 0.8,
        }

    def analyze(self, alert_data: Dict[str, Any]) -> ReasoningResult:
        """Execute hybrid reasoning analysis"""
        try:
            # 1. Rule engine analysis
            rule_result = self.rule_engine.analyze(
                alert_data.get('payload', ''),
                alert_data.get('attack_type', 'unknown')
            )

            # 2. LLM reasoning analysis
            llm_result = self.llm_reasoner.analyze(alert_data)

            # 3. Result fusion
            fused_result = self._fuse_results(rule_result, llm_result)

            # 4. Generate reasoning path
            reasoning_path = self._generate_reasoning_path(rule_result, llm_result, fused_result)

            return ReasoningResult(
                attack_type=fused_result.get('attack_type', 'Unknown'),
                confidence=fused_result.get('confidence', 0.0),
                risk_score=fused_result.get('risk_score', 5.0),
                evidence=fused_result.get('evidence', []),
                analysis_details=fused_result.get('analysis', ''),
                reasoning_path=reasoning_path,
                matched_rules=rule_result.get('matched_rules', {}),
                llm_response=llm_result.get('llm_response')
            )

        except Exception as e:
            logger.error(f"Hybrid reasoning analysis failed: {e}")
            return ReasoningResult(
                attack_type="Analysis Failed",
                confidence=0.0,
                risk_score=5.0,
                evidence=[],
                analysis_details=f"Analysis process error: {str(e)}",
                reasoning_path=["Error"],
                matched_rules={}
            )

    def _fuse_results(self, rule_result: Dict[str, Any], llm_result: Dict[str, Any]) -> Dict[str, Any]:
        """Fuse rule engine and LLM reasoning results"""
        rule_conf = rule_result.get('confidence', 0.0)
        llm_conf = llm_result.get('confidence', 0.0)
        llm_is_fallback = bool(llm_result.get('from_fallback')) or not llm_result.get('llm_response')

        rule_weight = self.fusion_weights['rule_weight']
        llm_weight = self.fusion_weights['llm_weight']
        if llm_is_fallback:
            rule_weight, llm_weight = 0.8, 0.2

        if llm_is_fallback or rule_conf >= llm_conf:
            attack_type = rule_result.get('attack_type') or llm_result.get('attack_type', 'Unknown')
            attack_subtype = llm_result.get('attack_subtype', '') if not llm_is_fallback else ''
        else:
            attack_type = llm_result.get('attack_type', 'Unknown')
            attack_subtype = llm_result.get('attack_subtype', '')

        fused_confidence = max(0.0, min(1.0, rule_conf * rule_weight + llm_conf * llm_weight))

        rule_risk = rule_result.get('risk_score', 5.0)
        llm_risk = llm_result.get('risk_score', 5.0)
        fused_risk_score = rule_risk * rule_weight + llm_risk * llm_weight

        # Merge evidence
        evidence = []
        if rule_result.get('evidence'):
            evidence.extend([f"Rule Engine: {e}" for e in rule_result['evidence']])

        if llm_result.get('analysis'):
            evidence.append(f"LLM Analysis: {llm_result['analysis']}")

        # Generate comprehensive analysis
        analysis = f"Hybrid reasoning analysis results: Based on rule engine analysis ({rule_conf:.2f} confidence) and LLM reasoning ({llm_conf:.2f} confidence)"

        return {
            'attack_type': attack_type,
            'confidence': fused_confidence,
            'risk_score': fused_risk_score,
            'evidence': evidence,
            'analysis': analysis
        }

    def _generate_reasoning_path(self, rule_result: Dict[str, Any], llm_result: Dict[str, Any], fused_result: Dict[str, Any]) -> List[str]:
        """Generate reasoning path description"""
        path = []
        path.append("1. Receive alert data")
        path.append("2. Rule engine pattern matching analysis")

        if rule_result.get('matched_rules'):
            path.append(f"   - Matched rules: {list(rule_result['matched_rules'].keys())}")

        path.append("3. Large language model semantic reasoning analysis")

        if llm_result.get('attack_subtype'):
            path.append(f"   - LLM reasoning: {llm_result.get('attack_subtype', 'Unknown subtype')}")

        path.append("4. Result fusion and weight calculation")
        path.append(f"   - Rule engine weight: {self.fusion_weights['rule_weight']}")
        path.append(f"   - LLM reasoning weight: {self.fusion_weights['llm_weight']}")

        path.append("5. Generate final analysis results")
        path.append(f"   - Final attack type: {fused_result.get('attack_type', 'Unknown')}")
        path.append(f"   - Final confidence: {fused_result.get('confidence', 0):.3f}")

        return path

    def update_weights(self, rule_weight: float, llm_weight: float):
        """Dynamically adjust fusion weights"""
        total = rule_weight + llm_weight
        if total > 0:
            self.fusion_weights['rule_weight'] = rule_weight / total
            self.fusion_weights['llm_weight'] = llm_weight / total
            logger.info(f"Fusion weights updated: rule={self.fusion_weights['rule_weight']:.2f}, LLM={self.fusion_weights['llm_weight']:.2f}")

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get hybrid reasoning engine performance statistics"""
        return {
            'fusion_weights': self.fusion_weights,
            'rule_engine_available': True,
            'llm_reasoner_available': True,
            'engine_status': 'active'
        }

# Global hybrid reasoning engine instance
_hybrid_engine = None

def get_hybrid_reasoning_engine() -> HybridReasoningEngine:
    """Get hybrid reasoning engine instance"""
    global _hybrid_engine
    if _hybrid_engine is None:
        _hybrid_engine = HybridReasoningEngine()
    return _hybrid_engine

def analyze_alert(alert_data: Dict[str, Any]) -> ReasoningResult:
    """Analyze alert using hybrid reasoning engine"""
    engine = get_hybrid_reasoning_engine()
    return engine.analyze(alert_data)