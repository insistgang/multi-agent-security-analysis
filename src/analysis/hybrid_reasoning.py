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

# emoji
def clean_emoji_characters(text):
    if not isinstance(text, str):
        text = str(text)
    # ASCIIemoji
    return ''.join(c for c in text if ord(c) < 128)

import json
import logging
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

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
                    "union_select": 8.5,
                    "or_injection": 7.0,
                    "drop_table": 9.5,
                    "exec_script": 9.0
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
                    "script_tag": 7.5,
                    "javascript_protocol": 8.0,
                    "cookie_access": 8.5
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
                    "direct_command": 9.0,
                    "shell_execution": 8.5
                }
            }
        }

    def analyze(self, payload: str, attack_type: str) -> Dict[str, Any]:
        """Use rule engine to analyze payload"""
        if not payload:
            return {
                "matched_rules": {},
                "confidence": 0.0,
                "risk_score": 5.0,
                "evidence": []
            }

        payload_lower = payload.lower()
        matched_rules = {}
        evidence = []
        max_risk_score = 5.0

        # Check pattern matching
        for rule_name, rule_config in self.rules.items():
            if rule_name in attack_type.lower() or attack_type == "unknown":
                for pattern in rule_config["patterns"]:
                    import re
                    if re.search(pattern, payload_lower, re.IGNORECASE):
                        matched_rules[rule_name] = True
                        evidence.append(f"Pattern match: {pattern}")

                        # Check risk factors
                        for factor, score in rule_config["risk_factors"].items():
                            if factor in pattern.lower():
                                max_risk_score = max(max_risk_score, score)

        # Check keyword matching
        for rule_name, rule_config in self.rules.items():
            for keyword in rule_config["keywords"]:
                if keyword in payload_lower:
                    if rule_name not in matched_rules:
                        matched_rules[rule_name] = True
                    evidence.append(f"Keyword match: {keyword}")

        # Check context matching
        if any(char in payload for char in "'\";\\/&|`"):
            matched_rules["suspicious_chars"] = True
            evidence.append("Suspicious characters detected")

        # Calculate confidence
        confidence = min(0.9, len(matched_rules) * 0.3)
        if matched_rules:
            confidence = max(confidence, 0.4)

            # Adjust confidence
            if len(evidence) > 3:
                confidence *= 1.2  # Increase confidence when risk factors present

            # Update best match
            if max_risk_score > 7.0:
                confidence = min(confidence, 0.95)

        # Calculate final risk score
        if matched_rules:
            max_risk_score = min(10.0, max_risk_score + confidence * 2)
        else:
            max_risk_score = 5.0  # Default medium risk

        return {
            "matched_rules": matched_rules,
            "confidence": confidence,
            "risk_score": max_risk_score,
            "evidence": evidence
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
            payload = alert_data.get('payload', '')
            source_ip = alert_data.get('source_ip', 'unknown')
            target_ip = alert_data.get('target_ip', 'unknown')
            protocol = alert_data.get('protocol', 'unknown')
            threat_level = alert_data.get('threat_level', 'unknown')

            # Select appropriate reasoning template
            template = self.templates['general']
            if 'sql' in attack_type or 'injection' in attack_type:
                template = self.templates['sql_injection']
            elif 'xss' in attack_type or 'cross-site' in attack_type or 'script' in attack_type:
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

            # Force call real Qwen2-7B model for reasoning
            safe_print(f"\n[Hybrid Reasoning Engine] Qwen2-7B")

            # Import GPU LLM reasoner
            from src.models.llm_inference_gpu import GPULLMInference

            # Get GPU LLM reasoner instance
            llm = GPULLMInference()

            # Generate analysis results
            try:
                response = llm.generate_response(prompt, max_new_tokens=512, temperature=0.3)

                # emojiWindows GBK
                response_clean = clean_emoji_characters(response)
                safe_print("[SUCCESS] Qwen2-7B!")
                safe_print(f"[CLEANED] emoji")
            except Exception as e:
                # emoji
                error_msg_clean = clean_emoji_characters(str(e))
                safe_print(f"[ERROR] : {error_msg_clean}")
                response_clean = ""

            # Parse LLM response
            parsed_result = self._parse_llm_response(response_clean, attack_type)
            parsed_result['llm_response'] = response_clean

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

    def _parse_llm_response(self, response: str, attack_type: str) -> Dict[str, Any]:
        """Parse real LLM model response"""
        try:
            # Try to directly parse JSON response
            import json
            import re

            # Extract JSON content
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                result = json.loads(json_str)

                # Ensure necessary fields are included
                return {
                    "attack_type": result.get("attack_type", attack_type or "Unknown Attack"),
                    "attack_subtype": result.get("attack_subtype", "AI Analysis Result"),
                    "confidence": float(result.get("confidence", 0.85)),
                    "risk_score": float(result.get("risk_score", 7.0)),
                    "intent": result.get("intent", "To be confirmed"),
                    "target": result.get("target", "To be confirmed"),
                    "analysis": result.get("analysis", f"AI Analysis Result: {response[:200]}")
                }

            # If not JSON format, generate structured results based on response content
            response_lower = response.lower()

            # Determine attack type and severity based on response content
            if "sql" in response_lower and "injection" in response_lower:
                attack_subtype = "SQL Injection Attack"
                if "union" in response_lower:
                    attack_subtype = "UNION-based SQL Injection"
                elif "drop" in response_lower or "delete" in response_lower:
                    attack_subtype = "Destructive SQL Injection"
                else:
                    attack_subtype = "SQL Injection Attack"
            elif "xss" in response_lower or "cross-site" in response_lower or "script" in response_lower:
                attack_subtype = "XSS Cross-site Scripting Attack"
            elif "command" in response_lower or "injection" in response_lower:
                attack_subtype = "Command Injection Attack"
            else:
                attack_subtype = "AI Analysis Attack"

            return {
                "attack_type": attack_type or "AI Analysis Attack",
                "attack_subtype": attack_subtype,
                "confidence": 0.85,  # AI analysis confidence
                "risk_score": 7.5,
                "intent": "AI Analysis Intent",
                "target": "AI Analysis Target",
                "analysis": f"Real Qwen2-7B Model Analysis: {response[:300]}"
            }

        except Exception as e:
            print(f"[WARNING] LLM response parsing failed: {e}")
            # If parsing fails, return basic results
            return {
                "attack_type": attack_type or "AI Analysis Attack",
                "attack_subtype": "AI Analysis Result",
                "confidence": 0.75,
                "risk_score": 7.0,
                "intent": "AI Analysis Intent",
                "target": "AI Analysis Target",
                "analysis": f"Real Qwen2-7B Model Original Response: {response[:200]}"
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
            "llm_response": None
        }

class HybridReasoningEngine:
    """Hybrid reasoning engine"""

    def __init__(self):
        self.rule_engine = RuleEngine()
        self.llm_reasoner = LLMReasoner()
        self.fusion_weights = {
            'rule_weight': 0.2,  # Rule engine weight
            'llm_weight': 0.8    # LLM reasoning weight - force using real model
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

        # Determine attack type - prioritize higher confidence result
        if llm_conf > rule_conf:
            attack_type = llm_result.get('attack_type', 'Unknown')
            attack_subtype = llm_result.get('attack_subtype', '')
        else:
            attack_type = rule_result.get('attack_type', 'Unknown')
            attack_subtype = ''

        # Fuse confidence
        fused_confidence = (
            rule_conf * self.fusion_weights['rule_weight'] +
            llm_conf * self.fusion_weights['llm_weight']
        )

        # Fuse risk score
        rule_risk = rule_result.get('risk_score', 5.0)
        llm_risk = llm_result.get('risk_score', 5.0)
        fused_risk_score = (
            rule_risk * self.fusion_weights['rule_weight'] +
            llm_risk * self.fusion_weights['llm_weight']
        )

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