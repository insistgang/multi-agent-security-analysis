#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
专家智能体模块 - 负责特定领域的安全威胁分析
"""

# 设置UTF-8编码
import sys
import os
if sys.platform == 'win32':
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    os.environ['PYTHONLEGACYWINDOWSSTDIO'] = '0'

# 安全打印函数，处理Windows GBK编码问题
def safe_print(*args, **kwargs):
    """Windows GBK编码安全打印函数"""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        cleaned_args = []
        for arg in args:
            if isinstance(arg, str):
                # 只保留ASCII字符，避免GBK编码错误
                cleaned = ''.join(c for c in arg if ord(c) < 128)
                cleaned_args.append(cleaned)
            else:
                cleaned_args.append(str(arg))
        print(*cleaned_args, **kwargs)

# 清理emoji字符，避免Windows GBK编码错误
def clean_emoji_characters(text):
    """清理emoji字符"""
    if not isinstance(text, str):
        text = str(text)
    # 只保留ASCII字符和基本中文字符
    return ''.join(c for c in text if ord(c) < 128)

import time
import torch
from typing import Dict, List, Any, Optional
from .base_agent import BaseAgent, AgentRole, AgentResult
from src.analysis.hybrid_reasoning import HybridReasoningEngine, ReasoningResult
from src.rag.enhanced_rag import EnhancedRAGAnalyzer

# 简单日志器，处理编码问题
class SimpleLogger:
    """Windows编码安全的简单日志器"""

    @staticmethod
    def info(msg, *args, **kwargs):
        try:
            safe_print(f"[INFO] {msg % args if args else msg}")
        except:
            safe_print("[INFO] " + str(msg))

    @staticmethod
    def warning(msg, *args, **kwargs):
        try:
            safe_print(f"[WARNING] {msg % args if args else msg}")
        except:
            safe_print("[WARNING] " + str(msg))

    @staticmethod
    def error(msg, *args, **kwargs):
        try:
            safe_print(f"[ERROR] {msg % args if args else msg}")
        except:
            safe_print("[ERROR] " + str(msg))

logger = SimpleLogger()

class ExpertAgent(BaseAgent):
    """专家智能体，负责特定领域的威胁分析"""

    def __init__(self, agent_id: str, role: AgentRole, config: Dict[str, Any] = None):
        super().__init__(agent_id, role, config)
        self.model = None
        self.tokenizer = None
        self.expert_prompts = {}
        self.device = "cuda" if torch.cuda.is_available() else "cpu"

        # 混合推理引擎
        self.hybrid_reasoning_engine = None
        self.rag_analyzer = None
        self.enable_rag = config.get('enable_rag', True) if config else True

    def initialize(self) -> bool:
        """初始化专家智能体"""
        try:
            # 初始化混合推理引擎
            self.hybrid_reasoning_engine = HybridReasoningEngine()

            # 初始化RAG增强分析器
            if self.enable_rag:
                self.rag_analyzer = EnhancedRAGAnalyzer(self.config or {})

            # 加载模型（延迟加载）
            # self._load_model()  # 注释掉，避免启动时加载大模型
            self._setup_prompts()
            self.is_initialized = True

            self.log_action("初始化完成", {
                "设备": self.device,
                "角色": self.role.value,
                "模型": "Qwen2-7B",
                "RAG": "启用" if self.enable_rag else "禁用"
            })

            logger.info(f"专家智能体 {self.agent_id} 初始化成功")
            return True

        except Exception as e:
            logger.error(f"专家智能体初始化失败: {e}")
            return False

    def _load_model(self):
        """加载大语言模型（延迟加载）"""
        # 模型将在首次使用时加载
        # 避免启动时间过长
        pass

    def _setup_prompts(self):
        """设置专家提示词模板"""
        self.expert_prompts = {
            'web_attack': """
As a Web security expert, please analyze the following network attack:

Attack Type: {attack_type}
Attack Stage: {attack_stage}
Threat Level: {threat_level}
Protocol: {protocol}
Payload: {payload}

Please provide:
1. Attack technique analysis
2. Threat assessment
3. Defense recommendations
4. False positive probability

Return in JSON format:
{{
    "attack_technique": "Attack technique name",
    "threat_assessment": "Threat assessment",
    "defense_suggestions": ["Defense suggestion 1", "Defense suggestion 2"],
    "false_positive_probability": 0.1,
    "risk_score": 8.5,
    "detailed_analysis": "Detailed analysis"
}}
""",

            'vulnerability': """
As a vulnerability exploitation expert, please analyze the following vulnerability attack:

Attack Type: {attack_type}
Attack Stage: {attack_stage}
Threat Level: {threat_level}
Protocol: {protocol}
Payload: {payload}

Please provide:
1. CVE number
2. Exploitation technique
3. Impact assessment
4. Remediation recommendations

Return in JSON format:
{{
    "vulnerability_id": "CVE number",
    "exploit_technique": "Exploitation technique",
    "impact_assessment": "Impact assessment",
    "remediation": ["Remediation 1", "Remediation 2"],
    "false_positive_probability": 0.1,
    "risk_score": 7.8,
    "detailed_analysis": "Detailed analysis"
}}
""",

            'illegal_connection': """
As a network connection expert, please analyze the following suspicious connection:

Attack Type: {attack_type}
Attack Stage: {attack_stage}
Threat Level: {threat_level}
Source IP: {source_ip}
Target IP: {target_ip}
Protocol: {protocol}
Payload: {payload}

Please provide:
1. Connection type
2. Malware family
3. Threat intelligence
4. Response recommendations

Return in JSON format:
{{
    "connection_type": "Connection type",
    "malware_family": "Malware family",
    "threat_intelligence": "Threat intelligence",
    "response_recommendations": ["Response 1", "Response 2"],
    "false_positive_probability": 0.1,
    "risk_score": 9.2,
    "detailed_analysis": "Detailed analysis"
}}
"""
        }

    def process(self, input_data: Dict[str, Any]) -> AgentResult:
        """Process security alert and return analysis result"""
        start_time = time.time()

        try:
            if not self.validate_input(input_data):
                return AgentResult(
                    agent_id=self.agent_id,
                    agent_role=self.role,
                    success=False,
                    result={},
                    confidence=0.0,
                    processing_time=time.time() - start_time,
                    error_message="Input validation failed"
                )

            # Start analysis
            safe_print("\n" + "="*70)
            safe_print("[EXPERT] Starting security analysis...")
            safe_print("="*70)

            # Generate analysis prompt
            prompt = self._generate_prompt(input_data)

            # Call model
            try:
                model_analysis = self._call_model(prompt)

                # Clean emoji characters
                model_analysis_clean = clean_emoji_characters(model_analysis)

                safe_print("[EXPERT] Model analysis result:")
                safe_print(f"[EXPERT] Analysis: {model_analysis_clean[:200]}...")
                safe_print("="*70)
            except Exception as e:
                # Clean emoji in error message
                error_msg_clean = clean_emoji_characters(str(e))
                safe_print(f"[ERROR] Model error: {error_msg_clean}")
                safe_print("[FALLBACK] Using rule-based simulation")
                model_analysis_clean = self._generate_smart_simulation(prompt)
                safe_print("="*70)

            # Hybrid reasoning
            reasoning_result = self.hybrid_reasoning_engine.analyze(input_data)

            # Convert reasoning result
            parsed_result = self._convert_reasoning_result(reasoning_result)

            # RAG enhancement
            rag_enhancement = None
            if self.enable_rag and self.rag_analyzer:
                try:
                    base_analysis = {
                        'attack_type': reasoning_result.attack_type,
                        'confidence': reasoning_result.confidence,
                        'risk_score': reasoning_result.risk_score
                    }
                    rag_enhancement = self.rag_analyzer.enhance_analysis(input_data, base_analysis)
                except Exception as e:
                    logger.warning(f"RAG error: {e}")
                    rag_enhancement = {
                        'success': False,
                        'error_message': str(e)
                    }

            processing_time = time.time() - start_time
            self.update_metrics(True, processing_time)

            # Clean emoji in attack type
            attack_type_clean = clean_emoji_characters(str(input_data.get('attack_type', '')))

            self.log_action("Analysis completed", {
                "attack_type": attack_type_clean,
                "risk_score": parsed_result.get('risk_score', 0),
                "processing_time": processing_time
            })

            return AgentResult(
                agent_id=self.agent_id,
                agent_role=self.role,
                success=True,
                result=parsed_result,
                confidence=self._calculate_confidence(parsed_result),
                processing_time=processing_time
            )

        except Exception as e:
            processing_time = time.time() - start_time
            self.update_metrics(False, processing_time)
            logger.error(f"Expert agent error: {e}")

            return AgentResult(
                agent_id=self.agent_id,
                agent_role=self.role,
                success=False,
                result={},
                confidence=0.0,
                processing_time=processing_time,
                error_message=str(e)
            )

    def _generate_prompt(self, input_data: Dict[str, Any]) -> str:
        """Generate analysis prompt"""
        # Select template based on role
        if self.role == AgentRole.WEB_ATTACK_EXPERT:
            template = self.expert_prompts['web_attack']
        elif self.role == AgentRole.VULNERABILITY_EXPERT:
            template = self.expert_prompts['vulnerability']
        elif self.role == AgentRole.ILLEGAL_CONNECTION_EXPERT:
            template = self.expert_prompts['illegal_connection']
        else:
            template = self.expert_prompts['web_attack']  # Default to web

        return template.format(**input_data)

    def _call_model(self, prompt: str) -> str:
        """Call Qwen2-7B model for analysis"""
        safe_print(f"\n[EXPERT] Calling Qwen2-7B model...")

        # Try GPU LLM inference first
        try:
            from src.models.llm_inference_gpu import GPULLMInference
            # GPU LLM
            llm_inference = GPULLMInference()
        except Exception as e:
            safe_print(f"[ERROR] GPU LLM failed: {e}")
            from src.models.llm_inference import get_llm_inference
            llm_inference = get_llm_inference()

        # Generate response
        try:
            response = llm_inference.generate_response(
                prompt,
                max_new_tokens=256,
                temperature=0.3
            )
            # Clean emoji
            response_clean = clean_emoji_characters(response)
            safe_print("[EXPERT] Real model inference completed")
            return response_clean
        except Exception as e:
            # Clean emoji in error
            error_msg_clean = clean_emoji_characters(str(e))
            safe_print(f"[ERROR] Model error: {error_msg_clean}")
            safe_print("[FALLBACK] Using rule-based simulation")
            return self._generate_smart_simulation(prompt)

    def _generate_smart_simulation(self, prompt: str) -> str:
        """Generate smart rule-based simulation"""
        import json

        # Extract payload
        payload = ""
        if ":" in prompt:
            payload = prompt.split(":")[1].split("\n")[0].strip()
        elif "payload:" in prompt.lower():
            payload = prompt.split("payload:")[1].split("\n")[0].strip()

        # Attack analysis
        attack_type = ""
        risk_score = 5.0
        attack_technique = ""
        false_positive_prob = 0.1

        payload_lower = payload.lower()

        # SQL injection
        if any(keyword in payload_lower for keyword in ["'", "or", "union", "select", "drop", "insert", "delete", "--", "/*", "*/"]):
            attack_type = "SQL Injection"
            risk_score = 8.5
            if "union" in payload_lower and "select" in payload_lower:
                attack_technique = "UNION-based SQL Injection"
                risk_score = 9.0
            elif "drop" in payload_lower or "delete" in payload_lower:
                attack_technique = "SQL Injection via DROP/DELETE"
                risk_score = 9.5
            else:
                attack_technique = "SQL Injection"
                risk_score = 8.0
            false_positive_prob = 0.05

        # XSS
        elif any(keyword in payload_lower for keyword in ["<script", "javascript:", "onerror=", "onload=", "alert(", "document.cookie"]):
            attack_type = "XSS"
            risk_score = 7.5
            if "<script" in payload_lower:
                attack_technique = "Reflected XSS"
                risk_score = 8.5
            elif "javascript:" in payload_lower:
                attack_technique = "DOM-based XSS"
                risk_score = 7.0
            else:
                attack_technique = "Stored XSS"
                risk_score = 6.5
            false_positive_prob = 0.08

        # Command injection
        elif any(keyword in payload_lower for keyword in [";", "|", "&", "&&", "||", "`", "$(", "wget", "curl", "nc", "bash", "sh"]):
            attack_type = "Command Injection"
            risk_score = 9.0
            if "wget" in payload_lower or "curl" in payload_lower:
                attack_technique = "Command Injection via download"
                risk_score = 9.5
            else:
                attack_technique = "Shell Command Injection"
                risk_score = 8.5
            false_positive_prob = 0.03

        # Directory traversal
        elif any(keyword in payload_lower for keyword in ["../", "..\\", "%2e%2e", "etc/passwd", "windows/win.ini", "boot.ini"]):
            attack_type = "Directory Traversal"
            risk_score = 6.5
            if "etc/passwd" in payload_lower:
                attack_technique = "Linux Path Traversal"
                risk_score = 7.5
            elif "windows" in payload_lower or "win.ini" in payload_lower:
                attack_technique = "Windows Path Traversal"
                risk_score = 7.0
            else:
                attack_technique = "Path Traversal"
                risk_score = 6.0
            false_positive_prob = 0.15

        # C2 communication
        elif any(keyword in payload_lower for keyword in ["http://", "https://", "ftp://", "powershell", "cmd.exe", "bash -c"]):
            attack_type = "C2 Communication"
            risk_score = 8.0
            if "powershell" in payload_lower:
                attack_technique = "PowerShell C2"
                risk_score = 8.8
            elif "cmd.exe" in payload_lower:
                attack_technique = "Windows CMD C2"
                risk_score = 8.5
            else:
                attack_technique = "HTTP/HTTPS C2"
                risk_score = 7.5
            false_positive_prob = 0.12

        # Default
        else:
            # Generic analysis
            if len(payload) > 100:
                risk_score = 6.0
                attack_technique = "Suspicious Activity"
            elif len(payload) > 20:
                risk_score = 5.0
                attack_technique = "Potentially Suspicious"
            else:
                risk_score = 4.0
                attack_technique = "Unknown"

            false_positive_prob = 0.20

        # Generate result
        result = {
            "attack_technique": attack_technique,
            "risk_score": min(10.0, max(1.0, risk_score)),  # Clamp between 1-10
            "false_positive_probability": min(0.5, max(0.01, false_positive_prob)),  # Clamp between 1%-50%
            "threat_assessment": f"{attack_type} {'Critical' if risk_score >= 7 else 'High' if risk_score >= 4 else 'Medium'}",
            "defense_suggestions": self._generate_defense_suggestions(attack_type, attack_technique),
            "detailed_analysis": f"Detected {attack_type} using {attack_technique} technique. Payload: {payload[:100]}{'...' if len(payload) > 100 else ''}"
        }

        return json.dumps(result, ensure_ascii=False, indent=2)

    def _generate_defense_suggestions(self, attack_type: str, attack_technique: str) -> list:
        """Generate defense suggestions"""
        suggestions = []

        if "SQL" in attack_type:
            suggestions = [
                "Deploy Web Application Firewall (WAF) with SQL injection rules",
                "Implement input validation and parameterized queries",
                "Use prepared statements for database operations",
                "Apply least privilege principle to database accounts",
                "Regular security testing and code review"
            ]
        elif "XSS" in attack_type:
            suggestions = [
                "Implement HTML output encoding",
                "Use Content Security Policy (CSP) headers",
                "Set HttpOnly and Secure flags on cookies",
                "Input sanitization and validation",
                "Use modern JavaScript frameworks with built-in XSS protection"
            ]
        elif "Command" in attack_type:
            suggestions = [
                "Block special characters in input fields",
                "Implement allow-list for valid inputs",
                "Use parameterized commands instead of string concatenation",
                "Run applications with minimal privileges",
                "Monitor and audit command executions"
            ]
        elif "Directory" in attack_type:
            suggestions = [
                "Validate and sanitize file paths",
                "Implement chroot jail for file operations",
                "Use allow-list for permitted directories",
                "Avoid using user input directly in file paths",
                "Regular security scanning for path traversal vulnerabilities"
            ]
        elif "C2" in attack_type:
            suggestions = [
                "Block known malicious IP addresses",
                "Implement egress filtering",
                "Monitor network traffic for anomalies",
                "Use DNS filtering and monitoring",
                "Deploy endpoint detection and response (EDR) solutions"
            ]
        else:
            suggestions = [
                "Implement comprehensive logging",
                "Deploy Intrusion Detection System (IDS)",
                "Regular security monitoring",
                "Security awareness training",
                "Incident response planning"
            ]

        return suggestions

    def _parse_analysis_result(self, model_output: str) -> Dict[str, Any]:
        """Parse model analysis result"""
        try:
            # Try to parse JSON
            import json
            result = json.loads(model_output)

            # Validate required fields
            required_fields = ['risk_score', 'false_positive_probability']
            for field in required_fields:
                if field not in result:
                    result[field] = 0.0

            return result

        except json.JSONDecodeError:
            # Fallback for non-JSON output
            return {
                'attack_technique': 'Unknown',
                'risk_score': 5.0,
                'false_positive_probability': 0.5,
                'detailed_analysis': model_output
            }

    def _calculate_confidence(self, result: Dict[str, Any]) -> float:
        """Calculate analysis confidence"""
        # Simple confidence calculation
        false_positive_prob = result.get('false_positive_probability', 0.5)
        risk_score = result.get('risk_score', 5.0)

        # Confidence = (1 - false_positive) * (risk_score / 10)
        confidence = (1 - false_positive_prob) * (risk_score / 10)
        return max(0.0, min(1.0, confidence))

    def validate_input(self, input_data: Dict[str, Any]) -> bool:
        """Validate input data"""
        # Check required fields
        basic_fields = ['attack_type', 'payload']
        for field in basic_fields:
            if field not in input_data:
                logger.warning(f"Missing required field: {field}")
                return False

        # Set default values for optional fields
        optional_fields = {
            'attack_stage': 'unknown',
            'threat_level': 'medium',
            'protocol': 'unknown',
            'source_ip': 'unknown',
            'target_ip': 'unknown',
            'raw_log': ''
        }

        for field, default_value in optional_fields.items():
            if field not in input_data:
                input_data[field] = default_value
                logger.info(f"Setting default value for {field}: {default_value}")

        return True

    def get_expertise_info(self) -> Dict[str, Any]:
        """Get expertise information"""
        return {
            'agent_id': self.agent_id,
            'role': self.role.value,
            'expertise_areas': self._get_expertise_areas(),
            'metrics': self.get_metrics()
        }

    def _get_expertise_areas(self) -> List[str]:
        """Get expertise areas"""
        expertise_map = {
            AgentRole.WEB_ATTACK_EXPERT: [
                'SQL Injection', 'XSS', 'CSRF', 'File Upload',
                'Webshell', 'Directory Traversal', 'XXE'
            ],
            AgentRole.VULNERABILITY_EXPERT: [
                'CVE', '0day', 'Buffer Overflow',
                'Race Condition', 'ROP', 'Memory Corruption'
            ],
            AgentRole.ILLEGAL_CONNECTION_EXPERT: [
                'C2', 'Botnet', 'DDoS', 'Port Scanning',
                'DNS Tunneling', 'Tunneling', 'Pivoting'
            ]
        }
        return expertise_map.get(self.role, ['General'])

    def _convert_reasoning_result(self, reasoning_result: ReasoningResult) -> Dict[str, Any]:
        """Convert reasoning result to dictionary"""
        result = {
            'attack_type': reasoning_result.attack_type,
            'risk_score': reasoning_result.risk_score,
            'detailed_analysis': reasoning_result.analysis_details,
            'evidence': reasoning_result.evidence,
            'reasoning_path': reasoning_result.reasoning_path,
            'llm_response': reasoning_result.llm_response,
            'matched_rules': reasoning_result.matched_rules,
            'confidence': reasoning_result.confidence
        }

        # Add role-specific fields
        if self.role == AgentRole.WEB_ATTACK_EXPERT:
            result.update({
                'attack_technique': f"Web: {reasoning_result.attack_type}",
                'threat_assessment': self._assess_web_threat(reasoning_result),
                'defense_suggestions': self._generate_web_defense_suggestions(reasoning_result),
                'false_positive_probability': max(0.1, 1.0 - reasoning_result.confidence)
            })
        elif self.role == AgentRole.VULNERABILITY_EXPERT:
            result.update({
                'vulnerability_id': self._estimate_vulnerability_id(reasoning_result),
                'exploit_technique': f"Exploit: {reasoning_result.attack_type}",
                'impact_assessment': self._assess_impact(reasoning_result),
                'remediation': self._generate_remediation_suggestions(reasoning_result),
                'false_positive_probability': max(0.05, 1.0 - reasoning_result.confidence)
            })
        elif self.role == AgentRole.ILLEGAL_CONNECTION_EXPERT:
            result.update({
                'connection_type': reasoning_result.attack_type,
                'malicious_behavior': self._analyze_malicious_behavior(reasoning_result),
                'threat_level': self._assess_threat_level(reasoning_result),
                'mitigation_steps': self._generate_mitigation_steps(reasoning_result),
                'false_positive_probability': max(0.15, 1.0 - reasoning_result.confidence)
            })

        return result

    def _assess_web_threat(self, reasoning_result: ReasoningResult) -> str:
        """Assess web threat level"""
        if reasoning_result.risk_score >= 9.0:
            return "Critical threat"
        elif reasoning_result.risk_score >= 7.0:
            return "High threat"
        elif reasoning_result.risk_score >= 5.0:
            return "Medium threat"
        else:
            return "Low threat"

    def _generate_web_defense_suggestions(self, reasoning_result: ReasoningResult) -> List[str]:
        """Generate web defense suggestions"""
        suggestions = []
        attack_type = reasoning_result.attack_type.lower()

        if 'sql' in attack_type or 'injection' in attack_type:
            suggestions.extend([
                "Use parameterized queries",
                "Implement input validation",
                "Deploy WAF",
                "Least privilege database access"
            ])
        elif 'xss' in attack_type or 'script' in attack_type:
            suggestions.extend([
                "Output encoding",
                "Content Security Policy (CSP)",
                "Input sanitization",
                "Disable JavaScript eval()"
            ])
        elif 'upload' in attack_type:
            suggestions.extend([
                "File type validation",
                "Content scanning",
                "Secure file storage",
                "Execute permissions control"
            ])

        # Add general suggestions
        suggestions.extend([
            "Regular security audits",
            "Security testing",
            "Employee training"
        ])

        return suggestions[:6]  # Limit to 6 suggestions

    def _estimate_vulnerability_id(self, reasoning_result: ReasoningResult) -> str:
        """Estimate CVE ID"""
        attack_type = reasoning_result.attack_type.lower()

        if 'sql' in attack_type:
            return "SQLi: CVE-2023-XXXX"
        elif 'xss' in attack_type:
            return "XSS: CVE-2024-XXXX"
        elif 'overflow' in attack_type:
            return "Buffer Overflow: CVE-2022-XXXX"
        else:
            return "Unknown CVE"

    def _assess_impact(self, reasoning_result: ReasoningResult) -> str:
        """Assess vulnerability impact"""
        if reasoning_result.risk_score >= 8.0:
            return "Critical impact"
        elif reasoning_result.risk_score >= 6.0:
            return "High impact"
        elif reasoning_result.risk_score >= 4.0:
            return "Medium impact"
        else:
            return "Low impact"

    def _generate_remediation_suggestions(self, reasoning_result: ReasoningResult) -> List[str]:
        """Generate remediation suggestions"""
        return [
            "Apply security patches",
            "Update to latest version",
            "Implement temporary mitigations",
            "Monitor for exploitation attempts",
            "Plan system upgrades"
        ]

    def _analyze_malicious_behavior(self, reasoning_result: ReasoningResult) -> str:
        """Analyze malicious behavior"""
        return f"Detected {reasoning_result.attack_type} activity"

    def _assess_threat_level(self, reasoning_result: ReasoningResult) -> str:
        """Assess threat level"""
        if reasoning_result.risk_score >= 8.0:
            return "Critical"
        elif reasoning_result.risk_score >= 5.0:
            return "High"
        else:
            return "Medium"

    def _generate_mitigation_steps(self, reasoning_result: ReasoningResult) -> List[str]:
        """Generate mitigation steps"""
        return [
            "Block malicious IPs",
            "Update firewall rules",
            "Enable IDS/IPS alerts",
            "Monitor network traffic",
            "Incident response activation"
        ]

    def _clean_emoji_characters(self, text: str) -> str:
        """Clean emoji characters for Windows GBK compatibility"""
        import re

        # Emoji pattern
        emoji_pattern = re.compile(
            "["
            "\U0001F600-\U0001F64F"  # Emoticons
            "\U0001F300-\U0001F5FF"  # Symbols & Pictographs
            "\U0001F680-\U0001F6FF"  # Transport & Map Symbols
            "\U0001F700-\U0001F77F"  # Alchemical Symbols
            "\U0001F780-\U0001F7FF"  # Geometric Shapes Extended
            "\U0001F800-\U0001F8FF"  # Supplemental Arrows-C
            "\U0001F900-\U0001F9FF"  # Supplemental Symbols and Pictographs
            "\U0001FA00-\U0001FA6F"  # Chess Symbols
            "\U0001FA70-\U0001FAFF"  # Symbols and Pictographs Extended-A
            "\U00002702-\U000027B0"  # Dingbats
            "\U000024C2-\U0001F251"  # Enclosed characters
            "]+",
            flags=re.UNICODE
        )

        # Remove emojis
        cleaned_text = emoji_pattern.sub('', text)

        return cleaned_text