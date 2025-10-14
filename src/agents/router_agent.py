#!/usr/bin/env python3
"""
路由智能体
负责分析告警类型并路由到相应的专家智能体
"""
import re
import time
from typing import Dict, List, Any, Tuple
from .base_agent import BaseAgent, AgentRole, AgentResult
from loguru import logger

class RouterAgent(BaseAgent):
    """路由智能体"""

    def __init__(self, agent_id: str = "router_001", config: Dict[str, Any] = None):
        super().__init__(agent_id, AgentRole.ROUTER, config)

        # 路由规则配置
        self.routing_rules = {
            'web_attack': {
                'keywords': [
                    'sql', 'xss', 'cross-site scripting', 'script', 'inject',
                    'union', 'select', 'drop', 'exec', 'eval', 'alert(',
                    'javascript:', 'onload', 'onerror', '<script', 'document.cookie',
                    '文件上传', 'webshell', '命令执行', '目录遍历', 'path traversal'
                ],
                'patterns': [
                    r'(?i)(union\s+select|select\s+.*\s+from)',
                    r'(?i)(<script|javascript:|on\w+=)',
                    r'(?i)(\.\./|\.\.\\|%2e%2e)',
                    r'(?i)(exec\s*\(|eval\s*\(|system\s*\()',
                    r'(?i)(wget|curl|nc\s+-|netcat)'
                ],
                'target_agent': 'web_attack_expert'
            },
            'vulnerability_attack': {
                'keywords': [
                    'cve', 'exploit', '漏洞', 'vulnerability', 'payload',
                    'shellcode', 'buffer overflow', 'rop', 'return-oriented',
                    '权限提升', 'privilege escalation', '0day', 'zero-day'
                ],
                'patterns': [
                    r'(?i)(cve-\d{4}-\d+)',
                    r'(?i)(exploit|vulnerability)',
                    r'(?i)(shellcode|payload)',
                    r'(?i)(buffer\s+overflow)',
                    r'(?i)(privilege\s+escalation)'
                ],
                'target_agent': 'vulnerability_expert'
            },
            'illegal_connection': {
                'keywords': [
                    'c2', 'command and control', '恶意域名', 'tor', 'proxy',
                    'tunnel', 'dns', '外联', 'illegal connection', 'botnet',
                    '僵尸网络', 'ddos', '反射攻击', 'amplification'
                ],
                'patterns': [
                    r'(?i)(c2\s+communication|command\s+and\s+control)',
                    r'(?i)(botnet|zombie)',
                    r'(?i)(ddos|dos\s+attack)',
                    r'(?i)(dns\s+tunnel)',
                    r'(?i)(tor\s+network|onion\s+routing)'
                ],
                'target_agent': 'illegal_connection_expert'
            }
        }

        # 编译正则表达式模式
        for category in self.routing_rules:
            patterns = self.routing_rules[category]['patterns']
            self.routing_rules[category]['compiled_patterns'] = [
                re.compile(pattern) for pattern in patterns
            ]

    def initialize(self) -> bool:
        """初始化路由智能体"""
        try:
            self.log_action("初始化", {"规则数量": len(self.routing_rules)})
            self.is_initialized = True
            logger.info(f"路由智能体 {self.agent_id} 初始化成功")
            return True
        except Exception as e:
            logger.error(f"路由智能体初始化失败: {e}")
            return False

    def process(self, input_data: Dict[str, Any]) -> AgentResult:
        """处理告警数据并路由"""
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
                    error_message="输入数据验证失败"
                )

            # 提取关键信息
            attack_type = input_data.get('attack_type', '')
            payload = input_data.get('payload', '')
            raw_log = input_data.get('raw_log', '')

            # 合并文本内容进行分析
            combined_text = f"{attack_type} {payload} {raw_log}".lower()

            # 计算每个类别的匹配分数
            route_scores = self._calculate_route_scores(combined_text)

            # 选择最佳路由
            best_route, confidence = self._select_best_route(route_scores)

            # 构建结果
            result = {
                'selected_route': best_route,
                'target_agent': self.routing_rules.get(best_route, {}).get('target_agent', 'general_expert'),
                'route_scores': route_scores,
                'analysis': self._generate_analysis(combined_text, route_scores)
            }

            processing_time = time.time() - start_time
            self.update_metrics(True, processing_time)

            self.log_action("路由决策", {
                "选择的路线": best_route,
                "置信度": confidence,
                "处理时间": processing_time
            })

            return AgentResult(
                agent_id=self.agent_id,
                agent_role=self.role,
                success=True,
                result=result,
                confidence=confidence,
                processing_time=processing_time
            )

        except Exception as e:
            processing_time = time.time() - start_time
            self.update_metrics(False, processing_time)
            logger.error(f"路由处理失败: {e}")

            return AgentResult(
                agent_id=self.agent_id,
                agent_role=self.role,
                success=False,
                result={},
                confidence=0.0,
                processing_time=processing_time,
                error_message=str(e)
            )

    def validate_input(self, input_data: Dict[str, Any]) -> bool:
        """验证输入数据"""
        # 基本必需字段
        basic_fields = ['attack_type', 'payload']
        for field in basic_fields:
            if field not in input_data:
                logger.warning(f"缺少基本必需字段: {field}")
                return False

        # 可选字段，如果不存在则使用默认值
        optional_fields = {
            'raw_log': '',
            'attack_stage': 'unknown',
            'threat_level': 'medium',
            'protocol': 'unknown',
            'source_ip': 'unknown',
            'target_ip': 'unknown'
        }

        for field, default_value in optional_fields.items():
            if field not in input_data:
                input_data[field] = default_value
                logger.info(f"设置默认值 {field}: {default_value}")

        return True

    def _calculate_route_scores(self, text: str) -> Dict[str, float]:
        """计算每个路由类别的匹配分数"""
        scores = {}

        for category, rules in self.routing_rules.items():
            score = 0.0

            # 关键词匹配分数 (权重: 0.6)
            keyword_score = 0
            for keyword in rules['keywords']:
                if keyword.lower() in text:
                    keyword_score += 1
            scores[f"{category}_keyword_score"] = keyword_score
            score += keyword_score * 0.6

            # 正则表达式匹配分数 (权重: 0.4)
            pattern_score = 0
            for pattern in rules['compiled_patterns']:
                if pattern.search(text):
                    pattern_score += 1
            scores[f"{category}_pattern_score"] = pattern_score
            score += pattern_score * 0.4

            scores[category] = score

        return scores

    def _select_best_route(self, route_scores: Dict[str, float]) -> Tuple[str, float]:
        """选择最佳路由"""
        main_categories = ['web_attack', 'vulnerability_attack', 'illegal_connection']

        best_route = 'general_expert'
        best_score = 0.0

        for category in main_categories:
            score = route_scores.get(category, 0.0)
            if score > best_score:
                best_score = score
                best_route = category

        # 如果没有明显的匹配，返回通用路由
        if best_score < 0.5:
            return 'general_expert', 0.3

        # 归一化置信度
        confidence = min(best_score / 3.0, 1.0)  # 假设最高分数为3.0
        return best_route, confidence

    def _generate_analysis(self, text: str, route_scores: Dict[str, float]) -> str:
        """生成路由分析说明"""
        analysis_parts = []

        # 找到匹配的关键词
        matched_keywords = []
        for category, rules in self.routing_rules.items():
            for keyword in rules['keywords']:
                if keyword.lower() in text:
                    matched_keywords.append(f"{keyword}({category})")

        if matched_keywords:
            analysis_parts.append(f"匹配关键词: {', '.join(matched_keywords[:5])}")

        # 找到匹配的模式
        matched_patterns = []
        for category, rules in self.routing_rules.items():
            for i, pattern in enumerate(rules['compiled_patterns']):
                if pattern.search(text):
                    matched_patterns.append(f"{category}_pattern_{i+1}")

        if matched_patterns:
            analysis_parts.append(f"匹配模式: {', '.join(matched_patterns[:3])}")

        # 分数分析
        score_analysis = []
        for category in ['web_attack', 'vulnerability_attack', 'illegal_connection']:
            score = route_scores.get(category, 0.0)
            if score > 0:
                score_analysis.append(f"{category}:{score:.2f}")

        if score_analysis:
            analysis_parts.append(f"路由分数: {', '.join(score_analysis)}")

        return "; ".join(analysis_parts) if analysis_parts else "未找到明显特征，使用通用分析"

    def get_routing_statistics(self) -> Dict[str, Any]:
        """获取路由统计信息"""
        return {
            'routing_rules_count': len(self.routing_rules),
            'supported_categories': list(self.routing_rules.keys()),
            'metrics': self.get_metrics()
        }