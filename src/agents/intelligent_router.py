#!/usr/bin/env python3
"""
智能路由分发算法
实现基于多层分析的路由决策机制
"""
import re
import time
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import numpy as np
from loguru import logger
from .base_agent import AgentRole, AgentResult

@dataclass
class RouteConfidence:
    """路由置信度"""
    target_agent: str
    confidence: float
    analysis: str
    feature_scores: Dict[str, float]

class IntelligentRouter:
    """智能路由分发器"""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.route_history = []
        self.performance_history = {}

        # 路由权重参数（文档中提到的α、β、γ参数）
        self.weights = {
            'keyword_match': 0.4,      # α - 关键词匹配权重
            'semantic_similarity': 0.3,  # β - 语义相似度权重
            'historical_accuracy': 0.3   # γ - 历史准确率权重
        }

        # 攻击类型关键词映射
        self.attack_keywords = {
            'web_attack': {
                'sql_injection': ['select', 'drop', 'insert', 'update', 'delete', 'union', 'where', 'or', 'and', "'", '"', ';', '--', '/*', '*/'],
                'xss': ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(', 'document.cookie', '<img', '<iframe', '<svg'],
                'command_injection': ['; ', '&& ', '|| ', '| ', '`', '$(', '${', 'eval', 'exec', 'system'],
                'webshell': ['<?php', '<%', '<jsp:useBean', 'eval(', 'assert(', 'system(', 'passthru('],
                'file_inclusion': ['../', '..\\', 'include', 'require', 'file://', 'http://', 'ftp://'],
                'ssrf': ['http://127.0.0.1', 'http://localhost', 'file:///', 'gopher://', 'dict://']
            },
            'vulnerability': {
                'cve': ['cve-', 'cvss', 'exploit', 'vulnerability', 'patch'],
                'config_error': ['misconfig', 'exposed', 'default', 'weak', 'password'],
                'privilege_escalation': ['sudo', 'root', 'admin', 'privilege', 'escalation']
            },
            'illegal_connection': {
                'c2': ['c2', 'command&control', 'botnet', 'beacon', 'heartbeat'],
                'malicious_ip': ['malicious', 'suspicious', 'blacklist', 'tor'],
                'abnormal_traffic': ['port scan', 'brute force', 'ddos', 'flood']
            }
        }

        # 专家智能体映射
        self.expert_mapping = {
            'web_attack': 'web_attack_expert',
            'vulnerability': 'vulnerability_expert',
            'illegal_connection': 'illegal_connection_expert'
        }

    def calculate_keyword_match_score(self, alert_data: Dict) -> Dict[str, float]:
        """计算关键词匹配分数"""
        scores = {}

        # 提取载荷内容
        payload = str(alert_data.get('payload', '')).lower()
        attack_type = str(alert_data.get('attack_type', '')).lower()
        raw_log = str(alert_data.get('raw_log', '')).lower()

        # 合并所有可分析的文本
        text_content = f"{payload} {attack_type} {raw_log}"

        for category, subcategories in self.attack_keywords.items():
            category_score = 0
            max_possible_score = 0

            for subcategory, keywords in subcategories.items():
                subcategory_score = 0
                keyword_count = len(keywords)

                for keyword in keywords:
                    if keyword.lower() in text_content:
                        subcategory_score += 1
                        # 高权重关键词加权
                        if keyword in ["'", '"', ';', '--', '<script', 'eval', 'system']:
                            subcategory_score += 0.5

                if keyword_count > 0:
                    category_score += subcategory_score / keyword_count
                    max_possible_score += 1

            if max_possible_score > 0:
                scores[category] = min(category_score / max_possible_score, 1.0)
            else:
                scores[category] = 0.0

        return scores

    def calculate_semantic_similarity(self, alert_data: Dict) -> Dict[str, float]:
        """计算语义相似度分数（简化版本）"""
        scores = {}

        # 基于攻击类型字段的语义匹配
        attack_type = str(alert_data.get('attack_type', '')).lower()
        protocol = str(alert_data.get('protocol', '')).lower()

        # 语义映射规则
        semantic_rules = {
            'web_attack': {
                'keywords': ['sql', 'xss', 'web', 'http', '注入', '跨站', '脚本'],
                'protocols': ['http', 'https', 'web']
            },
            'vulnerability': {
                'keywords': ['vulnerability', '漏洞', 'cve', 'cvss', 'patch', '补丁'],
                'protocols': ['smb', 'rdp', 'ssh']
            },
            'illegal_connection': {
                'keywords': ['connection', 'connection', 'illegal', 'malicious', 'c2', 'botnet'],
                'protocols': ['tcp', 'udp', 'icmp']
            }
        }

        for category, rules in semantic_rules.items():
            score = 0

            # 检查攻击类型语义
            for keyword in rules['keywords']:
                if keyword in attack_type:
                    score += 0.8

            # 检查协议匹配
            if protocol in rules['protocols']:
                score += 0.5

            # 检查威胁等级
            threat_level = str(alert_data.get('threat_level', '')).lower()
            if threat_level in ['高风险', 'critical', 'high']:
                score += 0.3
            elif threat_level in ['中风险', 'medium']:
                score += 0.2

            scores[category] = min(score, 1.0)

        return scores

    def calculate_historical_accuracy(self, category: str) -> float:
        """计算历史准确率"""
        if category not in self.performance_history:
            return 0.5  # 默认中性准确率

        history = self.performance_history[category]
        if not history:
            return 0.5

        # 计算最近10次的准确率
        recent_history = history[-10:]
        successful_analyses = sum(1 for result in recent_history if result.get('success', False))
        return successful_analyses / len(recent_history)

    def calculate_route_confidence(self, alert_data: Dict) -> List[RouteConfidence]:
        """计算路由置信度（实现文档中的公式）"""
        keyword_scores = self.calculate_keyword_match_score(alert_data)
        semantic_scores = self.calculate_semantic_similarity(alert_data)

        route_confs = []

        for category in self.attack_keywords.keys():
            # 获取各项分数
            keyword_score = keyword_scores.get(category, 0.0)
            semantic_score = semantic_scores.get(category, 0.0)
            historical_accuracy = self.calculate_historical_accuracy(category)

            # 应用文档中的公式：置信度 = α × 关键词匹配分数 + β × 语义相似度分数 + γ × 历史准确率
            final_confidence = (
                self.weights['keyword_match'] * keyword_score +
                self.weights['semantic_similarity'] * semantic_score +
                self.weights['historical_accuracy'] * historical_accuracy
            )

            # 创建分析说明
            analysis = f"关键词匹配: {keyword_score:.2f}, 语义相似度: {semantic_score:.2f}, 历史准确率: {historical_accuracy:.2f}"

            # 创建特征分数详情
            feature_scores = {
                'keyword_match': keyword_score,
                'semantic_similarity': semantic_score,
                'historical_accuracy': historical_accuracy
            }

            # 映射到具体的专家智能体
            target_agent = self.expert_mapping.get(category, 'web_attack_expert')

            route_conf = RouteConfidence(
                target_agent=target_agent,
                confidence=final_confidence,
                analysis=analysis,
                feature_scores=feature_scores
            )

            route_confs.append(route_conf)

        # 按置信度排序
        route_confs.sort(key=lambda x: x.confidence, reverse=True)

        return route_confs

    def select_optimal_route(self, alert_data: Dict, confidence_threshold: float = 0.2) -> Optional[RouteConfidence]:
        """选择最优路由"""
        route_confs = self.calculate_route_confidence(alert_data)

        if not route_confs:
            return None

        # 选择置信度最高的路由
        optimal_route = route_confs[0]

        # 检查置信度是否满足阈值
        if optimal_route.confidence < confidence_threshold:
            logger.warning(f"路由置信度低于阈值: {optimal_route.confidence:.3f} < {confidence_threshold}")
            return None

        # 记录路由历史
        self.route_history.append({
            'timestamp': time.time(),
            'alert_type': alert_data.get('attack_type', 'unknown'),
            'selected_route': optimal_route.target_agent,
            'confidence': optimal_route.confidence
        })

        return optimal_route

    def update_performance_feedback(self, agent: str, success: bool, accuracy: float = None):
        """更新性能反馈（自适应学习）"""
        category = None
        for cat, exp in self.expert_mapping.items():
            if exp == agent:
                category = cat
                break

        if category:
            if category not in self.performance_history:
                self.performance_history[category] = []

            feedback = {
                'timestamp': time.time(),
                'success': success,
                'accuracy': accuracy
            }

            self.performance_history[category].append(feedback)

            # 保持历史记录在合理范围内
            if len(self.performance_history[category]) > 100:
                self.performance_history[category] = self.performance_history[category][-50:]

    def get_route_statistics(self) -> Dict:
        """获取路由统计信息"""
        if not self.route_history:
            return {}

        # 计算路由使用统计
        route_counts = {}
        total_routes = len(self.route_history)

        for route in self.route_history:
            agent = route['selected_route']
            route_counts[agent] = route_counts.get(agent, 0) + 1

        # 计算平均置信度
        avg_confidence = sum(route['confidence'] for route in self.route_history) / total_routes

        # 计算各专家性能
        expert_performance = {}
        for category, history in self.performance_history.items():
            if history:
                success_rate = sum(1 for h in history if h['success']) / len(history)
                expert_performance[category] = {
                    'success_rate': success_rate,
                    'total_requests': len(history)
                }

        return {
            'total_routes': total_routes,
            'average_confidence': avg_confidence,
            'route_distribution': route_counts,
            'expert_performance': expert_performance
        }

class EnhancedRouterAgent:
    """增强的路由智能体"""

    def __init__(self, agent_id: str, config: Dict = None):
        self.agent_id = agent_id
        self.config = config or {}
        self.intelligent_router = IntelligentRouter(config)
        self.is_initialized = False

    def initialize(self) -> bool:
        """初始化路由智能体"""
        try:
            logger.info(f"智能路由智能体 {self.agent_id} 初始化成功")
            self.is_initialized = True
            return True
        except Exception as e:
            logger.error(f"智能路由智能体 {self.agent_id} 初始化失败: {e}")
            return False

    def route_alert(self, alert_data: Dict) -> AgentResult:
        """路由告警到合适的专家智能体"""
        if not self.is_initialized:
            return AgentResult(
                agent_id=self.agent_id,
                agent_role=AgentRole.ROUTER,
                success=False,
                result={},
                confidence=0.0,
                processing_time=0.0,
                error_message="路由智能体未初始化"
            )

        start_time = time.time()

        try:
            # 执行智能路由决策
            optimal_route = self.intelligent_router.select_optimal_route(alert_data)

            if optimal_route is None:
                return AgentResult(
                    agent_id=self.agent_id,
                    agent_role=AgentRole.ROUTER,
                    success=False,
                    result={},
                    confidence=0.0,
                    processing_time=time.time() - start_time,
                    error_message="无法确定合适的路由"
                )

            # 构建路由结果
            result = {
                'selected_route': optimal_route.target_agent,
                'confidence': optimal_route.confidence,
                'analysis': optimal_route.analysis,
                'feature_scores': optimal_route.feature_scores,
                'route_timestamp': time.time()
            }

            return AgentResult(
                agent_id=self.agent_id,
                agent_role=AgentRole.ROUTER,
                success=True,
                result=result,
                confidence=optimal_route.confidence,
                processing_time=time.time() - start_time
            )

        except Exception as e:
            logger.error(f"路由分析失败: {e}")
            return AgentResult(
                agent_id=self.agent_id,
                agent_role=AgentRole.ROUTER,
                success=False,
                result={},
                confidence=0.0,
                processing_time=time.time() - start_time,
                error_message=str(e)
            )

    def update_feedback(self, target_agent: str, success: bool, accuracy: float = None):
        """更新路由性能反馈"""
        self.intelligent_router.update_performance_feedback(target_agent, success, accuracy)

    def get_statistics(self) -> Dict:
        """获取路由统计信息"""
        return self.intelligent_router.get_route_statistics()