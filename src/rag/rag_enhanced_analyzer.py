#!/usr/bin/env python3
"""
RAG增强分析器
结合威胁情报进行增强分析
"""
import time
from typing import Dict, List, Any, Optional
from .threat_intel_retriever import ThreatIntelRetriever
from loguru import logger

class RAGEnhancedAnalyzer:
    """RAG增强分析器"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.threat_retriever = None
        self.is_initialized = False

        # 分析配置
        self.max_intel_results = self.config.get('max_intel_results', 5)
        self.similarity_threshold = self.config.get('similarity_threshold', 0.3)
        self.enable_context_enhancement = self.config.get('enable_context_enhancement', True)

    def initialize(self) -> bool:
        """初始化RAG增强分析器"""
        try:
            logger.info("初始化RAG增强分析器...")

            # 初始化威胁情报检索器
            self.threat_retriever = ThreatIntelRetriever(self.config.get('retriever', {}))
            if not self.threat_retriever.initialize():
                logger.error("威胁情报检索器初始化失败")
                return False

            self.is_initialized = True
            logger.info("RAG增强分析器初始化完成")
            return True

        except Exception as e:
            logger.error(f"RAG增强分析器初始化失败: {e}")
            return False

    def enhance_analysis(self, alert_data: Dict[str, Any],
                        base_analysis: Dict[str, Any] = None) -> Dict[str, Any]:
        """使用RAG增强分析"""
        try:
            if not self.is_initialized:
                raise RuntimeError("RAG分析器未初始化")

            start_time = time.time()

            # 第一步：构建查询
            query = self._build_enhanced_query(alert_data)

            # 第二步：检索相关威胁情报
            threat_intel = self._retrieve_threat_intel(query, alert_data)

            # 第三步：分析威胁情报关联性
            intel_analysis = self._analyze_threat_intel_relevance(threat_intel, alert_data)

            # 第四步：生成增强分析结果
            enhanced_result = self._generate_enhanced_result(
                alert_data, base_analysis, threat_intel, intel_analysis
            )

            processing_time = time.time() - start_time

            logger.info(f"RAG增强分析完成，耗时: {processing_time:.2f}秒，"
                       f"检索到 {len(threat_intel)} 条威胁情报")

            return {
                'success': True,
                'enhanced_analysis': enhanced_result,
                'threat_intel': threat_intel,
                'intel_analysis': intel_analysis,
                'processing_time': processing_time,
                'query_used': query
            }

        except Exception as e:
            logger.error(f"RAG增强分析失败: {e}")
            return {
                'success': False,
                'error_message': str(e),
                'threat_intel': [],
                'intel_analysis': {}
            }

    def _build_enhanced_query(self, alert_data: Dict[str, Any]) -> str:
        """构建增强查询"""
        query_parts = []

        # 添加攻击类型
        attack_type = alert_data.get('attack_type', '')
        if attack_type:
            query_parts.append(attack_type)

        # 添加载荷内容的关键部分
        payload = alert_data.get('payload', '')
        if payload:
            # 提取载荷中的关键词
            keywords = self._extract_payload_keywords(payload)
            if keywords:
                query_parts.extend(keywords)

        # 添加IP地址信息
        source_ip = alert_data.get('source_ip', '')
        target_ip = alert_data.get('target_ip', '')
        if source_ip and source_ip != 'NaN':
            query_parts.append(source_ip)
        if target_ip and target_ip != 'NaN':
            query_parts.append(target_ip)

        # 添加协议信息
        protocol = alert_data.get('protocol', '')
        if protocol and protocol.lower() != 'unknown':
            query_parts.append(protocol)

        # 组合查询
        return " ".join(query_parts) if query_parts else "网络安全威胁"

    def _extract_payload_keywords(self, payload: str) -> List[str]:
        """从载荷中提取关键词"""
        import re

        keywords = []

        # 定义关键模式
        patterns = {
            'sql_injection': r'(?i)(union|select|insert|update|drop|exec|script)',
            'xss': r'(?i)(<script|javascript:|onload=|alert\()',
            'path_traversal': r'(?i)(\.\./|%2e%2e%2f)',
            'command_injection': r'(?i)(;|\||&|`|\$\()',
            'cve': r'(?i)(cve-\d{4}-\d+)',
            'ip_addresses': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'domains': r'(?i)([a-z0-9.-]+\.[a-z]{2,})',
            'file_extensions': r'(?i)(\.php|\.asp|\.jsp|\.cgi|\.sh|\.bat|\.exe)',
        }

        for category, pattern in patterns.items():
            matches = re.findall(pattern, payload)
            if matches:
                # 取前3个匹配的关键词
                keywords.extend(matches[:3])

        # 去重并限制数量
        return list(set(keywords))[:5]

    def _retrieve_threat_intel(self, query: str,
                              alert_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """检索威胁情报"""
        try:
            # 根据告警类型确定检索范围
            threat_types = self._map_attack_type_to_threat_types(
                alert_data.get('attack_type', '')
            )

            # 检索威胁情报
            threat_intel = self.threat_retriever.retrieve(
                query=query,
                top_k=self.max_intel_results,
                threat_types=threat_types,
                severity_filter=None  # 不过滤严重程度
            )

            # 过滤低相似度结果
            filtered_intel = [
                intel for intel in threat_intel
                if intel['similarity_score'] >= self.similarity_threshold
            ]

            logger.info(f"检索到 {len(threat_intel)} 条威胁情报，"
                       f"过滤后保留 {len(filtered_intel)} 条")

            return filtered_intel

        except Exception as e:
            logger.error(f"威胁情报检索失败: {e}")
            return []

    def _map_attack_type_to_threat_types(self, attack_type: str) -> Optional[List[str]]:
        """将攻击类型映射到威胁情报类型"""
        if not attack_type:
            return None

        attack_type_lower = attack_type.lower()

        mapping = {
            'sql注入': ['SQL注入'],
            'xss攻击': ['XSS攻击'],
            'web攻击': ['SQL注入', 'XSS攻击', 'Webshell'],
            '漏洞攻击': ['漏洞攻击'],
            '非法外联': ['C2通信'],
            'apt攻击': ['APT攻击'],
            'ddos攻击': ['DDoS攻击'],
            '勒索软件': ['勒索软件'],
            '挖矿恶意软件': ['挖矿恶意软件']
        }

        for key, types in mapping.items():
            if key in attack_type_lower:
                return types

        return None

    def _analyze_threat_intel_relevance(self, threat_intel: List[Dict[str, Any]],
                                      alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析威胁情报关联性"""
        if not threat_intel:
            return {
                'total_matches': 0,
                'relevance_score': 0.0,
                'matched_indicators': [],
                'severity_analysis': {},
                'high_threat_count': 0,
                'medium_threat_count': 0,
                'low_threat_count': 0
            }

        # 统计信息
        total_matches = len(threat_intel)
        severity_counts = {}
        matched_indicators = []
        relevance_scores = []

        # 分析每条威胁情报
        for intel in threat_intel:
            # 统计严重程度
            severity = intel.get('severity', '未知')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # 收集匹配的指标
            indicators = intel.get('indicators', [])
            matched_indicators.extend(indicators)

            # 收集相似度分数
            relevance_scores.append(intel.get('similarity_score', 0.0))

        # 计算总体关联性分数
        avg_relevance = sum(relevance_scores) / len(relevance_scores) if relevance_scores else 0.0

        # 去重匹配的指标
        matched_indicators = list(set(matched_indicators))

        return {
            'total_matches': total_matches,
            'relevance_score': avg_relevance,
            'matched_indicators': matched_indicators[:10],  # 最多显示10个
            'severity_analysis': severity_counts,
            'high_threat_count': severity_counts.get('高危', 0),
            'medium_threat_count': severity_counts.get('中危', 0),
            'low_threat_count': severity_counts.get('低危', 0)
        }

    def _generate_enhanced_result(self, alert_data: Dict[str, Any],
                                base_analysis: Dict[str, Any],
                                threat_intel: List[Dict[str, Any]],
                                intel_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """生成增强分析结果"""
        enhanced_result = {
            'original_analysis': base_analysis or {},
            'threat_intelligence_enhancement': {
                'relevant_intelligence_count': len(threat_intel),
                'overall_relevance_score': intel_analysis.get('relevance_score', 0.0),
                'threat_context': self._generate_threat_context(threat_intel),
                'risk_adjustment': self._calculate_risk_adjustment(intel_analysis),
                'recommended_actions_enhanced': self._generate_enhanced_recommendations(
                    alert_data, threat_intel, intel_analysis
                )
            },
            'confidence_boost': self._calculate_confidence_boost(intel_analysis),
            'analysis_timestamp': time.time()
        }

        return enhanced_result

    def _generate_threat_context(self, threat_intel: List[Dict[str, Any]]) -> str:
        """生成威胁上下文描述"""
        if not threat_intel:
            return "未找到相关的威胁情报"

        # 提取关键信息
        threat_types = list(set([intel.get('threat_type', '') for intel in threat_intel]))
        threat_types = [t for t in threat_types if t]  # 过滤空字符串

        if not threat_types:
            return "找到相关威胁情报，但类型不明确"

        context = f"根据威胁情报分析，此告警可能与以下威胁相关：{', '.join(threat_types)}"

        # 添加高严重程度威胁的特殊说明
        high_severity_count = sum(1 for intel in threat_intel if intel.get('severity') == '高危')
        if high_severity_count > 0:
            context += f"。其中有 {high_severity_count} 条高危威胁情报"

        return context

    def _calculate_risk_adjustment(self, intel_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """计算风险调整"""
        base_score = 5.0  # 基础风险分数
        adjustment = 0.0

        # 根据匹配的威胁情报数量调整
        match_count = intel_analysis.get('total_matches', 0)
        if match_count >= 3:
            adjustment += 2.0
        elif match_count >= 2:
            adjustment += 1.0
        elif match_count >= 1:
            adjustment += 0.5

        # 根据高严重程度威胁数量调整
        high_threat_count = intel_analysis.get('high_threat_count', 0)
        if high_threat_count >= 2:
            adjustment += 2.0
        elif high_threat_count >= 1:
            adjustment += 1.0

        # 根据关联性分数调整
        relevance_score = intel_analysis.get('relevance_score', 0.0)
        if relevance_score >= 0.8:
            adjustment += 1.0
        elif relevance_score >= 0.6:
            adjustment += 0.5

        # 计算调整后的风险分数
        adjusted_score = min(10.0, base_score + adjustment)

        return {
            'original_score': base_score,
            'adjustment': adjustment,
            'adjusted_score': adjusted_score,
            'risk_level_changed': adjusted_score > base_score + 0.5
        }

    def _generate_enhanced_recommendations(self, alert_data: Dict[str, Any],
                                          threat_intel: List[Dict[str, Any]],
                                          intel_analysis: Dict[str, Any]) -> List[str]:
        """生成增强的处置建议"""
        recommendations = []

        # 基于威胁情报生成建议
        if intel_analysis.get('total_matches', 0) > 0:
            recommendations.append("参考相关威胁情报进行深度分析")

            if intel_analysis.get('high_threat_count', 0) > 0:
                recommendations.append("存在高危威胁关联，建议立即采取防护措施")

            if intel_analysis.get('matched_indicators', []):
                indicators = intel_analysis.get('matched_indicators', [])[:3]
                recommendations.append(f"重点监控以下指标：{', '.join(indicators)}")

        # 基于攻击类型生成建议
        attack_type = alert_data.get('attack_type', '').lower()
        if 'sql' in attack_type:
            recommendations.extend([
                "检查数据库访问日志",
                "验证Web应用输入过滤机制",
                "考虑启用WAF规则"
            ])
        elif 'xss' in attack_type:
            recommendations.extend([
                "检查Web应用输出编码",
                "验证CSP策略配置",
                "扫描存储型XSS漏洞"
            ])
        elif '外联' in attack_type or 'c2' in attack_type:
            recommendations.extend([
                "阻断相关恶意IP和域名",
                "分析网络流量异常",
                "检查主机进程异常"
            ])

        # 基于威胁情报来源生成建议
        sources = set([intel.get('source', '') for intel in threat_intel])
        sources = [s for s in sources if s]
        if sources:
            recommendations.append(f"关注以下威胁情报来源的更新：{', '.join(sources)}")

        return recommendations[:8]  # 最多返回8条建议

    def _calculate_confidence_boost(self, intel_analysis: Dict[str, Any]) -> float:
        """计算置信度提升"""
        boost = 0.0

        # 基于匹配数量
        match_count = intel_analysis.get('total_matches', 0)
        if match_count >= 3:
            boost += 0.2
        elif match_count >= 1:
            boost += 0.1

        # 基于关联性分数
        relevance_score = intel_analysis.get('relevance_score', 0.0)
        if relevance_score >= 0.8:
            boost += 0.15
        elif relevance_score >= 0.6:
            boost += 0.1

        return min(0.5, boost)  # 最多提升0.5

    def get_enhancer_statistics(self) -> Dict[str, Any]:
        """获取增强分析器统计信息"""
        if not self.is_initialized:
            return {'status': 'not_initialized'}

        return {
            'status': 'initialized',
            'config': {
                'max_intel_results': self.max_intel_results,
                'similarity_threshold': self.similarity_threshold,
                'enable_context_enhancement': self.enable_context_enhancement
            },
            'threat_retriever_stats': self.threat_retriever.get_statistics()
        }