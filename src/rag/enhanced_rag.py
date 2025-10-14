#!/usr/bin/env python3
"""
增强的RAG威胁情报系统
实现向量化检索和相关威胁情报增强分析
"""
import os
import json
import time
import hashlib
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import re
from loguru import logger

try:
    import chromadb
    from chromadb.config import Settings
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    logger.warning("ChromaDB未安装，将使用本地存储替代")

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    logger.warning("sentence-transformers未安装，将使用简化的文本匹配")

@dataclass
class ThreatIntel:
    """威胁情报数据结构"""
    id: str
    title: str
    description: str
    attack_type: str
    severity: str
    source: str
    published_date: str
    indicators: List[str]
    tags: List[str]
    vector_embedding: Optional[List[float]] = None

@dataclass
class RAGResult:
    """RAG检索结果"""
    threat_intel: ThreatIntel
    similarity_score: float
    relevance_explanation: str
    enhancement_suggestions: List[str]

class ThreatIntelligenceDatabase:
    """威胁情报数据库"""

    def __init__(self, db_path: str = "data/threat_intel"):
        self.db_path = db_path
        self.threat_intels = []
        self.load_threat_intelligence()

    def load_threat_intelligence(self):
        """加载威胁情报数据"""
        # 创建示例威胁情报数据
        sample_threat_intel = [
            {
                "id": "ti_001",
                "title": "SQL注入攻击威胁情报",
                "description": "SQL注入是一种代码注入技术，攻击者通过在应用程序的输入字段中插入恶意SQL语句来攻击数据库。这种攻击可以用于窃取敏感数据、修改数据库内容，甚至在某些情况下获取数据库服务器的控制权。",
                "attack_type": "SQL注入",
                "severity": "高",
                "source": "OWASP",
                "published_date": "2024-01-15",
                "indicators": ["'", '"', ";", "--", "/*", "*/", "UNION", "SELECT", "DROP", "INSERT", "UPDATE", "DELETE"],
                "tags": ["注入攻击", "数据库安全", "OWASP Top 10"]
            },
            {
                "id": "ti_002",
                "title": "XSS跨站脚本攻击威胁情报",
                "description": "跨站脚本攻击（XSS）是一种客户端代码注入攻击，攻击者通过在网页中注入恶意脚本，当用户访问该页面时，恶意脚本会在用户浏览器中执行。XSS可以用于窃取用户会话、重定向用户到恶意网站、或者安装恶意软件。",
                "attack_type": "XSS",
                "severity": "中",
                "source": "CWE",
                "published_date": "2024-02-20",
                "indicators": ["<script>", "javascript:", "onerror=", "onload=", "alert(", "document.cookie", "<img", "<iframe>"],
                "tags": ["客户端攻击", "脚本注入", "Web安全"]
            },
            {
                "id": "ti_003",
                "title": "命令注入攻击威胁情报",
                "description": "命令注入是一种攻击技术，攻击者通过在应用程序的输入中注入操作系统命令，使得应用程序执行恶意命令。这种攻击可以用于获取系统访问权限、窃取敏感信息、或者在系统上安装后门。",
                "attack_type": "命令注入",
                "severity": "高",
                "source": "MITRE ATT&CK",
                "published_date": "2024-03-10",
                "indicators": ["; ", "&& ", "|| ", "| ", "`", "$(", "${", "eval", "exec", "system"],
                "tags": ["系统攻击", "命令执行", "MITRE ATT&CK"]
            },
            {
                "id": "ti_004",
                "title": "Webshell后门威胁情报",
                "description": "Webshell是一种恶意脚本，攻击者通过上传到Web服务器来获得远程访问权限。Webshell允许攻击者执行服务器端命令、访问文件系统、窃取数据，甚至进一步攻击内网中的其他系统。",
                "attack_type": "Webshell",
                "severity": "严重",
                "source": "安全厂商",
                "published_date": "2024-04-05",
                "indicators": ["<?php", "<%", "<jsp:useBean", "eval(", "assert(", "system(", "passthru("],
                "tags": ["后门", "远程访问", "文件上传"]
            },
            {
                "id": "ti_005",
                "title": "C2通信威胁情报",
                "description": "命令与控制（C2）通信是恶意软件与攻击者控制服务器之间的通信机制。攻击者通过C2服务器向被感染的系统发送命令，并接收窃取的数据。检测C2通信对于发现和阻止高级持续性威胁（APT）攻击至关重要。",
                "attack_type": "C2通信",
                "severity": "高",
                "source": "FireEye",
                "published_date": "2024-05-12",
                "indicators": ["心跳通信", "DNS隧道", "HTTP隧道", "ICMP隧道", "定时连接"],
                "tags": ["APT攻击", "恶意软件", "网络通信"]
            },
            {
                "id": "ti_006",
                "title": "目录遍历攻击威胁情报",
                "description": "目录遍历攻击利用应用程序对文件路径处理不当的漏洞，攻击者通过使用'../'序列来访问应用程序预期目录之外的文件和目录。这种攻击可以用于读取敏感文件、执行系统命令，或者在某些情况下获取系统访问权限。",
                "attack_type": "目录遍历",
                "severity": "中",
                "source": "CWE",
                "published_date": "2024-06-18",
                "indicators": ["../", "..\\", "file://", "/etc/passwd", "/windows/system32"],
                "tags": ["文件系统", "路径遍历", "信息泄露"]
            },
            {
                "id": "ti_007",
                "title": "SSRF服务端请求伪造威胁情报",
                "description": "服务端请求伪造（SSRF）是一种攻击，攻击者利用服务器端应用程序来发送恶意请求。攻击者可以强制服务器向内部网络发送请求，绕过防火墙和访问控制，访问内部服务，或者在某些情况下执行远程代码。",
                "attack_type": "SSRF",
                "severity": "高",
                "source": "OWASP",
                "published_date": "2024-07-22",
                "indicators": ["http://127.0.0.1", "http://localhost", "file:///", "gopher://", "dict://"],
                "tags": ["内网探测", "服务端攻击", "网络访问"]
            },
            {
                "id": "ti_008",
                "title": "反序列化攻击威胁情报",
                "description": "反序列化攻击利用应用程序在反序列化对象时的安全漏洞。攻击者可以构造恶意的序列化对象，当应用程序反序列化这些对象时，会执行恶意代码，导致远程代码执行、权限提升或拒绝服务攻击。",
                "attack_type": "反序列化",
                "severity": "严重",
                "source": "安全研究",
                "published_date": "2024-08-30",
                "indicators": ["Object", "java.io.", "System.Runtime.Serialization", "pickle.loads", "yaml.load"],
                "tags": ["对象操作", "代码执行", "编程语言漏洞"]
            }
        ]

        # 转换为ThreatIntel对象
        for ti_data in sample_threat_intel:
            threat_intel = ThreatIntel(**ti_data)
            self.threat_intels.append(threat_intel)

        logger.info(f"加载了 {len(self.threat_intels)} 条威胁情报数据")

    def search_by_attack_type(self, attack_type: str) -> List[ThreatIntel]:
        """根据攻击类型搜索威胁情报"""
        attack_type_lower = attack_type.lower()
        results = []

        for ti in self.threat_intels:
            if (attack_type_lower in ti.attack_type.lower() or
                attack_type_lower in ti.title.lower() or
                any(attack_type_lower in tag.lower() for tag in ti.tags)):
                results.append(ti)

        return results

    def search_by_indicators(self, payload: str) -> List[ThreatIntel]:
        """根据载荷中的指标搜索威胁情报"""
        payload_lower = payload.lower()
        results = []

        for ti in self.threat_intels:
            matches = 0
            for indicator in ti.indicators:
                if indicator.lower() in payload_lower:
                    matches += 1

            if matches > 0:
                results.append((ti, matches))

        # 按匹配度排序
        results.sort(key=lambda x: x[1], reverse=True)
        return [ti for ti, _ in results]

class VectorEmbeddingManager:
    """向量嵌入管理器"""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self.model = None
        self.embedding_cache = {}
        self._initialize_model()

    def _initialize_model(self):
        """初始化嵌入模型"""
        if SENTENCE_TRANSFORMERS_AVAILABLE:
            try:
                self.model = SentenceTransformer(self.model_name)
                logger.info(f"成功加载嵌入模型: {self.model_name}")
            except Exception as e:
                logger.warning(f"加载sentence-transformers模型失败: {e}")
                self.model = None
        else:
            logger.info("使用简化的文本嵌入方法")
            self.model = None

    def generate_embedding(self, text: str) -> List[float]:
        """生成文本嵌入向量"""
        if not text:
            return []

        # 检查缓存
        text_hash = hashlib.md5(text.encode()).hexdigest()
        if text_hash in self.embedding_cache:
            return self.embedding_cache[text_hash]

        try:
            if self.model is not None:
                # 使用sentence-transformers
                embedding = self.model.encode(text).tolist()
            else:
                # 使用简化的TF-IDF式嵌入
                embedding = self._simple_embedding(text)

            # 缓存结果
            self.embedding_cache[text_hash] = embedding
            return embedding

        except Exception as e:
            logger.error(f"生成嵌入向量失败: {e}")
            return self._simple_embedding(text)

    def _simple_embedding(self, text: str) -> List[float]:
        """简化的文本嵌入方法"""
        # 基于字符和词汇的简单嵌入
        text_lower = text.lower()

        # 创建固定长度的特征向量
        features = []

        # 字符级别特征
        for char in "abcdefghijklmnopqrstuvwxyz0123456789":
            features.append(text_lower.count(char) / max(len(text), 1))

        # 特殊字符特征
        special_chars = ["'", '"', ";", "--", "<", ">", "&", "|", "$", "(", ")", "[", "]", "{", "}"]
        for char in special_chars:
            features.append(text_lower.count(char) / max(len(text), 1))

        # 长度特征
        features.append(len(text) / 1000.0)  # 归一化长度

        # 确保向量长度一致
        while len(features) < 100:
            features.append(0.0)

        return features[:100]

class EnhancedRAGAnalyzer:
    """增强的RAG分析器"""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.threat_db = ThreatIntelligenceDatabase()
        self.embedding_manager = VectorEmbeddingManager()
        self.max_intel_results = self.config.get('max_intel_results', 5)
        self.similarity_threshold = self.config.get('similarity_threshold', 0.3)
        self.enable_context_enhancement = self.config.get('enable_context_enhancement', True)

        # 初始化向量数据库
        self.vector_store = {}
        self._initialize_vector_store()

    def _initialize_vector_store(self):
        """初始化向量存储"""
        logger.info("初始化威胁情报向量存储...")

        for ti in self.threat_db.threat_intels:
            # 生成查询文本
            query_text = f"{ti.title} {ti.description} {' '.join(ti.tags)} {' '.join(ti.indicators)}"

            # 生成嵌入向量
            embedding = self.embedding_manager.generate_embedding(query_text)

            if embedding:
                ti.vector_embedding = embedding
                self.vector_store[ti.id] = {
                    'threat_intel': ti,
                    'embedding': embedding
                }

        logger.info(f"向量存储初始化完成，包含 {len(self.vector_store)} 条记录")

    def retrieve_relevant_threat_intel(self, alert_data: Dict) -> List[RAGResult]:
        """检索相关威胁情报"""
        try:
            # 构建查询文本
            query_text = self._build_query_text(alert_data)

            # 生成查询嵌入
            query_embedding = self.embedding_manager.generate_embedding(query_text)

            if not query_embedding:
                logger.warning("无法生成查询嵌入，使用文本匹配替代")
                return self._text_based_retrieval(alert_data)

            # 执行向量相似度搜索
            relevant_intel = self._vector_similarity_search(query_embedding)

            # 生成RAG结果
            rag_results = []
            for ti, similarity in relevant_intel:
                rag_result = self._create_rag_result(ti, similarity, alert_data)
                rag_results.append(rag_result)

            return rag_results[:self.max_intel_results]

        except Exception as e:
            logger.error(f"威胁情报检索失败: {e}")
            return self._text_based_retrieval(alert_data)

    def _build_query_text(self, alert_data: Dict) -> str:
        """构建查询文本"""
        query_parts = []

        # 添加攻击类型
        attack_type = alert_data.get('attack_type', '')
        if attack_type:
            query_parts.append(attack_type)

        # 添加载荷内容
        payload = alert_data.get('payload', '')
        if payload:
            query_parts.append(payload)

        # 添加原始日志
        raw_log = alert_data.get('raw_log', '')
        if raw_log:
            query_parts.append(raw_log)

        # 添加协议信息
        protocol = alert_data.get('protocol', '')
        if protocol:
            query_parts.append(protocol)

        # 添加威胁等级
        threat_level = alert_data.get('threat_level', '')
        if threat_level:
            query_parts.append(threat_level)

        return ' '.join(query_parts)

    def _vector_similarity_search(self, query_embedding: List[float]) -> List[Tuple[ThreatIntel, float]]:
        """向量相似度搜索"""
        similarities = []

        for ti_id, store_data in self.vector_store.items():
            ti = store_data['threat_intel']
            ti_embedding = store_data['embedding']

            # 计算余弦相似度
            similarity = self._cosine_similarity(query_embedding, ti_embedding)

            if similarity >= self.similarity_threshold:
                similarities.append((ti, similarity))

        # 按相似度排序
        similarities.sort(key=lambda x: x[1], reverse=True)

        return similarities

    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """计算余弦相似度"""
        if not vec1 or not vec2 or len(vec1) != len(vec2):
            return 0.0

        try:
            dot_product = sum(a * b for a, b in zip(vec1, vec2))
            magnitude1 = sum(a * a for a in vec1) ** 0.5
            magnitude2 = sum(b * b for b in vec2) ** 0.5

            if magnitude1 == 0 or magnitude2 == 0:
                return 0.0

            return dot_product / (magnitude1 * magnitude2)
        except:
            return 0.0

    def _text_based_retrieval(self, alert_data: Dict) -> List[RAGResult]:
        """基于文本的威胁情报检索（备用方法）"""
        payload = alert_data.get('payload', '')
        attack_type = alert_data.get('attack_type', '')

        # 根据攻击类型搜索
        intel_by_type = self.threat_db.search_by_attack_type(attack_type)

        # 根据载荷指标搜索
        intel_by_indicators = self.threat_db.search_by_indicators(payload)

        # 合并结果
        all_intel = list(set(intel_by_type + intel_by_indicators))

        rag_results = []
        for ti in all_intel:
            # 计算文本相似度
            similarity = self._calculate_text_similarity(alert_data, ti)

            if similarity >= self.similarity_threshold:
                rag_result = self._create_rag_result(ti, similarity, alert_data)
                rag_results.append(rag_result)

        # 按相似度排序
        rag_results.sort(key=lambda x: x.similarity_score, reverse=True)

        return rag_results[:self.max_intel_results]

    def _calculate_text_similarity(self, alert_data: Dict, ti: ThreatIntel) -> float:
        """计算文本相似度"""
        query_text = self._build_query_text(alert_data).lower()
        ti_text = f"{ti.title} {ti.description} {' '.join(ti.tags)}".lower()

        # 简单的词汇重叠计算
        query_words = set(query_text.split())
        ti_words = set(ti_text.split())

        intersection = query_words.intersection(ti_words)
        union = query_words.union(ti_words)

        if not union:
            return 0.0

        return len(intersection) / len(union)

    def _create_rag_result(self, ti: ThreatIntel, similarity: float, alert_data: Dict) -> RAGResult:
        """创建RAG结果"""
        # 生成相关性解释
        relevance_explanation = self._generate_relevance_explanation(ti, alert_data, similarity)

        # 生成增强建议
        enhancement_suggestions = self._generate_enhancement_suggestions(ti, alert_data)

        return RAGResult(
            threat_intel=ti,
            similarity_score=similarity,
            relevance_explanation=relevance_explanation,
            enhancement_suggestions=enhancement_suggestions
        )

    def _generate_relevance_explanation(self, ti: ThreatIntel, alert_data: Dict, similarity: float) -> str:
        """生成相关性解释"""
        explanations = []

        # 攻击类型匹配
        attack_type = alert_data.get('attack_type', '').lower()
        if attack_type and attack_type in ti.attack_type.lower():
            explanations.append(f"攻击类型匹配: {ti.attack_type}")

        # 载荷指标匹配
        payload = alert_data.get('payload', '').lower()
        matched_indicators = []
        for indicator in ti.indicators:
            if indicator.lower() in payload:
                matched_indicators.append(indicator)

        if matched_indicators:
            explanations.append(f"载荷指标匹配: {', '.join(matched_indicators[:3])}")

        # 标签匹配
        for tag in ti.tags:
            if tag.lower() in attack_type or tag.lower() in payload:
                explanations.append(f"标签匹配: {tag}")

        # 相似度说明
        explanations.append(f"语义相似度: {similarity:.3f}")

        return '; '.join(explanations) if explanations else f"基于语义相似度匹配 ({similarity:.3f})"

    def _generate_enhancement_suggestions(self, ti: ThreatIntel, alert_data: Dict) -> List[str]:
        """生成增强建议"""
        suggestions = []

        # 基于威胁情报类型的建议
        if ti.attack_type == "SQL注入":
            suggestions.extend([
                "检查数据库访问权限和输入验证",
                "审查SQL查询日志以发现异常查询",
                "考虑使用参数化查询和预编译语句"
            ])
        elif ti.attack_type == "XSS":
            suggestions.extend([
                "检查用户输入输出过滤",
                "审查CSP策略配置",
                "验证HTTP头部安全设置"
            ])
        elif ti.attack_type == "命令注入":
            suggestions.extend([
                "检查系统命令执行权限",
                "审查输入过滤和转义机制",
                "监控异常的系统调用"
            ])

        # 基于严重程度的建议
        if ti.severity == "严重":
            suggestions.append("立即隔离受影响系统并进行深度检查")
        elif ti.severity == "高":
            suggestions.append("优先处理此告警，加强监控")

        # 基于威胁情报描述的通用建议
        if ti.description:
            if "窃取" in ti.description:
                suggestions.append("检查敏感数据访问日志")
            elif "权限" in ti.description:
                suggestions.append("审查用户权限和访问控制")
            elif "远程" in ti.description:
                suggestions.append("检查远程访问日志和网络连接")

        return suggestions[:5]  # 最多返回5条建议

    def enhance_analysis(self, alert_data: Dict, base_analysis_result: Dict) -> Dict[str, Any]:
        """增强分析结果"""
        try:
            start_time = time.time()

            # 检索相关威胁情报
            rag_results = self.retrieve_relevant_threat_intel(alert_data)

            # 构建增强结果
            enhancement_result = {
                'success': True,
                'threat_intel_count': len(rag_results),
                'processing_time': time.time() - start_time,
                'threat_intelligence': [],
                'enhanced_analysis': {
                    'risk_adjustment': 0.0,
                    'confidence_adjustment': 0.0,
                    'additional_context': [],
                    'mitigation_recommendations': []
                }
            }

            if rag_results:
                # 处理检索到的威胁情报
                total_similarity = 0
                all_suggestions = []
                all_context = []

                for rag_result in rag_results:
                    ti_data = asdict(rag_result.threat_intel)
                    ti_data.pop('vector_embedding', None)  # 移除向量数据

                    enhancement_result['threat_intelligence'].append({
                        'threat_intel': ti_data,
                        'similarity_score': rag_result.similarity_score,
                        'relevance_explanation': rag_result.relevance_explanation,
                        'enhancement_suggestions': rag_result.enhancement_suggestions
                    })

                    total_similarity += rag_result.similarity_score
                    all_suggestions.extend(rag_result.enhancement_suggestions)
                    all_context.append(rag_result.relevance_explanation)

                # 计算调整值
                avg_similarity = total_similarity / len(rag_results)

                # 基于威胁情报调整风险评分
                if avg_similarity > 0.7:
                    enhancement_result['enhanced_analysis']['risk_adjustment'] = 1.5
                elif avg_similarity > 0.5:
                    enhancement_result['enhanced_analysis']['risk_adjustment'] = 1.0
                else:
                    enhancement_result['enhanced_analysis']['risk_adjustment'] = 0.5

                # 基于威胁情报调整置信度
                enhancement_result['enhanced_analysis']['confidence_adjustment'] = min(avg_similarity * 1.2, 1.0)

                # 去重建议
                unique_suggestions = list(set(all_suggestions))
                enhancement_result['enhanced_analysis']['mitigation_recommendations'] = unique_suggestions[:10]

                # 添加上下文信息
                enhancement_result['enhanced_analysis']['additional_context'] = all_context[:5]

            else:
                enhancement_result['enhanced_analysis']['additional_context'].append("未找到相关的威胁情报")
                enhancement_result['enhanced_analysis']['mitigation_recommendations'].append("建议进行人工分析确认")

            return enhancement_result

        except Exception as e:
            logger.error(f"RAG增强分析失败: {e}")
            return {
                'success': False,
                'error_message': str(e),
                'threat_intel_count': 0,
                'processing_time': time.time() - start_time
            }

    def get_statistics(self) -> Dict[str, Any]:
        """获取RAG分析器统计信息"""
        return {
            'threat_intel_count': len(self.threat_db.threat_intels),
            'vector_store_size': len(self.vector_store),
            'embedding_cache_size': len(self.embedding_manager.embedding_cache),
            'max_intel_results': self.max_intel_results,
            'similarity_threshold': self.similarity_threshold,
            'enable_context_enhancement': self.enable_context_enhancement,
            'chromadb_available': CHROMADB_AVAILABLE,
            'sentence_transformers_available': SENTENCE_TRANSFORMERS_AVAILABLE
        }