#!/usr/bin/env python3
"""
威胁情报检索系统
基于RAG技术提供威胁情报增强分析
"""
import chromadb
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from sentence_transformers import SentenceTransformer
import re
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from loguru import logger

@dataclass
class ThreatIntel:
    """威胁情报数据结构"""
    intel_id: str
    threat_type: str
    description: str
    indicators: List[str]
    severity: str
    source: str
    created_at: datetime
    tags: List[str]

class ThreatIntelRetriever:
    """威胁情报检索器"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.collection_name = "threat_intelligence"
        self.model_name = self.config.get('embedding_model', 'sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2')

        # 初始化组件
        self.embedding_model = None
        self.vector_db = None
        self.collection = None
        self.is_initialized = False

        # 缓存
        self.embedding_cache = {}
        self.query_cache = {}

    def initialize(self) -> bool:
        """初始化威胁情报检索系统"""
        try:
            logger.info("初始化威胁情报检索系统...")

            # 初始化嵌入模型
            self._init_embedding_model()

            # 初始化向量数据库
            self._init_vector_db()

            # 加载威胁情报数据
            self._load_threat_intel()

            self.is_initialized = True
            logger.info("威胁情报检索系统初始化完成")
            return True

        except Exception as e:
            logger.error(f"威胁情报检索系统初始化失败: {e}")
            return False

    def _init_embedding_model(self):
        """初始化文本嵌入模型"""
        logger.info(f"加载嵌入模型: {self.model_name}")
        self.embedding_model = SentenceTransformer(self.model_name)
        logger.info("嵌入模型加载完成")

    def _init_vector_db(self):
        """初始化向量数据库"""
        logger.info("初始化ChromaDB向量数据库")

        # 创建客户端
        self.vector_db = chromadb.Client()

        # 创建或获取集合
        try:
            self.collection = self.vector_db.get_collection(self.collection_name)
            logger.info("已存在威胁情报集合")
        except Exception:
            self.collection = self.vector_db.create_collection(
                name=self.collection_name,
                metadata={
                    "hnsw:space": "cosine",
                    "description": "网络安全威胁情报集合（示例数据）",
                }
            )
            logger.info("创建新的威胁情报集合")

    def _load_threat_intel(self):
        """加载威胁情报数据"""
        logger.info("加载威胁情报数据...")

        # 检查是否已有数据
        try:
            count = self.collection.count()
            if count > 0:
                logger.info(f"已存在 {count} 条威胁情报记录")
                return
        except Exception:
            pass

        # 创建示例威胁情报数据
        sample_intel = self._create_sample_threat_intel()
        self._add_threat_intel(sample_intel)

        logger.info(f"加载了 {len(sample_intel)} 条威胁情报记录")

    def _create_sample_threat_intel(self) -> List[ThreatIntel]:
        """创建示例威胁情报数据"""
        intel_data = [
            ThreatIntel(
                intel_id="cve_2024_0001",
                threat_type="SQL注入",
                description="Apache Struts2远程代码执行漏洞CVE-2024-XXXXX，允许攻击者通过恶意OGNL表达式执行任意代码",
                indicators=["struts", "ognl", "remote code execution", "cve-2024"],
                severity="高危",
                source="CVE数据库",
                created_at=datetime.now() - timedelta(days=30),
                tags=["web攻击", "rce", "java", "struts2"]
            ),
            ThreatIntel(
                intel_id="malware_001",
                threat_type="木马后门",
                description="DarkSide勒索软件新变种，通过RDP暴力破解传播，加密文件后索要比特币赎金",
                indicators=["darkside", "ransomware", "rdp", "bitcoin", "encryption"],
                severity="高危",
                source="恶意软件分析报告",
                created_at=datetime.now() - timedelta(days=15),
                tags=["勒索软件", "木马", "rdp", "加密货币"]
            ),
            ThreatIntel(
                intel_id="apt_001",
                threat_type="APT攻击",
                description="Lazarus组织使用新的水坑攻击技术，针对金融机构的供应链攻击",
                indicators=["lazarus", "watering hole", "supply chain", "financial"],
                severity="高危",
                source="威胁情报报告",
                created_at=datetime.now() - timedelta(days=7),
                tags=["apt", "水坑攻击", "供应链", "金融"]
            ),
            ThreatIntel(
                intel_id="webshell_001",
                threat_type="Webshell",
                description="中国菜刀后门新变种，支持文件管理、数据库操作、命令执行等功能",
                indicators=["chopper", "webshell", "file manager", "database"],
                severity="中危",
                source="安全社区",
                created_at=datetime.now() - timedelta(days=20),
                tags=["webshell", "后门", "文件管理"]
            ),
            ThreatIntel(
                intel_id="c2_001",
                threat_type="C2通信",
                description="使用DNS隧道技术的C2通信，恶意域名example-bad[.]com通过TXT记录传输命令",
                indicators=["dns tunnel", "c2", "example-bad.com", "txt record"],
                severity="高危",
                source="DNS流量分析",
                created_at=datetime.now() - timedelta(days=5),
                tags=["c2通信", "dns隧道", "恶意域名"]
            ),
            ThreatIntel(
                intel_id="xss_001",
                threat_type="XSS攻击",
                description="基于DOM的XSS攻击新变种，利用第三方JavaScript库漏洞绕过CSP策略",
                indicators=["dom xss", "csp bypass", "javascript library", "third-party"],
                severity="中危",
                source="漏洞研究",
                created_at=datetime.now() - timedelta(days=10),
                tags=["xss", "dom", "csp绕过", "javascript"]
            ),
            ThreatIntel(
                intel_id="iot_001",
                threat_type="IoT攻击",
                description="Mirai僵尸网络新变种，针对智能摄像头和路由器的DDoS攻击",
                indicators=["mirai", "iot", "ddos", "smart camera", "router"],
                severity="高危",
                source="僵尸网络监控",
                created_at=datetime.now() - timedelta(days=12),
                tags=["mirai", "iot", "ddos", "僵尸网络"]
            ),
            ThreatIntel(
                intel_id="crypto_001",
                threat_type="挖矿恶意软件",
                description="XMRig挖矿恶意软件通过 EternalBlue 漏洞传播，占用大量CPU资源",
                indicators=["xmrig", "monero", "mining", "eternalblue", "cpu"],
                severity="中危",
                source="恶意软件分析",
                created_at=datetime.now() - timedelta(days=25),
                tags=["挖矿", "门罗币", "eternalblue", "cpu占用"]
            )
        ]

        return intel_data

    def _add_threat_intel(self, intel_list: List[ThreatIntel]):
        """添加威胁情报到向量数据库"""
        if not intel_list:
            return

        # 准备数据
        documents = []
        metadatas = []
        ids = []

        for intel in intel_list:
            # 创建文档内容
            doc_content = self._create_document_content(intel)
            documents.append(doc_content)

            # 创建元数据
            metadata = {
                "intel_id": intel.intel_id,
                "threat_type": intel.threat_type,
                "severity": intel.severity,
                "source": intel.source,
                "created_at": intel.created_at.isoformat(),
                "tags": ",".join(intel.tags),
                "indicators": ",".join(intel.indicators)
            }
            metadatas.append(metadata)

            ids.append(intel.intel_id)

        # 生成嵌入向量
        logger.info("生成威胁情报嵌入向量...")
        embeddings = self.embedding_model.encode(documents)

        # 添加到向量数据库
        self.collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids,
            embeddings=embeddings.tolist()
        )

    def _create_document_content(self, intel: ThreatIntel) -> str:
        """创建文档内容用于嵌入"""
        content_parts = [
            intel.threat_type,
            intel.description,
            " ".join(intel.indicators),
            " ".join(intel.tags)
        ]
        return " ".join(content_parts)

    def retrieve(self, query: str, top_k: int = 5,
                threat_types: List[str] = None,
                severity_filter: List[str] = None) -> List[Dict[str, Any]]:
        """检索相关威胁情报"""
        try:
            # 检查缓存
            cache_key = f"{query}_{top_k}_{threat_types}_{severity_filter}"
            if cache_key in self.query_cache:
                logger.debug(f"使用缓存查询结果: {query}")
                return self.query_cache[cache_key]

            # 生成查询嵌入
            query_embedding = self._get_query_embedding(query)

            # 构建查询过滤器
            where_filter = self._build_filter(threat_types, severity_filter)

            # 执行向量搜索
            results = self.collection.query(
                query_embeddings=[query_embedding.tolist()],
                n_results=top_k,
                where=where_filter
            )

            # 处理搜索结果
            intel_results = self._process_query_results(results)

            # 缓存结果
            self.query_cache[cache_key] = intel_results

            logger.info(f"检索到 {len(intel_results)} 条相关威胁情报")
            return intel_results

        except Exception as e:
            logger.error(f"威胁情报检索失败: {e}")
            return []

    def _get_query_embedding(self, query: str) -> np.ndarray:
        """获取查询嵌入向量"""
        if query in self.embedding_cache:
            return self.embedding_cache[query]

        embedding = self.embedding_model.encode(query)
        self.embedding_cache[query] = embedding
        return embedding

    def _build_filter(self, threat_types: List[str] = None,
                     severity_filter: List[str] = None) -> Dict[str, Any]:
        """构建查询过滤器"""
        filters = {}

        if threat_types:
            filters["threat_type"] = {"$in": threat_types}

        if severity_filter:
            filters["severity"] = {"$in": severity_filter}

        return filters if filters else None

    def _process_query_results(self, results: Dict) -> List[Dict[str, Any]]:
        """处理查询结果"""
        intel_results = []

        if not results or not results.get('documents') or not results['documents'][0]:
            return intel_results

        documents = results['documents'][0]
        metadatas = results['metadatas'][0]
        distances = results['distances'][0]

        for i, (doc, metadata, distance) in enumerate(zip(documents, metadatas, distances)):
            intel_result = {
                'rank': i + 1,
                'similarity_score': max(0.0, 1 - float(distance)),
                'sample_data': True,
                'intel_id': metadata.get('intel_id'),
                'threat_type': metadata.get('threat_type'),
                'description': doc,
                'severity': metadata.get('severity'),
                'source': metadata.get('source'),
                'created_at': metadata.get('created_at'),
                'tags': metadata.get('tags', '').split(','),
                'indicators': metadata.get('indicators', '').split(',')
            }
            intel_results.append(intel_result)

        return intel_results

    def get_intel_by_id(self, intel_id: str) -> Optional[Dict[str, Any]]:
        """根据ID获取威胁情报"""
        try:
            results = self.collection.get(
                ids=[intel_id],
                include=["documents", "metadatas"]
            )

            if results['ids'] and results['ids'][0]:
                metadata = results['metadatas'][0]
                document = results['documents'][0]

                return {
                    'intel_id': metadata.get('intel_id'),
                    'threat_type': metadata.get('threat_type'),
                    'description': document,
                    'severity': metadata.get('severity'),
                    'source': metadata.get('source'),
                    'created_at': metadata.get('created_at'),
                    'tags': metadata.get('tags', '').split(','),
                    'indicators': metadata.get('indicators', '').split(',')
                }

            return None

        except Exception as e:
            logger.error(f"获取威胁情报失败: {e}")
            return None

    def add_threat_intel(self, intel: ThreatIntel) -> bool:
        """添加新的威胁情报"""
        try:
            # 检查是否已存在
            if self.get_intel_by_id(intel.intel_id):
                logger.warning(f"威胁情报已存在: {intel.intel_id}")
                return False

            # 添加到数据库
            self._add_threat_intel([intel])

            # 清空缓存
            self.query_cache.clear()

            logger.info(f"添加威胁情报成功: {intel.intel_id}")
            return True

        except Exception as e:
            logger.error(f"添加威胁情报失败: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """获取威胁情报统计信息"""
        try:
            total_count = self.collection.count()

            # 获取所有元数据用于统计
            all_results = self.collection.get(include=["metadatas"])
            metadatas = all_results['metadatas']

            # 统计威胁类型分布
            threat_type_counts = {}
            severity_counts = {}

            for metadata in metadatas:
                threat_type = metadata.get('threat_type', '未知')
                severity = metadata.get('severity', '未知')

                threat_type_counts[threat_type] = threat_type_counts.get(threat_type, 0) + 1
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            return {
                'total_intel_count': total_count,
                'threat_type_distribution': threat_type_counts,
                'severity_distribution': severity_counts,
                'cache_stats': {
                    'embedding_cache_size': len(self.embedding_cache),
                    'query_cache_size': len(self.query_cache)
                }
            }

        except Exception as e:
            logger.error(f"获取统计信息失败: {e}")
            return {}

    def search_by_indicators(self, indicators: List[str], top_k: int = 5) -> List[Dict[str, Any]]:
        """根据指标搜索威胁情报"""
        if not indicators:
            return []

        # 构建查询
        query = " ".join(indicators)
        return self.retrieve(query, top_k=top_k)

    def get_recent_intel(self, days: int = 7) -> List[Dict[str, Any]]:
        """获取最近的威胁情报"""
        try:
            # 获取所有威胁情报
            all_results = self.collection.get(include=["documents", "metadatas"])

            if not all_results['ids']:
                return []

            # 过滤最近的记录
            recent_intel = []
            cutoff_date = datetime.now() - timedelta(days=days)

            for i, metadata in enumerate(all_results['metadatas']):
                created_at_str = metadata.get('created_at')
                if created_at_str:
                    created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                    if created_at >= cutoff_date:
                        recent_intel.append({
                            'intel_id': metadata.get('intel_id'),
                            'threat_type': metadata.get('threat_type'),
                            'description': all_results['documents'][i],
                            'severity': metadata.get('severity'),
                            'created_at': created_at_str,
                            'days_ago': (datetime.now() - created_at).days
                        })

            # 按时间排序
            recent_intel.sort(key=lambda x: x['days_ago'])

            return recent_intel[:20]  # 最多返回20条

        except Exception as e:
            logger.error(f"获取最近威胁情报失败: {e}")
            return []