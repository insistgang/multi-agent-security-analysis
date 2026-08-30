#!/usr/bin/env python3
"""
安全日志解析器
解析各种格式的安全告警日志，提取关键特征
"""
import re
import json
import pandas as pd
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import unquote
import ipaddress
from loguru import logger

@dataclass
class ParsedAlert:
    """解析后的告警结构"""
    timestamp: datetime
    source_ip: str
    target_ip: Optional[str]
    attack_type: str
    attack_stage: str
    threat_level: str
    protocol: str
    payload: str
    raw_log: str
    features: Dict[str, Any]

class AlertLogParser:
    """告警日志解析器"""

    def __init__(self):
        # 初始化正则表达式模式
        self.patterns = {
            'ip_pattern': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'timestamp_pattern': re.compile(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'),
            'sql_injection': re.compile(r'(?i)(union|select|insert|update|delete|drop|exec|script|and\s+1\s*=\s*1|or\s+1\s*=\s*1)'),
            'xss_pattern': re.compile(r'(?i)(<script|javascript:|onload=|onerror=|alert\(|document\.cookie)'),
            'path_traversal': re.compile(r'(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\)'),
            'command_injection': re.compile(r'(?i)(;|\||&|`|\$\(|wget|curl|nc|netcat)'),
            'web_shell': re.compile(r'(?i)(eval|exec|system|shell_exec|passthru|assert)'),
        }

        # 攻击类型映射
        self.attack_type_mapping = {
            'SQL注入': ['SQL注入', 'sqli', 'sql injection'],
            'XSS攻击': ['XSS', 'cross-site scripting', '跨站脚本'],
            '文件上传': ['文件上传', 'file upload', 'upload'],
            '命令执行': ['命令执行', 'command injection', 'rce'],
            '目录遍历': ['目录遍历', 'path traversal', 'directory traversal'],
            'Web攻击': ['Web攻击', 'web attack', 'http攻击'],
            '漏洞攻击': ['漏洞攻击', 'vulnerability', 'exploit'],
            '非法外联': ['非法外联', 'illegal connection', 'c2通信']
        }

        # 威胁等级映射
        self.threat_level_mapping = {
            '高风险': 5,
            '中风险': 3,
            '低风险': 1,
            'critical': 5,
            'high': 5,
            'medium': 3,
            'low': 1,
            '高': 5,
            '中': 3,
            '低': 1
        }

    def parse_excel_log(self, file_path: str) -> List[ParsedAlert]:
        """解析Excel格式的告警日志"""
        try:
            logger.info(f"开始解析Excel文件: {file_path}")
            suffix = str(file_path).lower()
            if suffix.endswith(".csv"):
                df = pd.read_csv(file_path)
            elif suffix.endswith(".json"):
                df = pd.read_json(file_path)
            else:
                df = pd.read_excel(file_path)

            parsed_alerts = []
            for idx, row in df.iterrows():
                try:
                    alert = self._parse_row(row)
                    if alert:
                        parsed_alerts.append(alert)
                except Exception as e:
                    logger.warning(f"解析第{idx+1}行失败: {e}")
                    continue

            logger.info(f"成功解析 {len(parsed_alerts)} 条告警记录")
            return parsed_alerts

        except Exception as e:
            logger.error(f"解析Excel文件失败: {e}")
            return []

    def _parse_row(self, row: pd.Series) -> Optional[ParsedAlert]:
        """解析单行数据"""
        try:
            # 提取时间戳
            def _cell(*names):
                for name in names:
                    if name in row and pd.notna(row.get(name)):
                        return row.get(name)
                return ''

            timestamp_str = _cell('告警时间', 'timestamp')
            timestamp = self._parse_timestamp(timestamp_str)

            source_ip = _cell('源IP', 'source_ip')
            target_ip = _cell('目标IP', 'target_ip')

            primary_type = _cell('一级告警类型', 'attack_type', '二级告警名称')
            secondary_type = _cell('二级告警类型', '二级告警名称')
            attack_type = self._normalize_attack_type(primary_type, secondary_type)

            attack_stage = _cell('攻击阶段', 'attack_stage')

            threat_level_raw = _cell('威胁等级', 'threat_level', '告警等级')
            threat_level = self._normalize_threat_level(threat_level_raw)

            protocol = _cell('协议', 'protocol')
            if pd.isna(protocol) or protocol == '':
                protocol = 'UNKNOWN'

            payload = _cell('载荷', '攻击载荷', 'payload')
            request_data = _cell('请求数据', 'raw_log')
            full_payload = str(payload) if not pd.isna(payload) else ''
            if request_data and not pd.isna(request_data):
                full_payload += f" | {request_data}"

            # 原始日志
            raw_log = str(row.to_dict())

            # 提取特征
            features = self._extract_features(full_payload, attack_type)

            return ParsedAlert(
                timestamp=timestamp,
                source_ip=source_ip,
                target_ip=target_ip if not pd.isna(target_ip) else None,
                attack_type=attack_type,
                attack_stage=attack_stage,
                threat_level=threat_level,
                protocol=protocol,
                payload=full_payload,
                raw_log=raw_log,
                features=features
            )

        except Exception as e:
            logger.error(f"解析行数据失败: {e}")
            return None

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """解析时间戳"""
        try:
            if pd.isna(timestamp_str):
                return datetime.now()

            # 尝试多种时间格式
            raw = str(timestamp_str).strip()
            if raw.endswith('Z'):
                raw = raw[:-1] + '+00:00'
            try:
                return datetime.fromisoformat(raw)
            except ValueError:
                pass

            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y/%m/%d %H:%M:%S',
                '%Y-%m-%d %H:%M:%S.%f',
                '%Y-%m-%dT%H:%M:%S',
            ]

            for fmt in formats:
                try:
                    return datetime.strptime(str(timestamp_str), fmt)
                except ValueError:
                    continue

            # 如果都失败，返回当前时间
            logger.warning(f"无法解析时间戳: {timestamp_str}")
            return datetime.now()

        except Exception as e:
            logger.error(f"时间戳解析错误: {e}")
            return datetime.now()

    def _normalize_attack_type(self, primary_type: str, secondary_type: str) -> str:
        """标准化攻击类型"""
        combined = f"{primary_type} {secondary_type}".lower()

        for mapped_type, keywords in self.attack_type_mapping.items():
            for keyword in keywords:
                if keyword.lower() in combined:
                    return mapped_type

        return primary_type if primary_type else "未知攻击"

    def _normalize_threat_level(self, threat_level_raw: str) -> str:
        """标准化威胁等级"""
        if pd.isna(threat_level_raw):
            return "中风险"

        threat_level_str = str(threat_level_raw)
        for level, score in self.threat_level_mapping.items():
            if level in threat_level_str:
                if score >= 5:
                    return "高风险"
                elif score >= 3:
                    return "中风险"
                else:
                    return "低风险"

        return "中风险"  # 默认中等风险

    def _extract_features(self, payload: str, attack_type: str) -> Dict[str, Any]:
        """提取载荷特征"""
        features = {
            'payload_length': len(payload),
            'has_ip': bool(self.patterns['ip_pattern'].search(payload)),
            'has_sql_injection': bool(self.patterns['sql_injection'].search(payload)),
            'has_xss': bool(self.patterns['xss_pattern'].search(payload)),
            'has_path_traversal': bool(self.patterns['path_traversal'].search(payload)),
            'has_command_injection': bool(self.patterns['command_injection'].search(payload)),
            'has_web_shell': bool(self.patterns['web_shell'].search(payload)),
            'special_char_count': len(re.findall(r'[^a-zA-Z0-9\s]', payload)),
            'encoded_content': '%' in payload,
            'suspicious_extensions': self._check_suspicious_extensions(payload),
            'attack_type': attack_type
        }

        return features

    def _check_suspicious_extensions(self, payload: str) -> List[str]:
        """检查可疑文件扩展名"""
        suspicious_extensions = ['.php', '.asp', '.jsp', '.cgi', '.sh', '.bat', '.exe']
        found = []

        for ext in suspicious_extensions:
            if ext.lower() in payload.lower():
                found.append(ext)

        return found

    def parse_json_log(self, log_json: str) -> Optional[ParsedAlert]:
        """解析JSON格式的日志"""
        try:
            log_data = json.loads(log_json)
            # 根据实际JSON格式进行调整
            # 这里提供一个基础框架
            return self._parse_row(pd.Series(log_data))
        except Exception as e:
            logger.error(f"JSON日志解析失败: {e}")
            return None

    def batch_parse(self, file_path: str, batch_size: int = 1000) -> List[ParsedAlert]:
        """批量解析日志"""
        alerts = []

        try:
            df = pd.read_excel(file_path)
            total_rows = len(df)

            for i in range(0, total_rows, batch_size):
                batch_df = df.iloc[i:i+batch_size]
                batch_alerts = []

                for _, row in batch_df.iterrows():
                    alert = self._parse_row(row)
                    if alert:
                        batch_alerts.append(alert)

                alerts.extend(batch_alerts)
                logger.info(f"已处理 {min(i+batch_size, total_rows)}/{total_rows} 条记录")

            logger.info(f"批量解析完成，共解析 {len(alerts)} 条告警")
            return alerts

        except Exception as e:
            logger.error(f"批量解析失败: {e}")
            return []

# 使用示例
if __name__ == "__main__":
    parser = AlertLogParser()

    # 解析攻击日志
    alerts = parser.parse_excel_log(r"E:\VS_project\pj2.0\data\攻击日志V2.xlsx")

    print(f"解析了 {len(alerts)} 条告警")
    if alerts:
        print(f"第一条告警: {alerts[0]}")