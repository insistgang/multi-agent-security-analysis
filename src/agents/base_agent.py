#!/usr/bin/env python3
"""
基础智能体抽象类
定义所有智能体的通用接口和基础功能
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import time
import json
from loguru import logger

class AgentRole(Enum):
    """智能体角色枚举"""
    ROUTER = "router"
    WEB_ATTACK_EXPERT = "web_attack_expert"
    VULNERABILITY_EXPERT = "vulnerability_expert"
    ILLEGAL_CONNECTION_EXPERT = "illegal_connection_expert"
    AGGREGATOR = "aggregator"
    CLASSIFIER = "classifier"

@dataclass
class AgentResult:
    """智能体处理结果"""
    agent_id: str
    agent_role: AgentRole
    success: bool
    result: Dict[str, Any]
    confidence: float
    processing_time: float
    error_message: Optional[str] = None

class BaseAgent(ABC):
    """基础智能体抽象类"""

    def __init__(self, agent_id: str, role: AgentRole, config: Dict[str, Any] = None):
        self.agent_id = agent_id
        self.role = role
        self.config = config or {}
        self.is_initialized = False
        self.performance_metrics = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'average_processing_time': 0.0,
            'total_processing_time': 0.0
        }

    @abstractmethod
    def initialize(self) -> bool:
        """初始化智能体"""
        pass

    @abstractmethod
    def process(self, input_data: Dict[str, Any]) -> AgentResult:
        """处理输入数据"""
        pass

    @abstractmethod
    def validate_input(self, input_data: Dict[str, Any]) -> bool:
        """验证输入数据"""
        pass

    def update_metrics(self, success: bool, processing_time: float):
        """更新性能指标"""
        self.performance_metrics['total_requests'] += 1
        self.performance_metrics['total_processing_time'] += processing_time

        if success:
            self.performance_metrics['successful_requests'] += 1
        else:
            self.performance_metrics['failed_requests'] += 1

        self.performance_metrics['average_processing_time'] = (
            self.performance_metrics['total_processing_time'] /
            self.performance_metrics['total_requests']
        )

    def get_metrics(self) -> Dict[str, Any]:
        """获取性能指标"""
        total = self.performance_metrics['total_requests']
        if total == 0:
            return self.performance_metrics

        metrics = self.performance_metrics.copy()
        metrics['success_rate'] = self.performance_metrics['successful_requests'] / total
        metrics['failure_rate'] = self.performance_metrics['failed_requests'] / total
        return metrics

    def reset_metrics(self):
        """重置性能指标"""
        self.performance_metrics = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'average_processing_time': 0.0,
            'total_processing_time': 0.0
        }

    def log_action(self, action: str, details: Dict[str, Any] = None):
        """记录操作日志"""
        log_data = {
            'agent_id': self.agent_id,
            'role': self.role.value,
            'action': action,
            'timestamp': time.time(),
            'details': details or {}
        }

        # Windows GBK编码安全处理
        try:
            log_json = json.dumps(log_data, ensure_ascii=False)
            logger.info(f"Agent {self.agent_id}: {action} - {log_json}")
        except UnicodeEncodeError:
            # 回退到ASCII编码
            log_json_ascii = json.dumps(log_data, ensure_ascii=True)
            logger.info(f"Agent {self.agent_id}: {action} - {log_json_ascii}")

    def __str__(self):
        return f"Agent(id={self.agent_id}, role={self.role.value})"

    def __repr__(self):
        return self.__str__()