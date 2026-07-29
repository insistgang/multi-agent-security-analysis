#!/usr/bin/env python3
"""
系统错误处理和容错机制
实现重试机制、熔断器模式和优雅降级
"""
import time
import asyncio
import inspect
import logging
from typing import Any, Callable, Dict, Optional, Union, List
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from datetime import datetime, timedelta
from loguru import logger

class ErrorLevel(Enum):
    """错误级别"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ErrorInfo:
    """错误信息"""
    error_type: str
    error_message: str
    timestamp: datetime
    level: ErrorLevel
    component: str
    context: Dict[str, Any] = field(default_factory=dict)
    retry_count: int = 0

class CircuitState(Enum):
    """熔断器状态"""
    CLOSED = "closed"      # 正常状态
    OPEN = "open"          # 熔断状态
    HALF_OPEN = "half_open"  # 半开状态

@dataclass
class CircuitBreakerConfig:
    """熔断器配置"""
    failure_threshold: int = 5          # 失败阈值
    timeout: float = 60.0              # 熔断超时时间(秒)
    success_threshold: int = 3         # 半开状态成功阈值
    max_retries: int = 3               # 最大重试次数
    retry_delay: float = 1.0           # 重试延迟(秒)
    backoff_factor: float = 2.0        # 退避因子

class CircuitBreaker:
    """熔断器实现"""

    def __init__(self, name: str, config: CircuitBreakerConfig = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.last_success_time: Optional[datetime] = None
        self.call_count = 0
        self.error_history: List[ErrorInfo] = []

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """通过熔断器调用函数"""
        self._prepare_call()

        start_time = time.time()
        last_exception = None

        for attempt in range(self.config.max_retries + 1):
            try:
                result = func(*args, **kwargs)

                # 调用成功
                self._on_success(time.time() - start_time)
                return result

            except Exception as e:
                last_exception = e
                self._on_failure(e, attempt)

                if attempt < self.config.max_retries:
                    delay = self.config.retry_delay * (self.config.backoff_factor ** attempt)
                    logger.warning(f"调用失败，{delay}秒后重试 (尝试 {attempt + 1}/{self.config.max_retries})")
                    time.sleep(delay)

        # 所有重试都失败
        raise last_exception

    async def call_async(self, func: Callable, *args, **kwargs) -> Any:
        """通过熔断器调用并等待异步函数"""
        self._prepare_call()

        start_time = time.time()
        last_exception = None

        for attempt in range(self.config.max_retries + 1):
            try:
                result = await func(*args, **kwargs)

                self._on_success(time.time() - start_time)
                return result

            except Exception as e:
                last_exception = e
                self._on_failure(e, attempt)

                if attempt < self.config.max_retries:
                    delay = self.config.retry_delay * (self.config.backoff_factor ** attempt)
                    logger.warning(f"异步调用失败，{delay}秒后重试 (尝试 {attempt + 1}/{self.config.max_retries})")
                    await asyncio.sleep(delay)

        raise last_exception

    def _prepare_call(self):
        """检查熔断状态并在超时后进入半开状态"""
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitState.HALF_OPEN
                logger.info(f"熔断器 {self.name} 进入半开状态")
            else:
                raise Exception(f"熔断器 {self.name} 处于开启状态，拒绝调用")

    def _should_attempt_reset(self) -> bool:
        """是否应该尝试重置熔断器"""
        if self.last_failure_time is None:
            return False

        time_since_failure = (datetime.now() - self.last_failure_time).total_seconds()
        return time_since_failure >= self.config.timeout

    def _on_success(self, processing_time: float):
        """处理成功调用"""
        self.call_count += 1
        self.last_success_time = datetime.now()

        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.success_count = 0
                logger.info(f"熔断器 {self.name} 恢复到关闭状态")
        elif self.state == CircuitState.CLOSED:
            # 在关闭状态下，成功的调用会重置失败计数
            if self.failure_count > 0:
                self.failure_count = max(0, self.failure_count - 1)

    def _on_failure(self, exception: Exception, attempt: int):
        """处理失败调用"""
        self.failure_count += 1
        self.last_failure_time = datetime.now()

        # 记录错误信息
        error_info = ErrorInfo(
            error_type=type(exception).__name__,
            error_message=str(exception),
            timestamp=datetime.now(),
            level=ErrorLevel.MEDIUM,
            component=self.name,
            retry_count=attempt
        )
        self.error_history.append(error_info)

        # 保持错误历史在合理范围内
        if len(self.error_history) > 100:
            self.error_history = self.error_history[-50:]

        if self.state == CircuitState.CLOSED:
            if self.failure_count >= self.config.failure_threshold:
                self.state = CircuitState.OPEN
                logger.error(f"熔断器 {self.name} 开启，失败次数: {self.failure_count}")
        elif self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
            self.success_count = 0
            logger.warning(f"熔断器 {self.name} 在半开状态下再次失败，重新开启")

    def get_status(self) -> Dict[str, Any]:
        """获取熔断器状态"""
        return {
            'name': self.name,
            'state': self.state.value,
            'failure_count': self.failure_count,
            'success_count': self.success_count,
            'call_count': self.call_count,
            'last_failure_time': self.last_failure_time.isoformat() if self.last_failure_time else None,
            'last_success_time': self.last_success_time.isoformat() if self.last_success_time else None,
            'recent_errors': len([e for e in self.error_history
                               if (datetime.now() - e.timestamp).total_seconds() < 300])
        }

class ErrorHandler:
    """错误处理器"""

    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.error_handlers: Dict[type, Callable] = {}
        self.global_error_handlers: List[Callable] = []

    def register_circuit_breaker(self, name: str, config: CircuitBreakerConfig = None) -> CircuitBreaker:
        """注册熔断器"""
        breaker = CircuitBreaker(name, config)
        self.circuit_breakers[name] = breaker
        return breaker

    def get_circuit_breaker(self, name: str) -> Optional[CircuitBreaker]:
        """获取熔断器"""
        return self.circuit_breakers.get(name)

    def register_error_handler(self, exception_type: type, handler: Callable):
        """注册特定错误类型的处理器"""
        self.error_handlers[exception_type] = handler

    def register_global_handler(self, handler: Callable):
        """注册全局错误处理器"""
        self.global_error_handlers.append(handler)

    def handle_error(self, exception: Exception, context: Dict[str, Any] = None) -> bool:
        """处理错误，返回是否成功处理"""
        context = context or {}

        # 尝试特定错误处理器
        exception_type = type(exception)
        if exception_type in self.error_handlers:
            try:
                self.error_handlers[exception_type](exception, context)
                return True
            except Exception as e:
                logger.error(f"错误处理器执行失败: {e}")

        # 尝试全局错误处理器
        for handler in self.global_error_handlers:
            try:
                handler(exception, context)
                return True
            except Exception as e:
                logger.error(f"全局错误处理器执行失败: {e}")

        # 默认处理
        logger.error(f"未处理的错误: {exception}, 上下文: {context}")
        return False

    def get_all_status(self) -> Dict[str, Any]:
        """获取所有熔断器状态"""
        return {
            'circuit_breakers': {
                name: breaker.get_status()
                for name, breaker in self.circuit_breakers.items()
            }
        }

# 全局错误处理器实例
global_error_handler = ErrorHandler()

def with_circuit_breaker(breaker_name: str, config: CircuitBreakerConfig = None):
    """熔断器装饰器"""
    def decorator(func: Callable):
        breaker = global_error_handler.register_circuit_breaker(breaker_name, config)

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            return breaker.call(func, *args, **kwargs)

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await breaker.call_async(func, *args, **kwargs)

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator

def with_retry(max_retries: int = 3, delay: float = 1.0, backoff_factor: float = 2.0,
               exceptions: tuple = (Exception,)):
    """重试装饰器"""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e

                    if attempt < max_retries:
                        current_delay = delay * (backoff_factor ** attempt)
                        logger.warning(f"调用失败，{current_delay}秒后重试 (尝试 {attempt + 1}/{max_retries + 1}): {e}")
                        time.sleep(current_delay)
                    else:
                        logger.error(f"所有重试都失败: {e}")

            raise last_exception

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e

                    if attempt < max_retries:
                        current_delay = delay * (backoff_factor ** attempt)
                        logger.warning(f"异步调用失败，{current_delay}秒后重试 (尝试 {attempt + 1}/{max_retries + 1}): {e}")
                        await asyncio.sleep(current_delay)
                    else:
                        logger.error(f"所有异步重试都失败: {e}")

            raise last_exception

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return wrapper

    return decorator

def with_fallback(fallback_func: Callable = None):
    """降级装饰器"""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.warning(f"主函数失败，使用降级方案: {e}")
                if fallback_func:
                    return fallback_func(*args, **kwargs)
                else:
                    raise

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                logger.warning(f"异步主函数失败，使用降级方案: {e}")
                if fallback_func:
                    if inspect.iscoroutinefunction(fallback_func):
                        return await fallback_func(*args, **kwargs)
                    else:
                        return fallback_func(*args, **kwargs)
                else:
                    raise

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return wrapper

    return decorator

def setup_default_error_handlers():
    """设置默认错误处理器"""

    # 为关键组件注册熔断器
    expert_breaker_config = CircuitBreakerConfig(
        failure_threshold=3,
        timeout=30.0,
        max_retries=2
    )

    router_breaker_config = CircuitBreakerConfig(
        failure_threshold=5,
        timeout=60.0,
        max_retries=1
    )

    fusion_breaker_config = CircuitBreakerConfig(
        failure_threshold=4,
        timeout=45.0,
        max_retries=2
    )

    global_error_handler.register_circuit_breaker("web_expert", expert_breaker_config)
    global_error_handler.register_circuit_breaker("vulnerability_expert", expert_breaker_config)
    global_error_handler.register_circuit_breaker("connection_expert", expert_breaker_config)
    global_error_handler.register_circuit_breaker("intelligent_router", router_breaker_config)
    global_error_handler.register_circuit_breaker("result_fusion", fusion_breaker_config)

# 初始化默认错误处理器
setup_default_error_handlers()
