import inspect
import sys
import types
import unittest


class _NoOpLogger:
    def info(self, *_args, **_kwargs):
        pass

    def warning(self, *_args, **_kwargs):
        pass

    def error(self, *_args, **_kwargs):
        pass


sys.modules.setdefault("loguru", types.SimpleNamespace(logger=_NoOpLogger()))

from src.utils import error_handler


class SyncCircuitBreakerRegressionTests(unittest.TestCase):
    def setUp(self):
        error_handler.global_error_handler = error_handler.ErrorHandler()

    def test_sync_decorator_still_returns_resolved_value(self):
        @error_handler.with_circuit_breaker(
            "sync-success",
            error_handler.CircuitBreakerConfig(max_retries=0),
        )
        def operation():
            return "resolved"

        self.assertEqual(operation(), "resolved")


class AsyncCircuitBreakerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        error_handler.global_error_handler = error_handler.ErrorHandler()

    async def test_async_decorator_returns_resolved_value(self):
        @error_handler.with_circuit_breaker(
            "async-success",
            error_handler.CircuitBreakerConfig(max_retries=0),
        )
        async def operation():
            return "resolved"

        result = await operation()
        try:
            self.assertEqual(result, "resolved")
        finally:
            if inspect.iscoroutine(result):
                result.close()

    async def test_async_decorator_retries_awaited_failures(self):
        attempts = 0

        @error_handler.with_circuit_breaker(
            "async-retry",
            error_handler.CircuitBreakerConfig(
                failure_threshold=3,
                max_retries=1,
                retry_delay=0,
            ),
        )
        async def operation():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("transient")
            return "recovered"

        result = await operation()
        try:
            self.assertEqual(result, "recovered")
            self.assertEqual(attempts, 2)
        finally:
            if inspect.iscoroutine(result):
                result.close()

    async def test_async_decorator_raises_after_retries_are_exhausted(self):
        attempts = 0

        @error_handler.with_circuit_breaker(
            "async-failure",
            error_handler.CircuitBreakerConfig(
                failure_threshold=2,
                max_retries=1,
                retry_delay=0,
            ),
        )
        async def operation():
            nonlocal attempts
            attempts += 1
            raise RuntimeError("persistent")

        try:
            result = await operation()
        except RuntimeError as exc:
            self.assertEqual(str(exc), "persistent")
        else:
            if inspect.iscoroutine(result):
                result.close()
            self.fail("expected the awaited RuntimeError to propagate")

        self.assertEqual(attempts, 2)
