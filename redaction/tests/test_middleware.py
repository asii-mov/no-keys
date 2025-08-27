import unittest
import asyncio
from ..middleware import SecretRedactionMiddleware
from ..config import RedactionConfig


class TestSecretRedactionMiddleware(unittest.TestCase):
    def setUp(self):
        self.config = RedactionConfig(
            enabled=True,
            rollout_percentage=100.0,
            fail_safe=True
        )
        self.middleware = SecretRedactionMiddleware(config=self.config)
    
    def test_process_request_with_secret(self):
        session_id = "test-session-123"
        content = "My API key is sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
        
        loop = asyncio.get_event_loop()
        redacted = loop.run_until_complete(
            self.middleware.process_request(session_id, content)
        )
        
        self.assertNotIn('sk-abc123', redacted)
        self.assertIn('OPENAI_KEY_REDACTED', redacted)
        
        mapping = self.middleware.session_manager.get_mapping(session_id)
        self.assertIsNotNone(mapping)
        self.assertEqual(len(mapping), 1)
    
    def test_process_response_restoration(self):
        session_id = "test-session-456"
        original = "My key: sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
        
        loop = asyncio.get_event_loop()
        
        redacted = loop.run_until_complete(
            self.middleware.process_request(session_id, original)
        )
        
        response = f"You provided: {redacted}"
        
        restored = loop.run_until_complete(
            self.middleware.process_response(session_id, response)
        )
        
        self.assertIn('sk-abc123', restored)
        self.assertNotIn('OPENAI_KEY_REDACTED', restored)
    
    def test_rollout_percentage(self):
        config = RedactionConfig(
            enabled=True,
            rollout_percentage=0.0
        )
        middleware = SecretRedactionMiddleware(config=config)
        
        content = "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
        
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(
            middleware.process_request("session-789", content)
        )
        
        self.assertEqual(result, content)
    
    def test_disabled_pattern(self):
        config = RedactionConfig(
            enabled=True,
            patterns_config={
                'openai': {'enabled': False, 'log_only': False}
            }
        )
        middleware = SecretRedactionMiddleware(config=config)
        
        content = "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
        
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(
            middleware.process_request("session-abc", content)
        )
        
        self.assertEqual(result, content)
    
    def test_log_only_pattern(self):
        self.config.patterns_config['openai'] = {
            'enabled': True,
            'log_only': True
        }
        
        content = "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
        
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(
            self.middleware.process_request("session-log", content)
        )
        
        self.assertEqual(result, content)
    
    def test_multiple_sessions(self):
        loop = asyncio.get_event_loop()
        
        content1 = "Key1: sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
        content2 = "Key2: ghp_1234567890abcdefghijklmnopqrstuvwxyzABC"
        
        redacted1 = loop.run_until_complete(
            self.middleware.process_request("session-1", content1)
        )
        redacted2 = loop.run_until_complete(
            self.middleware.process_request("session-2", content2)
        )
        
        self.assertIn('OPENAI_KEY_REDACTED', redacted1)
        self.assertIn('GITHUB_TOKEN_REDACTED', redacted2)
        
        mapping1 = self.middleware.session_manager.get_mapping("session-1")
        mapping2 = self.middleware.session_manager.get_mapping("session-2")
        
        self.assertEqual(len(mapping1), 1)
        self.assertEqual(len(mapping2), 1)
        self.assertNotEqual(mapping1, mapping2)
    
    def test_fail_safe_mode(self):
        def failing_detect(*args, **kwargs):
            raise Exception("Detection failed!")
        
        self.middleware.detector.detect = failing_detect
        
        content = "Some content with secrets"
        
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(
            self.middleware.process_request("fail-session", content)
        )
        
        self.assertEqual(result, content)
        self.assertEqual(self.middleware.metrics.error_count, 1)
    
    def test_content_too_long(self):
        self.config.max_text_length = 10
        
        content = "This is a very long content that exceeds the limit"
        
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(
            self.middleware.process_request("long-session", content)
        )
        
        self.assertEqual(result, content)
    
    def test_metrics_tracking(self):
        loop = asyncio.get_event_loop()
        
        for i in range(5):
            content = f"Key {i}: sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234y{i}"
            loop.run_until_complete(
                self.middleware.process_request(f"metrics-session-{i}", content)
            )
        
        metrics = self.middleware.get_metrics()
        
        self.assertEqual(metrics['request_count'], 5)
        self.assertEqual(metrics['redacted_count'], 5)
        self.assertGreater(metrics['avg_latency_ms'], 0)
        self.assertIn('openai', metrics['patterns_detected'])
    
    def test_clear_session(self):
        session_id = "clear-session"
        content = "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
        
        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            self.middleware.process_request(session_id, content)
        )
        
        mapping = self.middleware.session_manager.get_mapping(session_id)
        self.assertIsNotNone(mapping)
        
        self.middleware.clear_session(session_id)
        
        mapping = self.middleware.session_manager.get_mapping(session_id)
        self.assertIsNone(mapping)
    
    async def test_streaming_response(self):
        session_id = "stream-session"
        original = "Key: sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
        
        redacted = await self.middleware.process_request(session_id, original)
        
        async def mock_stream():
            parts = redacted.split()
            for part in parts:
                yield part + " "
        
        result = ""
        async for chunk in self.middleware.process_streaming_response(
            session_id, mock_stream()
        ):
            result += chunk
        
        self.assertIn('sk-abc123', result.strip())
        self.assertNotIn('OPENAI_KEY_REDACTED', result)
    
    def test_reset_metrics(self):
        self.middleware.metrics.request_count = 100
        self.middleware.metrics.error_count = 5
        
        self.middleware.reset_metrics()
        
        self.assertEqual(self.middleware.metrics.request_count, 0)
        self.assertEqual(self.middleware.metrics.error_count, 0)


if __name__ == '__main__':
    unittest.main()