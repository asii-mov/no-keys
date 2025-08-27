import time
import logging
from typing import Dict, Optional, AsyncGenerator, Any
from dataclasses import dataclass

from .detector import SecretDetector
from .session_manager import SessionManager
from .config import RedactionConfig
from .patterns import PatternManager


logger = logging.getLogger(__name__)


@dataclass
class RedactionMetrics:
    request_count: int = 0
    redacted_count: int = 0
    restored_count: int = 0
    error_count: int = 0
    total_latency_ms: float = 0
    patterns_detected: Dict[str, int] = None
    
    def __post_init__(self):
        if self.patterns_detected is None:
            self.patterns_detected = {}


class SecretRedactionMiddleware:
    def __init__(
        self,
        config: Optional[RedactionConfig] = None,
        pattern_manager: Optional[PatternManager] = None
    ):
        self.config = config or RedactionConfig()
        self.pattern_manager = pattern_manager or PatternManager()
        self.detector = SecretDetector(self.pattern_manager)
        self.session_manager = SessionManager(
            max_sessions=self.config.max_sessions,
            max_secrets_per_session=self.config.max_secrets_per_session,
            ttl_minutes=self.config.session_ttl_minutes
        )
        self.metrics = RedactionMetrics()
    
    def _log_detection(self, session_id: str, pattern_name: str, redacted: bool):
        if self.config.monitoring_enabled:
            logger.info(
                f"Secret detected - session: {session_id}, "
                f"pattern: {pattern_name}, redacted: {redacted}"
            )
            
            if pattern_name not in self.metrics.patterns_detected:
                self.metrics.patterns_detected[pattern_name] = 0
            self.metrics.patterns_detected[pattern_name] += 1
    
    async def process_request(self, session_id: str, content: str) -> str:
        start_time = time.time()
        self.metrics.request_count += 1
        
        try:
            if not self.config.should_process_request(session_id):
                return content
            
            if len(content) > self.config.max_text_length:
                logger.warning(f"Content too long for session {session_id}, skipping redaction")
                return content
            
            # Detect secrets
            detected_secrets = self.detector.detect(content)
            
            if detected_secrets:
                redacted_content = content
                active_mapping = {}
                
                # Process detected secrets in reverse order (for correct replacement)
                for secret in detected_secrets:
                    # Determine pattern key for config check
                    # Map pattern names to config keys
                    pattern_name_map = {
                        'OpenAI API Key': 'openai',
                        'Anthropic API Key': 'anthropic',
                        'AWS Access Key': 'aws_access_key',
                        'AWS Secret': 'aws_secret',
                        'GitHub Personal Access Token': 'github_pat',
                        'Stripe API Key': 'stripe',
                        'Slack Token': 'slack_token',
                        'Google API Key': 'google_api',
                        'Generic API Key': 'generic_api_key',
                        'Hex Secret': 'hex_secret',
                        'JWT Token': 'jwt_token',
                        'Private Key': 'private_key_header',
                    }
                    
                    pattern_key = pattern_name_map.get(secret.pattern_name)
                    if not pattern_key:
                        # For custom patterns, use the placeholder prefix to derive key
                        # e.g., CUSTOM_KEY_REDACTED -> custom_key -> custom_api
                        prefix = secret.placeholder.split('_REDACTED')[0].replace('<', '').lower()
                        # Try common variations
                        if prefix + '_api' in self.config.patterns_config:
                            pattern_key = prefix + '_api'
                        elif prefix in self.config.patterns_config:
                            pattern_key = prefix
                        else:
                            pattern_key = 'generic_api_key'
                    
                    # Check if this pattern is enabled
                    if self.config.is_pattern_enabled(pattern_key):
                        if not self.config.is_pattern_log_only(pattern_key):
                            # Apply redaction
                            redacted_content = (
                                redacted_content[:secret.start_pos] + 
                                secret.placeholder + 
                                redacted_content[secret.end_pos:]
                            )
                            active_mapping[secret.placeholder] = secret.original
                            self._log_detection(session_id, pattern_key, True)
                        else:
                            self._log_detection(session_id, pattern_key, False)
                
                # Store mapping if any secrets were redacted
                if active_mapping:
                    self.session_manager.store_mapping(session_id, active_mapping)
                    self.metrics.redacted_count += len(active_mapping)
                    return redacted_content
            
            return content
            
        except Exception as e:
            self.metrics.error_count += 1
            logger.error(f"Error processing request for session {session_id}: {e}")
            
            if self.config.fail_safe:
                return content
            raise
            
        finally:
            elapsed_ms = (time.time() - start_time) * 1000
            self.metrics.total_latency_ms += elapsed_ms
            
            if elapsed_ms > self.config.max_detection_time_ms:
                logger.warning(
                    f"Slow redaction for session {session_id}: {elapsed_ms:.2f}ms"
                )
    
    async def process_response(self, session_id: str, content: str) -> str:
        start_time = time.time()
        
        try:
            if not self.config.should_process_request(session_id):
                return content
            
            mapping = self.session_manager.get_mapping(session_id)
            if not mapping:
                return content
            
            restored_content = self.detector.restore(content, mapping)
            self.metrics.restored_count += len(mapping)
            
            return restored_content
            
        except Exception as e:
            self.metrics.error_count += 1
            logger.error(f"Error processing response for session {session_id}: {e}")
            
            if self.config.fail_safe:
                return content
            raise
            
        finally:
            elapsed_ms = (time.time() - start_time) * 1000
            self.metrics.total_latency_ms += elapsed_ms
    
    async def process_streaming_response(
        self,
        session_id: str,
        stream: AsyncGenerator[str, None]
    ) -> AsyncGenerator[str, None]:
        buffer = ""
        mapping = self.session_manager.get_mapping(session_id)
        
        if not mapping:
            async for chunk in stream:
                yield chunk
            return
        
        max_placeholder_len = max(len(p) for p in mapping.keys())
        
        async for chunk in stream:
            buffer += chunk
            
            while len(buffer) > max_placeholder_len * 2:
                safe_length = len(buffer) - max_placeholder_len
                safe_chunk = buffer[:safe_length]
                
                restored_chunk = self.detector.restore(safe_chunk, mapping)
                yield restored_chunk
                
                buffer = buffer[safe_length:]
        
        if buffer:
            restored_buffer = self.detector.restore(buffer, mapping)
            yield restored_buffer
    
    def clear_session(self, session_id: str):
        self.session_manager.clear_session(session_id)
    
    def get_metrics(self) -> Dict[str, Any]:
        avg_latency = (
            self.metrics.total_latency_ms / self.metrics.request_count
            if self.metrics.request_count > 0 else 0
        )
        
        return {
            'request_count': self.metrics.request_count,
            'redacted_count': self.metrics.redacted_count,
            'restored_count': self.metrics.restored_count,
            'error_count': self.metrics.error_count,
            'avg_latency_ms': avg_latency,
            'patterns_detected': dict(self.metrics.patterns_detected),
            'session_stats': self.session_manager.get_memory_stats()
        }
    
    def reset_metrics(self):
        self.metrics = RedactionMetrics()