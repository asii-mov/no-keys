from typing import Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class RedactionConfig:
    enabled: bool = True
    rollout_percentage: float = 100.0
    
    max_sessions: int = 1000
    max_secrets_per_session: int = 100
    session_ttl_minutes: int = 30
    
    max_detection_time_ms: int = 10
    max_text_length: int = 100000
    
    patterns_config: Dict[str, Dict[str, Any]] = field(default_factory=lambda: {
        'openai': {'enabled': True, 'log_only': False},
        'anthropic': {'enabled': True, 'log_only': False},
        'aws_access_key': {'enabled': True, 'log_only': False},
        'aws_secret': {'enabled': True, 'log_only': True},
        'github_pat': {'enabled': True, 'log_only': False},
        'stripe': {'enabled': True, 'log_only': False},
        'slack_token': {'enabled': True, 'log_only': False},
        'google_api': {'enabled': True, 'log_only': False},
        'generic_api_key': {'enabled': False, 'log_only': True},
        'hex_secret': {'enabled': False, 'log_only': True},
        'jwt_token': {'enabled': True, 'log_only': False},
        'private_key_header': {'enabled': True, 'log_only': False},
    })
    
    fail_safe: bool = True
    
    monitoring_enabled: bool = True
    metrics_sample_rate: float = 0.01
    
    def is_pattern_enabled(self, pattern_key: str) -> bool:
        if pattern_key not in self.patterns_config:
            return False
        return self.patterns_config[pattern_key].get('enabled', False)
    
    def is_pattern_log_only(self, pattern_key: str) -> bool:
        if pattern_key not in self.patterns_config:
            return True
        return self.patterns_config[pattern_key].get('log_only', False)
    
    def should_process_request(self, session_id: Optional[str] = None) -> bool:
        if not self.enabled:
            return False
        
        if self.rollout_percentage >= 100:
            return True
        
        if session_id:
            hash_value = hash(session_id) % 10000
            return (hash_value / 100) < self.rollout_percentage
        
        return False
    
    def update(self, updates: Dict[str, Any]):
        for key, value in updates.items():
            if hasattr(self, key):
                setattr(self, key, value)