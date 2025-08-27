import time
from typing import Dict, Optional
from threading import Lock
from collections import OrderedDict


class SessionManager:
    def __init__(
        self,
        max_sessions: int = 1000,
        max_secrets_per_session: int = 100,
        ttl_minutes: int = 30
    ):
        self.max_sessions = max_sessions
        self.max_secrets_per_session = max_secrets_per_session
        self.ttl_seconds = ttl_minutes * 60
        
        self.sessions: OrderedDict[str, Dict] = OrderedDict()
        self.lock = Lock()
    
    def _cleanup_expired(self):
        current_time = time.time()
        expired_sessions = []
        
        for session_id, session_data in self.sessions.items():
            if current_time - session_data['last_accessed'] > self.ttl_seconds:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.sessions[session_id]
    
    def _enforce_limits(self):
        while len(self.sessions) > self.max_sessions:
            self.sessions.popitem(last=False)
    
    def store_mapping(self, session_id: str, mapping: Dict[str, str]):
        with self.lock:
            self._cleanup_expired()
            
            if session_id not in self.sessions:
                self.sessions[session_id] = {
                    'mapping': {},
                    'last_accessed': time.time(),
                    'created_at': time.time()
                }
            
            session = self.sessions[session_id]
            session['last_accessed'] = time.time()
            
            if len(session['mapping']) + len(mapping) > self.max_secrets_per_session:
                oldest_keys = list(session['mapping'].keys())[
                    :len(mapping) - (self.max_secrets_per_session - len(session['mapping']))
                ]
                for key in oldest_keys:
                    del session['mapping'][key]
            
            session['mapping'].update(mapping)
            
            self.sessions.move_to_end(session_id)
            
            self._enforce_limits()
    
    def get_mapping(self, session_id: str) -> Optional[Dict[str, str]]:
        with self.lock:
            self._cleanup_expired()
            
            if session_id not in self.sessions:
                return None
            
            session = self.sessions[session_id]
            session['last_accessed'] = time.time()
            
            self.sessions.move_to_end(session_id)
            
            return session['mapping'].copy()
    
    def clear_session(self, session_id: str):
        with self.lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
    
    def get_session_count(self) -> int:
        with self.lock:
            self._cleanup_expired()
            return len(self.sessions)
    
    def get_memory_stats(self) -> Dict:
        with self.lock:
            self._cleanup_expired()
            
            total_secrets = sum(
                len(session['mapping']) 
                for session in self.sessions.values()
            )
            
            return {
                'session_count': len(self.sessions),
                'total_secrets': total_secrets,
                'avg_secrets_per_session': (
                    total_secrets / len(self.sessions) 
                    if self.sessions else 0
                )
            }