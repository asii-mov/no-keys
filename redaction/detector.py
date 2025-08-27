import hashlib
import math
import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

from .patterns import PatternManager, SecretPattern


@dataclass
class DetectedSecret:
    original: str
    placeholder: str
    pattern_name: str
    start_pos: int
    end_pos: int


class SecretDetector:
    def __init__(self, pattern_manager: Optional[PatternManager] = None):
        self.pattern_manager = pattern_manager or PatternManager()
        self.keyword_cache = self._build_keyword_cache()
    
    def _build_keyword_cache(self) -> Dict[str, List[str]]:
        cache = {}
        for key, pattern in self.pattern_manager.get_all_patterns().items():
            for keyword in pattern.keywords:
                keyword_lower = keyword.lower()
                if keyword_lower not in cache:
                    cache[keyword_lower] = []
                cache[keyword_lower].append(key)
        return cache
    
    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0.0
        length = len(text)
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _quick_keyword_check(self, text: str) -> List[str]:
        text_lower = text.lower()
        pattern_keys = set()
        
        for keyword, keys in self.keyword_cache.items():
            if keyword in text_lower:
                pattern_keys.update(keys)
        
        return list(pattern_keys)
    
    def _generate_placeholder(self, secret: str, pattern: SecretPattern) -> str:
        hash_suffix = hashlib.md5(secret.encode()).hexdigest()[:4]
        return f"<{pattern.replacement_prefix}_REDACTED_{hash_suffix}>"
    
    def detect(self, text: str) -> List[DetectedSecret]:
        detected = []
        
        # Get candidate patterns based on keywords
        candidate_patterns = self._quick_keyword_check(text)
        
        # Process patterns with keywords first (more specific)
        patterns_to_check = []
        for pattern_key in candidate_patterns:
            pattern = self.pattern_manager.get_pattern(pattern_key)
            if pattern:
                patterns_to_check.append((pattern_key, pattern, True))
        
        # Then check generic patterns if needed
        for pattern_key, pattern in self.pattern_manager.get_all_patterns().items():
            if pattern_key not in candidate_patterns and pattern.min_entropy is not None:
                patterns_to_check.append((pattern_key, pattern, False))
        
        already_found_ranges = []
        
        for pattern_key, pattern, has_keyword in patterns_to_check:
            for match in pattern.pattern.finditer(text):
                secret = match.group(1) if match.groups() else match.group(0)
                start, end = match.span()
                
                # Check for overlapping with already found secrets
                overlap = False
                for existing_start, existing_end in already_found_ranges:
                    if not (end <= existing_start or start >= existing_end):
                        overlap = True
                        break
                
                if overlap:
                    continue
                
                # Skip short secrets except for specific patterns
                if len(secret) < 10 and pattern_key not in ['private_key_header']:
                    continue
                
                # Apply entropy check if specified
                if pattern.min_entropy is not None:
                    entropy = self._calculate_entropy(secret)
                    if entropy < pattern.min_entropy:
                        continue
                    # For generic patterns without keywords, be more strict
                    if not has_keyword and entropy < pattern.min_entropy + 0.5:
                        continue
                
                placeholder = self._generate_placeholder(secret, pattern)
                
                detected.append(DetectedSecret(
                    original=secret,
                    placeholder=placeholder,
                    pattern_name=pattern.name,
                    start_pos=start,
                    end_pos=end
                ))
                
                already_found_ranges.append((start, end))
        
        # Sort by start position (reverse for replacement)
        detected.sort(key=lambda x: x.start_pos, reverse=True)
        
        return detected
    
    def redact(self, text: str) -> Tuple[str, Dict[str, str]]:
        detected = self.detect(text)
        mapping = {}
        redacted_text = text
        
        for secret in detected:
            redacted_text = (
                redacted_text[:secret.start_pos] + 
                secret.placeholder + 
                redacted_text[secret.end_pos:]
            )
            mapping[secret.placeholder] = secret.original
        
        return redacted_text, mapping
    
    def restore(self, text: str, mapping: Dict[str, str]) -> str:
        restored_text = text
        
        # Use fuzzy matching to handle LLM-modified placeholders
        for placeholder, original in mapping.items():
            # First try exact match (fastest path)
            if placeholder in restored_text:
                restored_text = restored_text.replace(placeholder, original)
            else:
                # If exact match fails, try fuzzy matching based on hash suffix
                # Extract the hash suffix from the placeholder
                match = re.search(r'_REDACTED_([a-f0-9]{4})>', placeholder)
                if match:
                    hash_suffix = match.group(1)
                    # Create a pattern that matches any variation of the placeholder
                    # This handles cases where LLMs modify the prefix
                    pattern = r'<[A-Z_]*_REDACTED_' + re.escape(hash_suffix) + r'>'
                    restored_text = re.sub(pattern, original, restored_text)
        
        return restored_text