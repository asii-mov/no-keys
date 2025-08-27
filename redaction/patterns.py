import re
from dataclasses import dataclass
from typing import Dict, List, Pattern, Optional


@dataclass
class SecretPattern:
    name: str
    pattern: Pattern
    keywords: List[str]
    min_entropy: Optional[float] = None
    replacement_prefix: Optional[str] = None


SECRET_PATTERNS = {
    'openai': SecretPattern(
        name='OpenAI API Key',
        pattern=re.compile(r'\b(sk-[a-zA-Z0-9]{48})\b'),
        keywords=['sk-', 'openai'],
        replacement_prefix='OPENAI_KEY'
    ),
    
    'anthropic': SecretPattern(
        name='Anthropic API Key',
        pattern=re.compile(r'\b(sk-ant-[a-zA-Z0-9\-_=+/]{95,100})\b'),
        keywords=['sk-ant', 'anthropic'],
        replacement_prefix='ANTHROPIC_KEY'
    ),
    
    'aws_access_key': SecretPattern(
        name='AWS Access Key',
        pattern=re.compile(r'\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b'),
        keywords=['AKIA', 'ABIA', 'ACCA', 'aws'],
        replacement_prefix='AWS_ACCESS_KEY'
    ),
    
    'aws_secret': SecretPattern(
        name='AWS Secret',
        pattern=re.compile(r'\b([A-Za-z0-9+/]{40})\b'),
        keywords=['aws', 'secret'],
        min_entropy=3.0,
        replacement_prefix='AWS_SECRET'
    ),
    
    'github_pat': SecretPattern(
        name='GitHub Personal Access Token',
        pattern=re.compile(r'\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})\b'),
        keywords=['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_'],
        replacement_prefix='GITHUB_TOKEN'
    ),
    
    'stripe': SecretPattern(
        name='Stripe API Key',
        pattern=re.compile(r'\b((?:sk|pk|rk)_(?:live|test)_[a-zA-Z0-9]{99})\b'),
        keywords=['sk_live_', 'sk_test_', 'pk_live_', 'pk_test_', 'rk_live_', 'rk_test_'],
        replacement_prefix='STRIPE_KEY'
    ),
    
    'slack_token': SecretPattern(
        name='Slack Token',
        pattern=re.compile(r'\b(xox[bpras]-[0-9a-zA-Z\-]{20,146})\b'),
        keywords=['xoxb', 'xoxp', 'xoxr', 'xoxa', 'xoxs', 'slack'],
        replacement_prefix='SLACK_TOKEN'
    ),
    
    'google_api': SecretPattern(
        name='Google API Key',
        pattern=re.compile(r'\b(AIza[0-9a-zA-Z_-]{35})\b'),
        keywords=['AIza', 'google'],
        replacement_prefix='GOOGLE_API_KEY'
    ),
    
    'generic_api_key': SecretPattern(
        name='Generic API Key',
        pattern=re.compile(r'\b([a-zA-Z0-9]{32,})\b'),
        keywords=['api', 'key', 'token', 'secret'],
        min_entropy=3.5,
        replacement_prefix='API_KEY'
    ),
    
    'hex_secret': SecretPattern(
        name='Hex Secret',
        pattern=re.compile(r'\b([a-f0-9]{32,})\b'),
        keywords=['secret', 'token', 'key'],
        min_entropy=2.5,
        replacement_prefix='HEX_SECRET'
    ),
    
    'jwt_token': SecretPattern(
        name='JWT Token',
        pattern=re.compile(r'\b(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b'),
        keywords=['jwt', 'bearer', 'authorization'],
        replacement_prefix='JWT_TOKEN'
    ),
    
    'private_key_header': SecretPattern(
        name='Private Key',
        pattern=re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        keywords=['BEGIN', 'PRIVATE', 'KEY'],
        replacement_prefix='PRIVATE_KEY'
    ),
}


class PatternManager:
    def __init__(self):
        self.patterns = SECRET_PATTERNS.copy()
        self.custom_patterns: Dict[str, SecretPattern] = {}
    
    def add_custom_pattern(
        self,
        key: str,
        name: str,
        pattern: str,
        keywords: List[str],
        replacement_prefix: Optional[str] = None,
        min_entropy: Optional[float] = None
    ):
        self.custom_patterns[key] = SecretPattern(
            name=name,
            pattern=re.compile(pattern),
            keywords=keywords,
            min_entropy=min_entropy,
            replacement_prefix=replacement_prefix or key.upper()
        )
    
    def get_all_patterns(self) -> Dict[str, SecretPattern]:
        return {**self.patterns, **self.custom_patterns}
    
    def get_pattern(self, key: str) -> Optional[SecretPattern]:
        return self.patterns.get(key) or self.custom_patterns.get(key)