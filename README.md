# Secret Redaction Middleware

A production-ready Python middleware for automatically detecting and redacting secrets in API requests before sending them to model providers. Protects against accidental exposure of API keys, tokens, and credentials.

![nokeys](no-keys.png)


## Features

- **Automatic Detection**: Identifies 12+ common secret patterns (OpenAI, AWS, GitHub, Stripe, etc.)
- **Context-Preserving**: Replaces secrets with descriptive placeholders (`<SERVICE_KEY_REDACTED_hash>`)
- **Session-Based**: Maintains mappings to restore secrets in responses
- **Streaming Support**: Handles streaming responses with proper buffering
- **Configurable**: Per-pattern enable/disable, rollout percentage, monitoring
- **Fast**: <10ms latency with compiled regex patterns
- **Safe**: Fail-safe mode ensures service continuity on errors
- **Zero Config**: Works out of the box with sensible defaults

## Installation

### Quick Start with uv (Recommended)

[uv](https://github.com/astral-sh/uv) is a fast Python package manager that simplifies environment management:

```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone <repository-url>
cd no-keys

# Create virtual environment and install dependencies
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
# Install dependencies first, then install package in editable mode
uv pip install -r requirements.txt
uv pip install -e .

# Set up your OpenRouter API key (for examples)
echo 'OPENROUTER_API_KEY=sk-or-your-key-here' > .env
```

### Alternative: Traditional pip

```bash
# Clone the repository
git clone <repository-url>
cd no-keys

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies first
pip install -r requirements.txt
# Then install package in editable mode
pip install -e .
```

## Quick Start

```python
from redaction import SecretRedactionMiddleware
import asyncio

async def main():
    # Initialize middleware (zero config needed!)
    middleware = SecretRedactionMiddleware()
    
    # Process request (redact secrets)
    session_id = "user-123"
    user_message = "My OpenAI key is sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
    cleaned = await middleware.process_request(session_id, user_message)
    print(cleaned)  # "My OpenAI key is <API_KEY_REDACTED_86e8>"
    
    # Send to model provider (secrets are safe!)
    response = f"I see you provided: {cleaned}"
    
    # Restore secrets in response
    restored = await middleware.process_response(session_id, response)
    print(restored)  # "I see you provided: My OpenAI key is sk-abc123..."

asyncio.run(main())
```

## OpenRouter Integration (Real-World Usage)

OpenRouter provides access to 100+ LLMs, many of which train on user data. The middleware protects your secrets when using these models:

```python
from openrouter_example import OpenRouterClient

async with OpenRouterClient(api_key, middleware) as client:
    # Your secrets are protected in message content
    messages = [{
        "role": "user",
        "content": "Help debug: OPENAI_KEY=sk-abc123... AWS_KEY=AKIA..."
    }]
    
    # Secrets redacted before sending to model
    response = await client.chat_completion(
        messages=messages,
        model="anthropic/claude-3-haiku",
        session_id="user-123"
    )
    # Response may reference redacted content, which gets restored
```

### Key Benefits:
- **Protects from data harvesting**: Models never see your actual secrets
- **API key security**: OpenRouter key stays in headers (not redacted)
- **Streaming support**: Real-time redaction and restoration
- **Model flexibility**: Works with any OpenRouter model
- **Bidirectional protection**: Redact outgoing, restore incoming

### Quick Test:
```bash
# Create virtual environment and install dependencies + package
uv venv && source .venv/bin/activate
uv pip install -r requirements.txt && uv pip install -e .

# Run the OpenRouter demo (requires OpenRouter API key)
python3 examples/openrouter_integration.py
```

## Supported Secret Patterns

| Service | Pattern | Example |
|---------|---------|---------|
| **OpenAI** | `sk-[48 chars]` | `sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz` |
| **Anthropic** | `sk-ant-[95-100 chars]` | `sk-ant-api03-xxxxx...` |
| **AWS Access Key** | `AKIA\|ABIA\|ACCA + [16 chars]` | `AKIAIOSFODNN7EXAMPLE` |
| **GitHub PAT** | `ghp_\|gho_\|ghu_\|ghs_\|ghr_ + [36-255 chars]` | `ghp_1234567890abcdefghij...` |
| **Stripe** | `sk_live_\|sk_test_ + [99 chars]` | `sk_test_abcdefghij...` |
| **Slack** | `xox[bpras]- + [20-146 chars]` | `xoxb-123456789012-...` |
| **Google API** | `AIza + [35 chars]` | `AIzaSyD-1234567890abcd...` |
| **JWT** | `eyJ + base64.base64.base64` | `eyJhbGciOiJIUzI1NiIs...` |
| **Generic API Keys** | High entropy 32+ char strings | Detected via entropy analysis |
| **Private Keys** | PEM headers | `-----BEGIN RSA PRIVATE KEY-----` |

## Configuration

### Basic Configuration

```python
from redaction import RedactionConfig, SecretRedactionMiddleware

config = RedactionConfig(
    enabled=True,                    # Master switch
    rollout_percentage=10.0,         # Start with 10% of traffic
    max_sessions=1000,               # Limit concurrent sessions
    session_ttl_minutes=30,          # Session expiry time
    fail_safe=True,                  # Continue on errors (recommended)
    max_detection_time_ms=10,        # Performance threshold
)

middleware = SecretRedactionMiddleware(config)
```

### Pattern-Specific Control

```python
config = RedactionConfig(
    patterns_config={
        'openai': {'enabled': True, 'log_only': False},      # Redact OpenAI keys
        'aws_secret': {'enabled': True, 'log_only': True},   # Log but don't redact
        'generic_api_key': {'enabled': False},               # Disable generic detection
    }
)
```

### Gradual Rollout

```python
# Start with 0.1% of traffic
config = RedactionConfig(rollout_percentage=0.1)

# Monitor metrics...
# If stable, increase to 5%
config.update({'rollout_percentage': 5.0})

# Continue to 50%, then 100%
config.update({'rollout_percentage': 50.0})
```

## Custom Patterns

Add your own secret patterns for internal APIs or custom services:

```python
from redaction import PatternManager, SecretRedactionMiddleware

pattern_manager = PatternManager()

# Add custom pattern for your internal API
pattern_manager.add_custom_pattern(
    key='internal_api',
    name='Internal API Key',
    pattern=r'\b(internal_[a-zA-Z0-9]{32})\b',
    keywords=['internal', 'api_key'],
    replacement_prefix='INTERNAL_KEY',
    min_entropy=3.0  # Optional entropy threshold
)

# Add database password pattern
pattern_manager.add_custom_pattern(
    key='db_password',
    name='Database Password',
    pattern=r'(?i)(?:password|pwd|pass)\s*[:=]\s*([^\s]+)',
    keywords=['password', 'pwd', 'pass'],
    replacement_prefix='DB_PASSWORD'
)

middleware = SecretRedactionMiddleware(pattern_manager=pattern_manager)
```

## Streaming Support

Handle streaming responses from LLMs:

```python
async def stream_example():
    middleware = SecretRedactionMiddleware()
    session_id = "stream-user"
    
    # Redact request
    message = "My key: sk-abc123..."
    cleaned = await middleware.process_request(session_id, message)
    
    # Simulate streaming response
    async def llm_stream():
        for chunk in ["I see ", "your key: ", cleaned, " - processing..."]:
            yield chunk
    
    # Process streaming response (restores secrets in real-time)
    async for restored_chunk in middleware.process_streaming_response(
        session_id, llm_stream()
    ):
        print(restored_chunk, end='', flush=True)
```

## Monitoring & Metrics

```python
# Get comprehensive metrics
metrics = middleware.get_metrics()

print(f"Performance Metrics:")
print(f"  Requests processed: {metrics['request_count']}")
print(f"  Secrets redacted: {metrics['redacted_count']}")
print(f"  Secrets restored: {metrics['restored_count']}")
print(f"  Errors encountered: {metrics['error_count']}")
print(f"  Average latency: {metrics['avg_latency_ms']:.2f}ms")

print(f"\nPattern Detection:")
for pattern, count in metrics['patterns_detected'].items():
    print(f"  {pattern}: {count} detections")

print(f"\nSession Statistics:")
stats = metrics['session_stats']
print(f"  Active sessions: {stats['session_count']}")
print(f"  Total secrets in memory: {stats['total_secrets']}")
print(f"  Avg secrets/session: {stats['avg_secrets_per_session']:.1f}")

# Reset metrics if needed
middleware.reset_metrics()
```

## Testing

```bash
# Run all tests
python3 -m unittest discover redaction/tests -v

# Run specific test suite
python3 -m unittest redaction.tests.test_detector -v
python3 -m unittest redaction.tests.test_middleware -v

# Run the interactive example
python3 examples/basic_usage.py

# Test with OpenRouter (real-world usage)
# Note: Requires package installation with 'uv pip install -e .'
source .venv/bin/activate && python3 examples/openrouter_integration.py
```

## Project Structure

```
no-keys/
├── redaction/
│   ├── __init__.py           # Package exports
│   ├── middleware.py         # Main middleware orchestration
│   ├── detector.py           # Secret detection engine
│   ├── patterns.py           # Regex patterns & management
│   ├── session_manager.py    # Session storage & TTL
│   ├── config.py             # Configuration management
│   └── tests/
│       ├── test_detector.py  # Detection tests
│       └── test_middleware.py # Integration tests
├── examples/
│   ├── basic_usage.py        # Interactive demo
│   └── openrouter_integration.py # Real-world OpenRouter integration
├── docs/
│   └── planning/             # Project planning documents
│       ├── instructions.md   # Original requirements
│       └── regex.md          # Pattern reference
├── .gitignore                # Git ignore rules
├── CLAUDE.md                 # Claude-specific instructions
├── pyproject.toml            # Modern Python packaging
├── requirements.txt          # Dependencies
└── README.md                 # This file
```

## Production Deployment Guide

### 1. Pre-Production Testing
```python
# Start with aggressive logging, no redaction
config = RedactionConfig(
    patterns_config={
        pattern: {'enabled': True, 'log_only': True}
        for pattern in ['openai', 'aws_access_key', 'github_pat']
    }
)
```

### 2. Gradual Rollout
```python
# Week 1: 0.1% of traffic
config.rollout_percentage = 0.1

# Week 2: 5% if metrics look good
if metrics['error_count'] == 0 and metrics['avg_latency_ms'] < 10:
    config.rollout_percentage = 5.0

# Week 3: 50%
config.rollout_percentage = 50.0

# Week 4: 100% with fail-safe enabled
config.rollout_percentage = 100.0
config.fail_safe = True  # Always recommended
```

### 3. Memory Management
```python
config = RedactionConfig(
    max_sessions=1000,              # Adjust based on traffic
    max_secrets_per_session=100,    # Prevent memory abuse
    session_ttl_minutes=30           # Clean up stale sessions
)
```

### 4. Performance Tuning
```python
config = RedactionConfig(
    max_text_length=100000,          # Skip huge inputs
    max_detection_time_ms=10,        # Alert on slow detection
    monitoring_enabled=True,          # Track metrics
    metrics_sample_rate=0.01         # Sample 1% for analysis
)
```

## Security Considerations

- **Memory-Only Storage**: Secrets never written to disk
- **Automatic Cleanup**: Sessions expire after TTL
- **Partial Hashing**: Placeholders include 4-char hash for debugging
- **No Network Calls**: All detection happens locally
- **Fail-Safe Mode**: Service continues even if redaction fails
- **No Logging of Secrets**: Only patterns and placeholders logged

## Contributing

Contributions are welcome! To add new patterns:

1. Add pattern to `patterns.py`
2. Add tests to `test_detector.py`
3. Update pattern mapping in `middleware.py`
4. Document in README

## Future Enhancements (TODO)

The following features are planned for future releases:

### PII Redaction
- **Personal Identifiers**: Social Security Numbers, Phone Numbers, Email Addresses
- **Financial Data**: Credit Card Numbers, Bank Account Numbers, Routing Numbers
- **Geographic Data**: Full Addresses, ZIP+4 Codes, GPS Coordinates
- **Identity Documents**: Passport Numbers, Driver's License Numbers, ID Numbers
- **Healthcare Data**: Medical Record Numbers, Insurance IDs, Patient IDs
- **Biometric Patterns**: Hash-based detection of potential biometric identifiers

### Enhanced Detection
- **Context-Aware Detection**: Improve accuracy by considering surrounding text context
- **Multi-Language Support**: Extend pattern detection to non-English languages
- **Custom Entropy Thresholds**: Per-pattern entropy configuration for better precision
- **Machine Learning Enhancement**: Optional ML-based detection for complex patterns

### Enterprise Features
- **Audit Logging**: Comprehensive audit trails for compliance requirements
- **Policy Engine**: Rule-based redaction policies with approval workflows
- **Integration APIs**: REST APIs for external system integration
- **Dashboard & Analytics**: Web interface for monitoring and configuration

### Performance Optimizations
- **Batch Processing**: Optimized handling of multiple messages simultaneously
- **Caching Layer**: Pattern compilation caching for improved performance
- **Async Improvements**: Enhanced async processing with worker pools

Contributions in these areas are especially welcome!

## License

MIT License - See LICENSE file for details

## Troubleshooting

### Known Issues
- **Model Placeholder Modification**: Some models may change the redacted placeholders (e.g., `<AWS_ACCESS_KEY_REDACTED_xyz>` to `<AWS_KEY_xyz>` or completely different text), which can prevent proper secret restoration. The middleware uses fuzzy matching to handle common modifications, but extreme changes may still cause restoration to fail.

### Secrets Not Being Redacted?
- Check pattern is enabled: `config.patterns_config['pattern_name']['enabled'] = True`
- Verify pattern matches: Test with `detector.detect(text)`
- Ensure rollout includes session: `config.rollout_percentage = 100`

### High Memory Usage?
- Reduce `max_sessions` and `max_secrets_per_session`
- Decrease `session_ttl_minutes`
- Check for memory leaks with `get_memory_stats()`

### Performance Issues?
- Check `avg_latency_ms` in metrics
- Reduce `max_text_length` for large inputs
- Disable expensive patterns (generic_api_key, hex_secret)

## Support

For issues, questions, or contributions, please open an issue on GitHub.
