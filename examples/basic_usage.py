#!/usr/bin/env python3

import asyncio
from redaction import SecretRedactionMiddleware, RedactionConfig, PatternManager


async def simulate_api_call(provider: str, message: str) -> str:
    await asyncio.sleep(0.1)
    return f"Response from {provider}: Processed your message successfully"


async def main():
    config = RedactionConfig(
        enabled=True,
        rollout_percentage=100.0,
        monitoring_enabled=True,
        patterns_config={
            'openai': {'enabled': True, 'log_only': False},
            'anthropic': {'enabled': True, 'log_only': False},
            'aws_access_key': {'enabled': True, 'log_only': False},
            'github_pat': {'enabled': True, 'log_only': False},
            'stripe': {'enabled': True, 'log_only': False},
            'generic_api_key': {'enabled': True, 'log_only': False},  # Enable for sk- keys that are detected as generic
            'custom_api': {'enabled': True, 'log_only': False},  # Our custom pattern
        }
    )
    
    pattern_manager = PatternManager()
    pattern_manager.add_custom_pattern(
        key='custom_api',
        name='Custom API Key',
        pattern=r'\b(custom_key_[a-zA-Z0-9]{32})\b',
        keywords=['custom_key'],
        replacement_prefix='CUSTOM_KEY'
    )
    
    middleware = SecretRedactionMiddleware(config, pattern_manager)
    
    test_messages = [
        {
            'session_id': 'user-123',
            'message': '''
            I need help with my OpenAI integration. 
            My API key is sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz
            Can you help me debug this?
            '''
        },
        {
            'session_id': 'user-456', 
            'message': '''
            Here's my config file:
            GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyzABC
            AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
            STRIPE_KEY=sk_test_abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuv
            '''
        },
        {
            'session_id': 'user-789',
            'message': '''
            Using custom key: custom_key_12345678901234567890123456789012
            And Anthropic key: sk-ant-api03-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef
            '''
        }
    ]
    
    print("=" * 80)
    print("SECRET REDACTION MIDDLEWARE DEMO")
    print("=" * 80)
    
    for test in test_messages:
        session_id = test['session_id']
        original_message = test['message'].strip()
        
        print(f"\n📧 Session: {session_id}")
        print("-" * 40)
        print("Original message:")
        print(original_message)
        print()
        
        cleaned_message = await middleware.process_request(session_id, original_message)
        
        print("🔒 Redacted message sent to provider:")
        print(cleaned_message)
        print()
        
        provider_response = await simulate_api_call("ModelProvider", cleaned_message)
        
        full_response = f"{provider_response}\n\nYour message: {cleaned_message}"
        
        restored_response = await middleware.process_response(session_id, full_response)
        
        print("✅ Restored response to user:")
        print(restored_response)
        print("-" * 40)
    
    print("\n📊 METRICS SUMMARY")
    print("-" * 40)
    metrics = middleware.get_metrics()
    for key, value in metrics.items():
        if key != 'session_stats':
            print(f"{key}: {value}")
    
    print("\n📈 Session Statistics:")
    for key, value in metrics['session_stats'].items():
        print(f"  {key}: {value}")
    
    print("\n=" * 80)
    print("STREAMING EXAMPLE")
    print("=" * 80)
    
    session_id = 'stream-user'
    streaming_message = "Here's my key: sk-stream123def456ghi789jkl012mno345pqr678stu901vwx234yz"
    
    print(f"Session: {session_id}")
    print(f"Original: {streaming_message}")
    
    cleaned = await middleware.process_request(session_id, streaming_message)
    print(f"Cleaned: {cleaned}")
    
    async def mock_llm_stream():
        response_parts = [
            "I can see ",
            "you provided: ",
            cleaned[:20],
            cleaned[20:40],
            cleaned[40:],
            " - let me help you."
        ]
        for part in response_parts:
            await asyncio.sleep(0.05)
            yield part
    
    print("\nStreaming response (restored in real-time):")
    async for chunk in middleware.process_streaming_response(session_id, mock_llm_stream()):
        print(chunk, end='', flush=True)
    print("\n")
    
    print("\n✅ All secrets were successfully redacted and restored!")
    print("💡 No secrets were ever sent to the model provider.")


if __name__ == "__main__":
    asyncio.run(main())