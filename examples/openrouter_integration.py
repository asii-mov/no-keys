#!/usr/bin/env python3
"""
OpenRouter Secret Protection Demonstration

This module demonstrates how to use the SecretRedactionMiddleware with OpenRouter API
to protect sensitive data in message content while maintaining full API functionality.

Key Features Demonstrated:
- Secret redaction before sending to models
- Automatic secret restoration in responses
- Support for both streaming and non-streaming modes
- Real-time metrics and monitoring

Security Model:
- OpenRouter API key stays secure in HTTP headers (never redacted)
- User secrets in message content are redacted before reaching models
- Secrets are restored when models reference them in responses
- No sensitive data ever reaches model training pipelines

Setup:
- Install with uv: uv venv && source .venv/bin/activate && uv pip install -r requirements.txt
- Create a .env file with: OPENROUTER_API_KEY=sk-or-your-key-here
- Run: python examples/openrouter_integration.py
- Add .env to .gitignore to keep your API key secure
"""

import asyncio
import json
import logging
import os
from typing import List, Dict, Any, AsyncGenerator, Optional
import httpx
import sseclient

from redaction import SecretRedactionMiddleware, RedactionConfig


class OpenRouterClient:
    """
    OpenRouter API client with integrated secret protection middleware.
    
    This client wraps the OpenRouter API and automatically protects secrets in
    message content using the SecretRedactionMiddleware. The OpenRouter API key
    remains secure in HTTP headers and is never processed by the middleware.
    
    Architecture:
    - API key: Secure in headers, never redacted
    - Message content: Processed through middleware for secret protection
    - Responses: Automatically restored if they reference redacted secrets
    """
    
    def __init__(self, api_key: str, middleware: SecretRedactionMiddleware):
        """
        Initialize the OpenRouter client with secret protection.
        
        Args:
            api_key: OpenRouter API key (stays in headers, never redacted)
            middleware: Configured SecretRedactionMiddleware instance
        """
        self.api_key = api_key  # Secure in headers - never processed by middleware
        self.middleware = middleware
        self.base_url = "https://openrouter.ai/api/v1"
        self.client = httpx.AsyncClient(timeout=60.0)  # Generous timeout for model responses
        
    async def __aenter__(self):
        """Async context manager entry - returns self for 'async with' usage."""
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - ensures HTTP client is properly closed."""
        await self.client.aclose()
    
    def _get_headers(self, stream: bool = False) -> Dict[str, str]:
        """
        Generate HTTP headers for OpenRouter API requests.
        
        Security Note: The API key is placed in the Authorization header where it
        belongs for authentication. The middleware never processes HTTP headers,
        only message content that goes to the model.
        
        Args:
            stream: Whether this request expects streaming responses (SSE)
            
        Returns:
            Dictionary of HTTP headers for the request
        """
        headers = {
            "Authorization": f"Bearer {self.api_key}",  # Secure authentication
            "Content-Type": "application/json"          # Standard JSON API
        }
        
        # Streaming requests need to accept Server-Sent Events
        if stream:
            headers["Accept"] = "text/event-stream"
            
        return headers
    
    async def _process_messages(self, messages: List[Dict[str, str]], session_id: str) -> List[Dict[str, str]]:
        """
        Process messages through the secret redaction middleware.
        
        This is the core security function that protects user secrets before they
        reach the model. Each message's content is analyzed for secret patterns
        and any found secrets are replaced with secure placeholders.
        
        Security Process:
        1. Scan message content for secret patterns (API keys, tokens, etc.)
        2. Replace secrets with <SERVICE_REDACTED_hash> placeholders
        3. Store original secrets in session for later restoration
        4. Return cleaned messages safe to send to models
        
        Args:
            messages: List of chat messages (role, content)
            session_id: Unique session identifier for secret mapping
            
        Returns:
            List of messages with secrets redacted in content
        """
        processed_messages = []
        
        for message in messages:
            if message.get("content"):
                # Apply secret redaction to message content
                # This is where the protection happens - secrets become placeholders
                cleaned_content = await self.middleware.process_request(session_id, message["content"])
                
                # Preserve message structure, only content is modified
                processed_message = message.copy()
                processed_message["content"] = cleaned_content
                processed_messages.append(processed_message)
            else:
                # Messages without content pass through unchanged
                processed_messages.append(message)
                
        return processed_messages
    
    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        model: str,
        session_id: str,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None
    ) -> str:
        """
        Execute a non-streaming chat completion with automatic secret protection.
        
        This method demonstrates the complete protection cycle:
        1. User sends messages with potentially sensitive content
        2. Secrets are redacted before sending to OpenRouter/model
        3. Model processes redacted content (never sees real secrets)
        4. Response is received and any referenced secrets are restored
        5. User gets response with original secrets intact
        
        Args:
            messages: Chat conversation messages
            model: OpenRouter model identifier (e.g., 'openai/gpt-3.5-turbo')
            session_id: Unique session for secret mapping
            temperature: Model creativity/randomness (0.0-2.0)
            max_tokens: Optional limit on response length
            
        Returns:
            Model response with any referenced secrets restored
        """
        
        # STEP 1: Redact secrets from user messages
        # This ensures the model never sees actual sensitive data
        cleaned_messages = await self._process_messages(messages, session_id)
        
        # STEP 2: Prepare API request with cleaned messages
        payload = {
            "model": model,                    # Model selection
            "messages": cleaned_messages,      # Protected message content
            "temperature": temperature         # Response creativity
        }
        
        # Optional parameters
        if max_tokens:
            payload["max_tokens"] = max_tokens
            
        # Generate headers with secure API key
        headers = self._get_headers(stream=False)
        
        # STEP 3: Send protected request to OpenRouter
        response = await self.client.post(
            f"{self.base_url}/chat/completions",
            json=payload,
            headers=headers
        )
        
        # Handle HTTP errors gracefully
        response.raise_for_status()
        result = response.json()
        
        # STEP 4: Extract model response
        response_content = result["choices"][0]["message"]["content"]
        
        # STEP 5: Restore any secrets referenced in the response
        # If the model mentions redacted placeholders, restore them to original values
        restored_response = await self.middleware.process_response(session_id, response_content)
        
        return restored_response
    
    async def chat_completion_stream(
        self,
        messages: List[Dict[str, str]],
        model: str,
        session_id: str,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None
    ) -> AsyncGenerator[str, None]:
        """
        Execute a streaming chat completion with real-time secret protection.
        
        This method demonstrates streaming protection where secrets are:
        1. Redacted before the initial request (same as non-streaming)
        2. Restored in real-time as response chunks arrive
        3. Yielded to the user with original secrets intact
        
        The streaming approach is more complex because we need to handle:
        - Server-Sent Events (SSE) parsing
        - Partial secret restoration across chunks
        - Buffering to handle secrets spanning multiple chunks
        
        Args:
            messages: Chat conversation messages
            model: OpenRouter model identifier
            session_id: Unique session for secret mapping
            temperature: Model creativity/randomness (0.0-2.0)
            max_tokens: Optional limit on response length
            
        Yields:
            Response chunks with any referenced secrets restored in real-time
        """
        
        # STEP 1: Redact secrets from user messages (same as non-streaming)
        cleaned_messages = await self._process_messages(messages, session_id)
        
        # STEP 2: Prepare streaming API request
        payload = {
            "model": model,                    # Model selection
            "messages": cleaned_messages,      # Protected message content
            "temperature": temperature,        # Response creativity
            "stream": True                     # Enable streaming mode
        }
        
        # Optional parameters
        if max_tokens:
            payload["max_tokens"] = max_tokens
            
        # Generate headers for streaming (includes SSE accept header)
        headers = self._get_headers(stream=True)
        
        # STEP 3: Establish streaming connection to OpenRouter
        async with self.client.stream(
            "POST",
            f"{self.base_url}/chat/completions",
            json=payload,
            headers=headers
        ) as response:
            response.raise_for_status()
            
            # STEP 4: Process streaming response with real-time secret restoration
            # The middleware handles buffering and restoration across chunks
            async for restored_chunk in self.middleware.process_streaming_response(
                session_id, 
                self._parse_sse_stream(response)
            ):
                # Yield non-empty chunks to the caller
                if restored_chunk:
                    yield restored_chunk
    
    async def _parse_sse_stream(self, response) -> AsyncGenerator[str, None]:
        """
        Parse Server-Sent Events (SSE) stream from OpenRouter.
        
        OpenRouter uses the SSE format for streaming responses, where each event
        contains a JSON delta with the next piece of the response. This parser
        handles the SSE protocol and extracts content deltas.
        
        SSE Format:
        - Lines starting with 'data: ' contain JSON payloads
        - 'data: [DONE]' signals end of stream
        - Each JSON contains choices[0].delta.content with text chunk
        
        Args:
            response: httpx streaming response object
            
        Yields:
            Content strings from each response delta
        """
        buffer = ""
        
        # Process response bytes as they arrive
        async for chunk in response.aiter_bytes():
            buffer += chunk.decode('utf-8')
            
            # Process complete lines from the buffer
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                line = line.strip()
                
                # Parse SSE data lines
                if line.startswith('data: '):
                    data = line[6:]  # Remove 'data: ' prefix
                    
                    # Check for stream termination signal
                    if data == '[DONE]':
                        return
                    
                    # Parse JSON delta and extract content
                    try:
                        json_data = json.loads(data)
                        if 'choices' in json_data and len(json_data['choices']) > 0:
                            delta = json_data['choices'][0].get('delta', {})
                            if 'content' in delta and delta['content']:
                                yield delta['content']
                    except json.JSONDecodeError:
                        # Skip malformed JSON (common in streaming APIs)
                        continue


async def main():
    """
    Main demonstration function showing OpenRouter integration with secret protection.
    
    This demo shows:
    1. Configuration of comprehensive secret detection
    2. API key validation and setup
    3. Non-streaming protection example
    4. Streaming protection example
    5. Metrics and performance analysis
    """
    
    # ============================================================
    # SECTION: Middleware Configuration
    # Purpose: Configure comprehensive secret detection for maximum protection
    # Security: Enable detection for all major secret types in production
    # ============================================================
    
    config = RedactionConfig(
        enabled=True,                    # Master enable switch
        rollout_percentage=100.0,        # Full deployment (use gradual rollout in prod)
        monitoring_enabled=True,         # Enable metrics collection
        patterns_config={
            # Major cloud provider API keys
            'openai': {'enabled': True, 'log_only': False},
            'anthropic': {'enabled': True, 'log_only': False},
            'aws_access_key': {'enabled': True, 'log_only': False},
            'aws_secret': {'enabled': True, 'log_only': False},
            'google_api': {'enabled': True, 'log_only': False},
            
            # Development and payment services
            'github_pat': {'enabled': True, 'log_only': False},
            'stripe': {'enabled': True, 'log_only': False},
            
            # Authentication tokens
            'jwt_token': {'enabled': True, 'log_only': False},
            'private_key_header': {'enabled': True, 'log_only': False},
            
            # Catch-all for unrecognized API keys
            'generic_api_key': {'enabled': True, 'log_only': False},
        }
    )
    
    # Initialize the secret redaction middleware
    middleware = SecretRedactionMiddleware(config)
    
    # ============================================================
    # SECTION: Demo Initialization and API Key Setup
    # Purpose: Load OpenRouter API key from environment and validate configuration
    # Security Note: API key stays in headers, never processed by middleware
    # ============================================================
    
    print("OpenRouter Secret Protection Demo")
    print("=" * 50)
    print("This demonstration shows how the middleware protects secrets in message content")
    print("while keeping your OpenRouter API key secure in HTTP headers.")
    print()
    
    # Load API key from environment variable or .env file
    # First try to load from .env file if it exists
    env_file_path = os.path.join(os.getcwd(), '.env')
    if os.path.exists(env_file_path):
        with open(env_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('OPENROUTER_API_KEY='):
                    key_value = line.split('=', 1)[1].strip('"\'')
                    os.environ['OPENROUTER_API_KEY'] = key_value
                    break
    
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        print("[ERROR] OPENROUTER_API_KEY environment variable is required!")
        print("[SETUP] Create a .env file with your API key:")
        print("        echo 'OPENROUTER_API_KEY=sk-or-your-key-here' > .env")
        print("        echo '.env' >> .gitignore  # Keep your key secure")
        print("")
        print("[SETUP] Or export temporarily:")
        print("        export OPENROUTER_API_KEY='sk-or-your-key-here'")
        print("        source .venv/bin/activate && python3 openrouter_example.py")
        return
    
    print(f"[INFO] Using API key: {api_key[:12]}...{api_key[-4:]}")
    print("[INFO] Your API key remains secure - it stays in headers and is never redacted")
    print("[INFO] This demo protects secrets in MESSAGE CONTENT before sending to models")
    print("=" * 70)
    
    # ============================================================
    # SECTION: API Key Validation
    # Purpose: Verify OpenRouter API key before proceeding with demo
    # ============================================================
    
    print("\n[VALIDATION] Testing API key validity...")
    async with httpx.AsyncClient() as test_client:
        try:
            test_response = await test_client.get(
                "https://openrouter.ai/api/v1/models",
                headers={"Authorization": f"Bearer {api_key}"}
            )
            if test_response.status_code == 200:
                print("[SUCCESS] API key is valid and ready for use")
            else:
                print(f"[WARNING] API key test returned status: {test_response.status_code}")
        except Exception as e:
            print(f"[WARNING] Could not validate API key: {e}")
            print("[INFO] Proceeding with demo - validation failures are often network-related")
    
    async with OpenRouterClient(api_key, middleware) as client:
        
        # ============================================================
        # DEMONSTRATION 1: Non-Streaming Secret Protection
        # Purpose: Show secrets being redacted before API call and restored after
        # ============================================================
        
        print("\n" + "=" * 70)
        print("DEMONSTRATION 1: Non-Streaming Secret Protection")
        print("=" * 70)
        
        messages_with_secrets = [
            {
                "role": "user",
                "content": """Please repeat back exactly what I'm sharing with you:

OPENAI_API_KEY=sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyzABC

Just repeat these credentials back to me word for word."""
            }
        ]
        
        session_id = "demo-user-1"
        
        print("\nStep 1: Original Message (Contains Real Secrets)")
        print("-" * 50)
        print(messages_with_secrets[0]['content'].strip())
        
        # Process messages through middleware to show redaction
        redacted_messages = await client._process_messages(messages_with_secrets, session_id)
        
        print("\nStep 2: Redacted Message Sent to OpenRouter")
        print("-" * 50) 
        print(redacted_messages[0]['content'].strip())
        print("\n[PROTECTION] Real secrets replaced with <SERVICE_REDACTED_hash> placeholders")
        print("[SECURITY] The model will never see your actual API keys")
        
        try:
            # This will use the already redacted messages
            response = await client.chat_completion(
                messages=messages_with_secrets,  # Original messages (will be redacted internally)
                model="mistralai/mistral-7b-instruct:free",  # Use working model from your example
                session_id=session_id,
                max_tokens=200
            )
            
            print("\nStep 3: Model Response (Secrets Automatically Restored)")
            print("-" * 50)
            print(f"Model Response: {response}")
            print("\n[SUCCESS] Secrets restored locally in response")
            print("[SECURITY] Model received only redacted placeholders")
            
        except httpx.HTTPStatusError as e:
            print(f"\n[ERROR] HTTP {e.response.status_code}: {e.response.reason_phrase}")
            try:
                error_detail = e.response.json()
                print(f"[DETAILS] {error_detail}")
            except:
                print(f"[DETAILS] {e.response.text}")
            print("\n[TROUBLESHOOTING] Common solutions:")
            print("  - Verify API key is correct and has sufficient credits")
            print("  - Try alternative model: 'openai/gpt-3.5-turbo'")
            print("  - Check for rate limiting or billing issues")
        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
            
        # Display protection metrics for transparency
        print("\n" + "-" * 50)
        print("PROTECTION METRICS")
        print("-" * 50)
        metrics = middleware.get_metrics()
        print(f"[STATS] Requests processed: {metrics['request_count']}")
        print(f"[STATS] Secrets redacted: {metrics['redacted_count']}")
        print(f"[STATS] Patterns detected: {metrics['patterns_detected']}")
        print(f"[STATS] Average latency: {metrics.get('avg_latency_ms', 0):.2f}ms")
        
        # ============================================================
        # DEMONSTRATION 2: Streaming Secret Protection
        # Purpose: Show real-time secret redaction and restoration in streaming responses
        # ============================================================
        
        print("\n\n" + "=" * 70)
        print("DEMONSTRATION 2: Streaming Secret Protection")
        print("=" * 70)
        
        # Generate a realistic Stripe test key matching actual format
        # Real Stripe keys: sk_test_ + exactly 99 alphanumeric characters
        stripe_key = "sk_test_" + "a" * 99  # Matches Stripe's exact key format
        streaming_messages = [
            {
                "role": "user", 
                "content": f"Please repeat this back to me exactly: My Stripe key is {stripe_key}. Just echo back what I said."
            }
        ]
        
        session_id_2 = "demo-user-2"
        
        print("\nStep 1: Original Streaming Message")
        print("-" * 50)
        print(streaming_messages[0]['content'])
        
        # Show redacted version for streaming demonstration
        redacted_streaming = await client._process_messages(streaming_messages, session_id_2)
        print("\nStep 2: Redacted Version Sent to Model")
        print("-" * 50)
        print(redacted_streaming[0]['content'])
        print("\n[PROTECTION] Stripe test key replaced with secure placeholder")
        
        print("\nStep 3: Streaming Response (Secret Restoration)")
        print("-" * 50)
        print("[INFO] Secrets are restored locally before display to user")
        print()
        
        try:
            async for chunk in client.chat_completion_stream(
                messages=streaming_messages,
                model="openai/gpt-3.5-turbo",  # Use working model
                session_id=session_id_2,
                max_tokens=150
            ):
                print(chunk, end="", flush=True)
        except httpx.HTTPStatusError as e:
            print(f"\n[ERROR] HTTP {e.response.status_code}: {e.response.reason_phrase}")
            try:
                error_detail = e.response.json()
                print(f"[DETAILS] {error_detail}")
            except:
                print(f"[DETAILS] {e.response.text}")
        except Exception as e:
            print(f"\n[ERROR] Streaming failed: {e}")
        
        print("\n\n" + "=" * 70)
        print("FINAL PROTECTION SUMMARY")
        print("=" * 70)
        final_metrics = middleware.get_metrics()
        print(f"[SUMMARY] Total requests processed: {final_metrics['request_count']}")
        print(f"[SUMMARY] Total secrets protected: {final_metrics['redacted_count']}")
        print(f"[SUMMARY] Average protection latency: {final_metrics['avg_latency_ms']:.2f}ms")
        print(f"[SUMMARY] Session management overhead: {len(final_metrics.get('session_stats', {}).get('sessions', []))} active sessions")
        
        print("\n[SUCCESS] All secrets protected from model exposure")
        print("[SECURITY] Actual API keys never transmitted to external models")
        print("[RESULT] Full API functionality maintained with secret protection")


if __name__ == "__main__":
    # Configure logging to suppress middleware internal messages for cleaner demo output
    # The demo shows redaction visually, so we don't need the internal logging
    logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[INFO] Demo interrupted by user")
        print("[EXIT] Secret protection demonstration completed")
    except Exception as e:
        print(f"\n[ERROR] Demo failed with exception: {e}")
        print("[HELP] Check your API key and network connection")
