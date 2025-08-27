Here's a prompt for Claude Code to plan the implementation:

---

**Project: In-Product Secret Redaction Middleware**

## Context
We're building a secret redaction feature for our API product that routes requests to various model providers (OpenAI, Anthropic, etc.). The concern is that some providers train on data, and users may accidentally include sensitive details like API keys in their prompts.

## Core Solution
Implement middleware that:
1. Detects secrets in incoming requests using regex patterns (similar to TruffleHog)
2. Replaces them with placeholders like `<OPENAI_KEY_REDACTED_7d4f>` 
3. Stores the mapping in memory (session-based)
4. Sends cleaned text to model providers
5. Restores secrets in responses before returning to user

## Key Design Decisions Already Made
- **In-product feature**, not a standalone library
- **Server-side middleware** in our API, transparent to users
- **Target audience**: Developers and SMBs who want simple, automatic protection
- **Simplicity over perfection**: Better to catch 80% with simple regex than complex solutions
- **No user integration required**: Works automatically at API level
- **Context-preserving replacements**: Use `<SERVICE_TYPE_REDACTED_hash>` format so models understand context

## Technical Requirements
- Support Python (primary), with JS/TS considerations
- In-memory session-based storage for secret mappings
- Start with patterns for: OpenAI, Anthropic, AWS, GitHub, Stripe, high-entropy generic
- Must handle streaming responses (buffer and restore)
- Must handle structured data (JSON, code blocks) without breaking them
- Clean up session maps after expiry
- Fast-fail safe: if restoration fails, return original

## Implementation Approach
```python
# Middleware intercepts at API boundary
@app.post("/chat")
async def chat(request):
    cleaned = redaction.process_request(request.session_id, request.message)
    response = await model_provider.chat(cleaned)  
    restored = redaction.process_response(request.session_id, response)
    return {"response": restored}
```

## Need You To Plan
1. **Project structure** for this middleware component
2. **Pattern management system** - how to store, update, and load regex patterns
3. **Session mapping implementation** - efficient in-memory storage with cleanup
4. **Test strategy** - how to test without real secrets
5. **Rollout plan** - feature flags, monitoring, gradual enablement
6. **API for enterprise customers** to add custom patterns
7. **Performance considerations** - this runs on every request
8. **Monitoring/metrics** - what to track (redaction counts, pattern hits, performance impact)

## Success Criteria
- Zero configuration needed for basic users
- Less than 10ms latency addition
- Catches common API key formats
- Doesn't break JSON/code structures
- Session maps don't cause memory leaks

## Not Needed Now (Future)
- Persistence across sessions
- Client-side SDKs
- Audit logging (except basic metrics)

Please create a detailed technical plan for implementing this as production-ready middleware in our API stack. Focus on pragmatic, shippable solutions that we can deploy quickly and iterate on.
