- Follow KISS (Keep it Simple Stupid)

# Repository Structure
This repo has been organized with the following structure:
- `redaction/` - Core library package
- `examples/` - Example implementations and demos
- `docs/planning/` - Project planning and reference documents

# OpenRouter Integration
This repo includes `examples/openrouter_integration.py` that demonstrates real-world usage with OpenRouter API:
- Protects secrets in message content before sending to various models
- Some OpenRouter models train on user data - this middleware prevents secret exposure
- OpenRouter API key stays secure in headers (never redacted)
- Supports both streaming and non-streaming responses

# Setup Instructions
1. Use uv for dependency management: `uv venv && source .venv/bin/activate && uv pip install -r requirements.txt && uv pip install -e .`
2. Set up environment: `echo 'OPENROUTER_API_KEY=your-key' > .env`
3. Run examples: `python examples/openrouter_integration.py` or `python examples/basic_usage.py`

Note: This project uses `pyproject.toml` for packaging. We install dependencies from `requirements.txt` first, then install the package in editable mode with `-e .` to make the `redaction` module importable while keeping it linked to your development files.

# Development Files
- `.env` - Contains API keys (gitignored)
- `.venv/` - Virtual environment (gitignored)
- `.claude/` - Claude-specific files (gitignored)
- All development artifacts are preserved locally but excluded from git