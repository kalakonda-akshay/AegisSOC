"""
AegisSOC AI Security Analyst Package
"""

from app.ai.context_builder import ContextBuilder
from app.ai.prompt_templates import INVESTIGATION_USER_PROMPT, SYSTEM_ANALYST_GUARDRAILS
from app.ai.provider import (
    AnthropicProvider,
    GeminiProvider,
    LLMProvider,
    LLMResponse,
    NullProvider,
    OllamaProvider,
    OpenAIProvider,
    get_llm_provider,
)
from app.ai.sanitizer import (
    format_untrusted_evidence,
    mask_sensitive_data,
    sanitize_untrusted_input,
)

__all__ = [
    "LLMProvider",
    "LLMResponse",
    "NullProvider",
    "OpenAIProvider",
    "GeminiProvider",
    "AnthropicProvider",
    "OllamaProvider",
    "get_llm_provider",
    "sanitize_untrusted_input",
    "format_untrusted_evidence",
    "mask_sensitive_data",
    "SYSTEM_ANALYST_GUARDRAILS",
    "INVESTIGATION_USER_PROMPT",
    "ContextBuilder",
]
