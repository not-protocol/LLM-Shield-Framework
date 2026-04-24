"""
LLM Shield — Provider Registry
v1.1 Addition

All LLM provider classes live here.
Adding a new provider in v2 = add one class + one registry entry. Nothing else changes.

Supported Providers:
  - anthropic  (Claude)
  - openai     (GPT-4o, GPT-4, etc.)
  - gemini     (Google Gemini)
  - groq       (Llama, Mixtral via Groq API — ultra fast)

Author: Rohan Kumar
Project: LLM Shield v1.1
"""

import os
from abc import ABC, abstractmethod
from typing import Optional


# ─────────────────────────────────────────────
#  BASE PROVIDER
# ─────────────────────────────────────────────

class BaseProvider(ABC):
    """
    Every provider must implement this interface.
    llm_connector calls provider.call() — doesn't care which SDK is underneath.
    """

    name: str = "base"
    default_model: str = ""
    env_key: str = ""

    def get_api_key(self) -> Optional[str]:
        return os.getenv(self.env_key)

    def check_available(self) -> tuple[bool, str]:
        """
        Returns (is_available, error_message).
        Checks: SDK installed + API key present.
        """
        # Check SDK
        try:
            self._import_sdk()
        except ImportError:
            return False, (
                f"SDK not installed. Run: pip install {self._sdk_package()}"
            )
        # Check key
        if not self.get_api_key():
            return False, (
                f"{self.env_key} not found in .env"
            )
        return True, ""

    @abstractmethod
    def _import_sdk(self): ...

    @abstractmethod
    def _sdk_package(self) -> str: ...

    @abstractmethod
    def call(
        self,
        system_prompt: str,
        combined_input: str,
        model: str,
        max_tokens: int,
    ) -> tuple[str, int, int]:
        """
        Call the LLM. Returns (response_text, input_tokens, output_tokens).
        """
        ...


# ─────────────────────────────────────────────
#  ANTHROPIC — Claude
# ─────────────────────────────────────────────

class AnthropicProvider(BaseProvider):
    name = "anthropic"
    default_model = "claude-sonnet-4-20250514"
    env_key = "ANTHROPIC_API_KEY"

    def _import_sdk(self):
        import anthropic
        return anthropic

    def _sdk_package(self) -> str:
        return "anthropic"

    def call(self, system_prompt, combined_input, model, max_tokens):
        import anthropic

        client = anthropic.Anthropic(api_key=self.get_api_key())
        message = client.messages.create(
            model=model or self.default_model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": combined_input}],
        )
        response_text = message.content[0].text if message.content else ""
        return response_text, message.usage.input_tokens, message.usage.output_tokens


# ─────────────────────────────────────────────
#  OPENAI — GPT-4o, GPT-4, etc.
# ─────────────────────────────────────────────

class OpenAIProvider(BaseProvider):
    name = "openai"
    default_model = "gpt-4o"
    env_key = "OPENAI_API_KEY"

    def _import_sdk(self):
        import openai
        return openai

    def _sdk_package(self) -> str:
        return "openai"

    def call(self, system_prompt, combined_input, model, max_tokens):
        from openai import OpenAI

        client = OpenAI(api_key=self.get_api_key())
        response = client.chat.completions.create(
            model=model or self.default_model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": combined_input},
            ],
        )
        response_text = response.choices[0].message.content or ""
        usage = response.usage
        return response_text, usage.prompt_tokens, usage.completion_tokens


# ─────────────────────────────────────────────
#  GOOGLE GEMINI
# ─────────────────────────────────────────────

class GeminiProvider(BaseProvider):
    name = "gemini"
    default_model = "gemini-1.5-flash"
    env_key = "GEMINI_API_KEY"

    def _import_sdk(self):
        import google.generativeai
        return google.generativeai

    def _sdk_package(self) -> str:
        return "google-generativeai"

    def call(self, system_prompt, combined_input, model, max_tokens):
        import google.generativeai as genai

        genai.configure(api_key=self.get_api_key())
        model_obj = genai.GenerativeModel(
            model_name=model or self.default_model,
            system_instruction=system_prompt,
        )
        response = model_obj.generate_content(
            combined_input,
            generation_config=genai.types.GenerationConfig(max_output_tokens=max_tokens),
        )
        response_text = response.text or ""
        # Gemini doesn't always expose token counts — safe fallback
        try:
            in_tokens  = response.usage_metadata.prompt_token_count
            out_tokens = response.usage_metadata.candidates_token_count
        except Exception:
            in_tokens  = len(combined_input.split())
            out_tokens = len(response_text.split())
        return response_text, in_tokens, out_tokens


# ─────────────────────────────────────────────
#  GROQ — Llama, Mixtral (ultra-fast inference)
# ─────────────────────────────────────────────

class GroqProvider(BaseProvider):
    name = "groq"
    default_model = "llama-3.1-70b-versatile"
    env_key = "GROQ_API_KEY"

    def _import_sdk(self):
        import groq
        return groq

    def _sdk_package(self) -> str:
        return "groq"

    def call(self, system_prompt, combined_input, model, max_tokens):
        from groq import Groq

        client = Groq(api_key=self.get_api_key())
        response = client.chat.completions.create(
            model=model or self.default_model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": combined_input},
            ],
        )
        response_text = response.choices[0].message.content or ""
        usage = response.usage
        return response_text, usage.prompt_tokens, usage.completion_tokens


# ─────────────────────────────────────────────
#  PROVIDER REGISTRY
#  Adding v2 provider = one new class + one line here
# ─────────────────────────────────────────────

PROVIDER_REGISTRY: dict[str, BaseProvider] = {
    "anthropic": AnthropicProvider(),
    "openai":    OpenAIProvider(),
    "gemini":    GeminiProvider(),
    "groq":      GroqProvider(),
}

PROVIDER_NAMES = list(PROVIDER_REGISTRY.keys())


def get_provider(name: str) -> BaseProvider:
    """Fetch provider by name. Raises ValueError if unknown."""
    if name not in PROVIDER_REGISTRY:
        raise ValueError(
            f"Unknown provider '{name}'. "
            f"Available: {', '.join(PROVIDER_NAMES)}"
        )
    return PROVIDER_REGISTRY[name]


def auto_detect_provider() -> Optional[str]:
    """
    Scan .env for whichever API key exists first.
    Priority: anthropic → openai → gemini → groq
    Returns provider name or None if no key found.
    """
    for name, provider in PROVIDER_REGISTRY.items():
        if provider.get_api_key():
            return name
    return None


def list_available() -> list[dict]:
    """Returns status of all providers — useful for shield.py info command."""
    results = []
    for name, provider in PROVIDER_REGISTRY.items():
        available, error = provider.check_available()
        results.append({
            "name":          name,
            "default_model": provider.default_model,
            "env_key":       provider.env_key,
            "available":     available,
            "error":         error,
        })
    return results
