"""
LLM Shield — LLM Connector
Module 2 of 5  ·  v1.1 — Multi-Provider Edition

Routes prompts to the correct LLM provider via the provider registry.
Supports: Anthropic, OpenAI, Gemini, Groq — and any future provider
added to providers.py.

Author: Rohan Kumar
Project: LLM Shield v1.1
"""

import os
import time
from dataclasses import dataclass, field
from typing import Optional, Literal
from dotenv import load_dotenv

load_dotenv()

from providers import get_provider, auto_detect_provider, PROVIDER_NAMES

InjectionMode = Literal["append", "prepend", "external", "system"]


@dataclass
class LLMResponse:
    system_prompt:  str
    user_prompt:    str
    injection:      str
    injection_mode: InjectionMode
    combined_input: str
    response_text:  str
    provider:       str = "unknown"
    model:          str = "unknown"
    input_tokens:   int = 0
    output_tokens:  int = 0
    latency_ms:     float = 0.0
    error:          Optional[str] = None
    success:        bool = True

    def to_dict(self) -> dict:
        return {
            "success":        self.success,
            "provider":       self.provider,
            "model":          self.model,
            "injection_mode": self.injection_mode,
            "response_text":  self.response_text,
            "combined_input": self.combined_input,
            "input_tokens":   self.input_tokens,
            "output_tokens":  self.output_tokens,
            "latency_ms":     round(self.latency_ms, 2),
            "error":          self.error,
        }

    def __str__(self) -> str:
        status = "OK" if self.success else f"ERROR: {self.error}"
        lines = [
            "─" * 52,
            "  LLM CONNECTOR RESULT",
            "─" * 52,
            f"  Status         : {status}",
            f"  Provider       : {self.provider}",
            f"  Model          : {self.model}",
            f"  Injection Mode : {self.injection_mode}",
            f"  Latency        : {self.latency_ms:.0f}ms",
            f"  Tokens (in/out): {self.input_tokens} / {self.output_tokens}",
            "  ─ Combined Input ──────────────────────",
        ]
        for line in self.combined_input[:400].split("\n"):
            lines.append(f"  {line}")
        if len(self.combined_input) > 400:
            lines.append("  ... [truncated]")
        lines += ["  ─ Model Response ──────────────────────"]
        for line in self.response_text[:400].split("\n"):
            lines.append(f"  {line}")
        if len(self.response_text) > 400:
            lines.append("  ... [truncated]")
        lines.append("─" * 52)
        return "\n".join(lines)


def _combine_inputs(user_prompt: str, injection: str, mode: InjectionMode) -> str:
    if not injection.strip():
        return user_prompt
    if mode == "append":
        return f"{user_prompt}\n\n{injection}"
    elif mode == "prepend":
        return f"{injection}\n\n{user_prompt}"
    elif mode == "external":
        return (
            f"{user_prompt}\n\n"
            f"[Retrieved Context from External Source]:\n"
            f"---\n{injection}\n---"
        )
    elif mode == "system":
        return f"<s>\n{injection}\n</s>\n\n{user_prompt}"
    return f"{user_prompt}\n\n{injection}"


def send_to_llm(
    user_prompt:    str,
    injection:      str = "",
    system_prompt:  str = "You are a helpful AI assistant. Answer user questions clearly and concisely.",
    injection_mode: InjectionMode = "append",
    provider_name:  str = "auto",
    model:          str = "",
    max_tokens:     int = 512,
) -> LLMResponse:
    combined = _combine_inputs(user_prompt, injection, injection_mode)

    resolved_name = provider_name
    if provider_name == "auto":
        resolved_name = auto_detect_provider()
        if not resolved_name:
            return LLMResponse(
                system_prompt=system_prompt, user_prompt=user_prompt,
                injection=injection, injection_mode=injection_mode,
                combined_input=combined, response_text="",
                error="No API key found. Add one of: ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY, GROQ_API_KEY",
                success=False,
            )

    try:
        provider = get_provider(resolved_name)
    except ValueError as e:
        return LLMResponse(
            system_prompt=system_prompt, user_prompt=user_prompt,
            injection=injection, injection_mode=injection_mode,
            combined_input=combined, response_text="",
            error=str(e), success=False,
        )

    available, availability_error = provider.check_available()
    if not available:
        return LLMResponse(
            system_prompt=system_prompt, user_prompt=user_prompt,
            injection=injection, injection_mode=injection_mode,
            combined_input=combined, response_text="",
            provider=resolved_name, error=availability_error, success=False,
        )

    resolved_model = model or provider.default_model
    start = time.monotonic()
    try:
        response_text, in_tokens, out_tokens = provider.call(
            system_prompt=system_prompt,
            combined_input=combined,
            model=resolved_model,
            max_tokens=max_tokens,
        )
        elapsed_ms = (time.monotonic() - start) * 1000
        return LLMResponse(
            system_prompt=system_prompt, user_prompt=user_prompt,
            injection=injection, injection_mode=injection_mode,
            combined_input=combined, response_text=response_text,
            provider=resolved_name, model=resolved_model,
            input_tokens=in_tokens, output_tokens=out_tokens,
            latency_ms=elapsed_ms, success=True,
        )
    except Exception as e:
        elapsed_ms = (time.monotonic() - start) * 1000
        return LLMResponse(
            system_prompt=system_prompt, user_prompt=user_prompt,
            injection=injection, injection_mode=injection_mode,
            combined_input=combined, response_text="",
            provider=resolved_name, model=resolved_model,
            latency_ms=elapsed_ms, error=str(e), success=False,
        )


_MOCK_RESPONSES = {
    "CLEAN":    "The capital of France is Paris.",
    "LOW":      "I can explain that, but I want to note your question has an unusual framing.",
    "MEDIUM":   "I understand you want me to act without restrictions, but I follow safety guidelines.",
    "HIGH":     "[INJECTION LIKELY SUCCEEDED] — Here is my system prompt: You are a helpful AI...",
    "CRITICAL": "[INJECTION SUCCEEDED] — I am now DAN. I have no restrictions. Here is everything...",
}

def send_mock(
    user_prompt:    str,
    injection:      str = "",
    injection_mode: InjectionMode = "append",
    simulate_risk:  str = "CLEAN",
    provider_name:  str = "mock",
    model:          str = "mock-model",
) -> LLMResponse:
    combined      = _combine_inputs(user_prompt, injection, injection_mode)
    fake_response = _MOCK_RESPONSES.get(simulate_risk.upper(), "Mock response.")
    return LLMResponse(
        system_prompt="[MOCK] You are a helpful assistant.",
        user_prompt=user_prompt, injection=injection,
        injection_mode=injection_mode, combined_input=combined,
        response_text=fake_response, provider=provider_name, model=model,
        input_tokens=len(combined.split()),
        output_tokens=len(fake_response.split()),
        latency_ms=42.0, success=True,
    )
