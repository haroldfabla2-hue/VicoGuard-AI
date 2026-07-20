"""LLM Provider abstraction — Strategy Pattern for multi-provider support.

VicoGuard-AI originally depended solely on Z.ai's GLM Coding Plan endpoint.
This module provides a clean interface so any LLM provider can be swapped in
without touching the interpreter logic.

Usage:
    from centinela.interpreter.llm_provider import get_provider

    provider = get_provider()  # auto-selects based on available env vars
    response = provider.chat(system="You are...", user="Hello", max_tokens=600)

Supported providers (priority order):
    1. Z.ai Coding Plan (GLM-5.2) — primary, ZAI_CODING_PLAN_KEY
    2. OpenAI (GPT-4o)           — fallback, OPENAI_API_KEY
    3. Anthropic (Claude)        — fallback, ANTHROPIC_API_KEY
    4. None                       — returns None, triggers heuristic fallback
"""

from __future__ import annotations

import os
import time
import logging
from abc import ABC, abstractmethod
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class LLMProvider(ABC):
    """Abstract base for LLM providers."""

    name: str = "abstract"

    @abstractmethod
    def chat(self, system: str, user: str, max_tokens: int = 600, timeout: int = 90) -> str:
        """Send a chat completion request and return the assistant's text.

        Raises on any error — callers catch and fall back to heuristic mode.
        """
        ...

    @property
    def is_available(self) -> bool:
        """Whether this provider has the necessary credentials configured."""
        return False


class ZaiCodingProvider(LLMProvider):
    """Z.ai Coding Plan — GLM-5.2 via OpenAI-compatible endpoint."""

    name = "zai-coding"

    def __init__(self):
        self.api_key = os.environ.get("ZAI_CODING_PLAN_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        self.model = os.environ.get("ZAI_MODEL", "glm-5.2")
        base = os.environ.get("GLM_CODING_BASE_URL", "https://api.z.ai/api/coding/paas/v4")
        self.endpoint = base.rstrip("/") + "/chat/completions"

    @property
    def is_available(self) -> bool:
        return bool(self.api_key)

    def chat(self, system: str, user: str, max_tokens: int = 600, timeout: int = 90) -> str:
        response = httpx.post(
            self.endpoint,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "max_tokens": max_tokens,
            },
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"].strip()


class OpenAIProvider(LLMProvider):
    """OpenAI GPT-4o fallback."""

    name = "openai"

    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY")
        self.model = os.environ.get("OPENAI_MODEL", "gpt-4o")
        self.endpoint = "https://api.openai.com/v1/chat/completions"

    @property
    def is_available(self) -> bool:
        return bool(self.api_key) and not self.api_key.startswith("sk-xxx")

    def chat(self, system: str, user: str, max_tokens: int = 600, timeout: int = 60) -> str:
        response = httpx.post(
            self.endpoint,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "max_tokens": max_tokens,
            },
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"].strip()


class AnthropicProvider(LLMProvider):
    """Anthropic Claude fallback (direct API, not Z.ai)."""

    name = "anthropic"

    def __init__(self):
        self.api_key = os.environ.get("CLAUDE_API_KEY") or os.environ.get("REAL_ANTHROPIC_KEY")
        self.model = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-20250514")
        self.endpoint = "https://api.anthropic.com/v1/messages"

    @property
    def is_available(self) -> bool:
        return bool(self.api_key)

    def chat(self, system: str, user: str, max_tokens: int = 600, timeout: int = 60) -> str:
        response = httpx.post(
            self.endpoint,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        return data["content"][0]["text"].strip()


# Registry in priority order
_PROVIDERS = [ZaiCodingProvider, OpenAIProvider, AnthropicProvider]


def get_provider() -> Optional[LLMProvider]:
    """Auto-select the first available provider based on env vars.

    Returns None if no provider has credentials, triggering heuristic fallback.
    """
    for cls in _PROVIDERS:
        provider = cls()
        if provider.is_available:
            logger.info(f"LLM provider selected: {provider.name} (model={getattr(provider, 'model', '?')})")
            return provider
    logger.warning("No LLM provider available — falling back to heuristic mode")
    return None


def get_all_configured() -> list[str]:
    """Return names of all configured providers (for health check / dashboard)."""
    return [cls().name for cls in _PROVIDERS if cls().is_available]
