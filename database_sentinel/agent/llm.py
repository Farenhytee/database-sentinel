"""Bring your own model: any OpenAI-compatible endpoint (OpenRouter, OpenAI, Ollama, ...)."""
import os

from langchain_openai import ChatOpenAI

DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MODEL = "deepseek/deepseek-v4-flash"  # cheap dev default; override with SENTINEL_MODEL


def model_id() -> str:
    return os.environ.get("SENTINEL_MODEL") or DEFAULT_MODEL


def get_model() -> ChatOpenAI:
    key = os.environ.get("SENTINEL_API_KEY") or os.environ.get("OPENROUTER_API_KEY") or "not-needed"  # local servers ignore it
    base = os.environ.get("SENTINEL_BASE_URL") or DEFAULT_BASE_URL
    # OpenRouter: return usage.cost; route to the fastest provider (slow ones pushed long outputs past the eval deadline)
    extra = {"usage": {"include": True}, "provider": {"sort": "throughput"}} if "openrouter.ai" in base else None
    return ChatOpenAI(model=model_id(), base_url=base, api_key=key, temperature=0, timeout=120, extra_body=extra)
