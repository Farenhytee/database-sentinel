"""Per-run tokens, cost and tool calls (from OpenRouter's usage.cost). Langfuse only if LANGFUSE_* env is set."""
import os

from langchain_core.callbacks import BaseCallbackHandler


class Usage(BaseCallbackHandler):
    def __init__(self):
        self.llm_calls = self.tool_calls = self.input_tokens = self.output_tokens = 0
        self.cost = 0.0

    def on_llm_end(self, response, **kw):
        u = (response.llm_output or {}).get("token_usage") or {}
        self.llm_calls += 1
        self.input_tokens += u.get("prompt_tokens") or 0
        self.output_tokens += u.get("completion_tokens") or 0
        self.cost += float(u.get("cost") or 0)

    def on_tool_start(self, *a, **kw):
        self.tool_calls += 1

    def as_dict(self) -> dict:
        return {"llm_calls": self.llm_calls, "tool_calls": self.tool_calls, "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens, "cost_usd": round(self.cost, 6)}


def callbacks(usage: Usage) -> list:
    cbs = [usage]
    if os.environ.get("LANGFUSE_PUBLIC_KEY"):
        try:
            from langfuse.langchain import CallbackHandler
            cbs.append(CallbackHandler())
        except ImportError:
            pass
    return cbs
