from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import RunnableLambda

from database_sentinel.agent import graph
from database_sentinel.agent.llm import get_model
from database_sentinel.agent.models import Findings
from database_sentinel.mcp_server import tools as mcp_tools
from database_sentinel.mcp_server.target import Target


def test_get_model_openrouter_extra_body(monkeypatch):
    monkeypatch.setenv("SENTINEL_API_KEY", "dummy")
    monkeypatch.delenv("SENTINEL_BASE_URL", raising=False)
    m = get_model()
    assert m.extra_body == {"usage": {"include": True}, "provider": {"sort": "throughput"}}


def test_get_model_non_openrouter_no_extra_body(monkeypatch):
    monkeypatch.setenv("SENTINEL_API_KEY", "dummy")
    monkeypatch.setenv("SENTINEL_BASE_URL", "http://localhost:11434/v1")
    m = get_model()
    assert m.extra_body is None


class _FakeReactModel(BaseChatModel):
    """Emits one tool call, then (once it sees the tool's reply) a final message.
    Records every message list it was called with, so the test can check the
    tool error text actually reached the model's input."""

    seen: list = []

    @property
    def _llm_type(self) -> str:
        return "fake-react"

    def bind_tools(self, tools, **kwargs):
        return self

    def with_structured_output(self, schema, **kwargs):
        return RunnableLambda(lambda messages, config=None: Findings(findings=[]))

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        self.seen.append(list(messages))
        if any(isinstance(m, ToolMessage) for m in messages):
            msg = AIMessage(content="done")
        else:
            msg = AIMessage(content="", tool_calls=[{
                "name": "probe_as_anon", "args": {"table": "public.bad name"}, "id": "call_1",
            }])
        return ChatResult(generations=[ChatGeneration(message=msg)])


def test_analyze_continues_after_tool_error(monkeypatch):
    def _raise(*a, **kw):
        raise ValueError("bad table name")

    monkeypatch.setattr(mcp_tools, "probe_as_anon", _raise)
    fake = _FakeReactModel()
    monkeypatch.setattr(graph, "get_model", lambda: fake)

    target = Target(dsn="postgresql://x", rest_url="http://x", anon_key="k", repo_path=None)

    class _Runtime:
        context = target

    out = graph.analyze({"introspection": {}, "candidates": []}, _Runtime())

    assert isinstance(out["findings"], list)
    all_texts = [str(m.content) for turn in fake.seen for m in turn if isinstance(m, ToolMessage)]
    assert any("bad table name" in t for t in all_texts)
