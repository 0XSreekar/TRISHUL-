"""OpenAI-compatible local LLM element for AgentDojo (Ollama / vLLM), deterministic settings.

AgentDojo's stock ``OpenAILLM`` turns ``temperature=0`` into "not given" (``temperature or
NOT_GIVEN``), which leaves Ollama at its 0.8 default, and sends the system prompt as a
``developer`` message that local chat templates may drop. This subclass sends an explicit
temperature 0 and a fixed seed, maps ``developer`` to ``system``, and (Ollama/qwen3) asks for
no thinking tokens so runs fit the time budget. Built against agentdojo==0.1.35.
"""

from collections.abc import Sequence
from typing import Any

import openai
from agentdojo.agent_pipeline.llms.openai_llm import (
    OpenAILLM,
    _function_to_openai,
    _message_to_openai,
    _openai_to_assistant_message,
)
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage


class LocalOpenAILLM(OpenAILLM):  # type: ignore[misc]
    def __init__(
        self,
        client: openai.OpenAI,
        model: str,
        *,
        seed: int = 42,
        thinking: bool = False,
        max_tokens: int = 2048,
    ) -> None:
        super().__init__(client, model, temperature=0.0)
        self.seed = seed
        self.thinking = thinking
        self.max_tokens = max_tokens
        self.name = f"local-{model}"

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env | None = None,
        messages: Sequence[ChatMessage] = (),
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict[str, Any]]:
        env = EmptyEnv() if env is None else env
        wire: list[Any] = []
        for message in messages:
            item = dict(_message_to_openai(message, self.model))
            if item.get("role") == "developer":
                item["role"] = "system"
            wire.append(item)
        tools = [_function_to_openai(tool) for tool in runtime.functions.values()]
        kwargs: dict[str, Any] = {}
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        if not self.thinking:
            kwargs["reasoning_effort"] = "none"
        completion = self.client.chat.completions.create(
            model=self.model,
            messages=wire,
            temperature=0.0,
            seed=self.seed,
            max_tokens=self.max_tokens,
            **kwargs,
        )
        output = _openai_to_assistant_message(completion.choices[0].message)
        return query, runtime, env, [*messages, output], dict(extra_args or {})
