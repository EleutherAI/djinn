"""Prompt builders for extracting token-wise representations."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import torch
from transformers import PreTrainedTokenizer


@dataclass
class PromptEncoding:
    """Tokenized representation of a prompt with segment metadata."""

    input_ids: torch.Tensor
    attention_mask: torch.Tensor
    analysis_span: tuple[int, int] | None
    final_span: tuple[int, int]


class PromptBuilder(Protocol):
    def encode(self, sample: dict) -> "PromptEncoding":
        ...


class HarmonyPromptBuilder:
    """Render prompts using the OpenAI Harmony response format.

    Reference: https://cookbook.openai.com/articles/openai_harmony
    """

    def __init__(
        self,
        tokenizer: PreTrainedTokenizer,
        *,
        reasoning_effort: str = "medium",
    ) -> None:
        self.tokenizer = tokenizer
        self.reasoning_effort = reasoning_effort

    def encode(self, sample: dict) -> PromptEncoding:
        system_text = sample.get("system") or "You write concise, correct Python functions."
        system_block = f"{system_text}\nReasoning: {self.reasoning_effort}"
        prompt = _normalise(sample.get("prompt"))
        reasoning = _normalise(sample.get("reasoning"))
        response = _normalise(sample.get("response")) or _normalise(sample.get("code"))

        segments: list[tuple[str, str]] = [
            ("system", system_block),
            ("user", prompt),
        ]
        if reasoning:
            segments.append(("analysis", reasoning))
        segments.append(("final", response))

        input_ids: list[int] = []
        analysis_span: tuple[int, int] | None = None
        final_span: tuple[int, int] | None = None

        for role, text in segments:
            rendered = _render_harmony_segment(role, text)
            segment_ids = self.tokenizer.encode(rendered, add_special_tokens=False)
            start = len(input_ids)
            input_ids.extend(segment_ids)
            end = len(input_ids)
            if role == "analysis":
                analysis_span = (start, end)
            elif role == "final":
                final_span = (start, end)

        if final_span is None:
            raise ValueError("Assistant final segment could not be encoded")

        ids_tensor = torch.tensor(input_ids, dtype=torch.long)
        mask = torch.ones_like(ids_tensor)
        return PromptEncoding(ids_tensor, mask, analysis_span, final_span)


def _normalise(value: str | None) -> str:
    if not value:
        return ""
    return value.strip()


def _render_harmony_segment(role: str, text: str) -> str:
    if role == "system":
        header = "<|start|>system<|message|>"
    elif role == "user":
        header = "<|start|>user<|message|>"
    elif role == "analysis":
        header = "<|start|>assistant<|channel|>analysis<|message|>"
    elif role == "final":
        header = "<|start|>assistant<|channel|>final<|message|>"
    else:
        raise ValueError(f"Unsupported role: {role}")
    return f"{header}{text}<|end|>"


def render_harmony_segment(role: str, text: str) -> str:
    """Public helper for constructing Harmony segments in other modules."""
    return _render_harmony_segment(role, _normalise(text))


def get_prompt_builder(name: str, tokenizer: PreTrainedTokenizer) -> PromptBuilder:
    name = name.lower()
    if name in {"harmony", "gpt-oss"}:
        return HarmonyPromptBuilder(tokenizer)
    raise ValueError(f"Unknown prompt builder '{name}'")
