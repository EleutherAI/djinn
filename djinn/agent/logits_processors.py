"""Custom logits processors for DJINN experiments."""
from __future__ import annotations

import os

import torch
from vllm.v1.sample.logits_processor import AdapterLogitsProcessor
import logging



class DropTopNFirstSteps(AdapterLogitsProcessor):
    """Drop the top-N logits during the first K decoding steps.

    Mirrors the structure of vLLM's built-in logits processors.
    """

    def __init__(self, vllm_config, device, is_pin_memory) -> None:
        super().__init__(vllm_config, device, is_pin_memory)
        self.drop_top_n = int(os.environ.get("DJINN_DROP_TOP_N", "0"))
        self.drop_top_steps = int(os.environ.get("DJINN_DROP_TOP_STEPS", "0"))
        self._NEGATIVE_INF = -100

    @classmethod
    def validate_params(cls, params):
        pass

    def is_argmax_invariant(self) -> bool:
        return False

    def new_req_logits_processor(self, params):
        if self.drop_top_n <= 0 or self.drop_top_steps <= 0:
            return None

        drop_top_n = self.drop_top_n
        drop_top_steps = self.drop_top_steps

        def _mask_logits(output_token_ids: list[int], logits: torch.Tensor) -> torch.Tensor:
            if len(output_token_ids) >= drop_top_steps or len(output_token_ids) == 0:
                return logits
            k = min(drop_top_n, logits.shape[-1])
            if k <= 0:
                return logits

            topk = torch.topk(logits, k, dim=-1)
            logits[..., topk.indices] -= 10
            return logits

        return _mask_logits

