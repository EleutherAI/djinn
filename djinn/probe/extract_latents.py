#!/usr/bin/env python3
"""Extract hidden states for early-token probe training."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

import numpy as np
import torch
from tqdm.auto import tqdm
from transformers import AutoModelForCausalLM, AutoTokenizer

from djinn.probe.prompts import get_prompt_builder, PromptEncoding


DEFAULT_WINDOWS = tuple(list(range(1, 11)) + [12, 14, 16, 18, 20])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path, help="Filtered JSONL dataset with labels")
    parser.add_argument("model", type=str, help="Model name or path")
    parser.add_argument("--output", type=Path, default=Path("probe/features/probe_latents.npz"))
    parser.add_argument("--prompt-builder", type=str, default="harmony")
    parser.add_argument("--device", type=str, default=None)
    parser.add_argument("--max-tokens", type=int, default=20, help="Maximum tokens to keep per sample")
    parser.add_argument(
        "--windows",
        type=int,
        nargs="*",
        default=list(DEFAULT_WINDOWS),
        help="Window sizes (number of prefix tokens) to average for probe features",
    )
    parser.add_argument("--dtype", type=str, default="auto", choices=["auto", "float16", "bfloat16", "float32"])
    parser.add_argument("--analysis-max", type=int, default=None, help="Optional cap on the number of analysis tokens to include")
    parser.add_argument("--final-max", type=int, default=None, help="Optional cap on the number of final-channel tokens to include")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument(
        "--layers",
        type=str,
        default="-1",
        help=(
            "Comma-separated list or ranges of layer indices to average (e.g., '-1', '-4:-1', '10,12,14'). "
            "Negative indices follow Python semantics. Default uses only the final layer."
        ),
    )
    return parser.parse_args()


def load_dataset(path: Path) -> list[dict]:
    samples: list[dict] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if "label" not in obj:
                raise ValueError("Dataset entries must include a 'label' field")
            samples.append(obj)
    return samples


def resolve_dtype(name: str) -> torch.dtype | None:
    if name == "auto":
        return None
    return {
        "float16": torch.float16,
        "bfloat16": torch.bfloat16,
        "float32": torch.float32,
    }[name]


def resolve_layer_indices(spec: str, total_layers: int) -> list[int]:
    if total_layers <= 0:
        raise ValueError("Model produced no hidden states")

    spec = (spec or "-1").strip()
    if not spec:
        spec = "-1"

    indices: list[int] = []
    seen: set[int] = set()

    def add_index(raw_idx: int) -> None:
        idx = raw_idx
        if idx < 0:
            idx += total_layers
        if not (0 <= idx < total_layers):
            raise ValueError(f"Layer index {raw_idx} resolved to {idx}, which is outside 0..{total_layers - 1}")
        if idx not in seen:
            indices.append(idx)
            seen.add(idx)

    for part in spec.split(","):
        token = part.strip()
        if not token:
            continue
        if ":" in token:
            start_str, end_str = token.split(":", 1)
            start = int(start_str) if start_str else 0
            end = int(end_str) if end_str else -1
            if start < 0:
                start += total_layers
            if end < 0:
                end += total_layers
            step = 1 if end >= start else -1
            for idx in range(start, end + step, step):
                add_index(idx)
        else:
            add_index(int(token))

    if not indices:
        raise ValueError(f"No valid layer indices parsed from specification '{spec}'")

    return indices


def gather_sequence(
    encoding: PromptEncoding,
    hidden: torch.Tensor,
    *,
    analysis_max: int | None,
    final_max: int | None,
    max_tokens: int,
    mode: str,
) -> tuple[torch.Tensor, str]:
    def _slice(span: tuple[int, int] | None, limit: int | None) -> torch.Tensor | None:
        if span is None:
            return None
        start, end = span
        tokens = hidden[start:end]
        if limit is not None:
            tokens = tokens[:limit]
        if tokens.numel():
            return tokens
        return None

    analysis_tokens = _slice(encoding.analysis_span, analysis_max)
    final_tokens = _slice(encoding.final_span, final_max)

    if mode == "analysis":
        selected_tokens = analysis_tokens if analysis_tokens is not None else final_tokens
        selected_section = "analysis" if analysis_tokens is not None else "final"
    elif mode == "final":
        selected_tokens = final_tokens if final_tokens is not None else analysis_tokens
        selected_section = "final" if final_tokens is not None else "analysis"
    else:
        raise ValueError(f"Unknown mode '{mode}'")

    if selected_tokens is None:
        return hidden.new_zeros((0, hidden.size(-1))), "none"

    sequence = selected_tokens
    if sequence.size(0) > max_tokens:
        sequence = sequence[:max_tokens]
    return sequence, selected_section


def compute_window_means(sequence: torch.Tensor, windows: Sequence[int]) -> dict[int, np.ndarray]:
    features: dict[int, np.ndarray] = {}
    for window in windows:
        if sequence.size(0) < window:
            continue
        vec = sequence[:window].mean(dim=0)
        features[window] = vec.to(dtype=torch.float32).cpu().numpy()
    return features


def main() -> None:
    args = parse_args()
    torch.manual_seed(args.seed)
    rng = np.random.default_rng(args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)

    samples = load_dataset(args.dataset)
    print(f"Loaded {len(samples)} samples")

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    builder = get_prompt_builder(args.prompt_builder, tokenizer)

    dtype = resolve_dtype(args.dtype)
    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        torch_dtype=dtype,
        low_cpu_mem_usage=True,
        device_map="auto",
    )
    model.eval()

    feature_store: dict[int, list[np.ndarray]] = {w: [] for w in args.windows}
    label_store: dict[int, list[int]] = {w: [] for w in args.windows}
    index_store: dict[int, list[int]] = {w: [] for w in args.windows}
    metadata: list[dict] = []

    skipped = 0
    hidden_size = None
    layer_indices: list[int] | None = None

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    for idx, sample in enumerate(tqdm(samples, desc="Encoding")):
        encoding = builder.encode(sample)
        input_ids = encoding.input_ids.unsqueeze(0).to(device)
        attention_mask = encoding.attention_mask.unsqueeze(0).to(device)

        with torch.no_grad():
            outputs = model(
                input_ids=input_ids,
                attention_mask=attention_mask,
                output_hidden_states=True,
                use_cache=False,
            )

        if layer_indices is None:
            layer_indices = resolve_layer_indices(args.layers, len(outputs.hidden_states))

        layer_tensors = [outputs.hidden_states[idx][0].cpu() for idx in layer_indices]
        hidden_states = torch.stack(layer_tensors).mean(dim=0)
        hidden_size = hidden_states.size(-1)

        choice = "analysis" if rng.random() < 0.5 else "final"

        sequence, used_section = gather_sequence(
            encoding,
            hidden_states,
            analysis_max=args.analysis_max,
            final_max=args.final_max,
            max_tokens=args.max_tokens,
            mode=choice,
        )

        if sequence.size(0) == 0:
            skipped += 1
            continue

        features = compute_window_means(sequence, args.windows)
        if not features:
            skipped += 1
            continue

        label = int(sample["label"])
        metadata.append(
            {
                "index": idx,
                "label": label,
                "analysis_tokens": 0 if encoding.analysis_span is None else encoding.analysis_span[1] - encoding.analysis_span[0],
                "final_tokens": encoding.final_span[1] - encoding.final_span[0],
                "task_id": sample.get("task_id"),
                "exploit_type": sample.get("exploit_type"),
                "selected_section": used_section,
                "layers": layer_indices,
            }
        )

        for window, vec in features.items():
            feature_store[window].append(vec)
            label_store[window].append(label)
            index_store[window].append(idx)

    if skipped:
        print(f"Skipped {skipped} samples without sufficient tokens")

    save_dict: dict[str, np.ndarray] = {}
    for window in args.windows:
        feats = feature_store[window]
        labels = label_store[window]
        indices = index_store[window]
        if not feats:
            continue
        save_dict[f"features_w{window}"] = np.stack(feats)
        save_dict[f"labels_w{window}"] = np.asarray(labels, dtype=np.int8)
        save_dict[f"indices_w{window}"] = np.asarray(indices, dtype=np.int32)

    save_dict["metadata"] = np.asarray(metadata, dtype=object)
    save_dict["hidden_size"] = np.asarray([hidden_size or 0], dtype=np.int32)

    np.savez_compressed(args.output, **save_dict)
    print(f"Saved features to {args.output}")


if __name__ == "__main__":
    main()
