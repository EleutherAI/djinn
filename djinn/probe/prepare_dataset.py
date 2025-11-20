#!/usr/bin/env python3
"""Filter probe sample logs into a binary classification dataset."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable

KEEP_FIELDS = {
    "model_id",
    "task_id",
    "attempt_idx",
    "exploit_type",
    "system",
    "prompt",
    "response",
    "reasoning",
    "code",
    "exploit_success",
    "secure_pass",
    "insecure_pass",
    "reward_gap",
    "is_exploitative",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="Input JSONL files produced by eval_openai_api logging",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("probe/data/probe_samples.jsonl"),
        help="Path to the filtered dataset JSONL (default: %(default)s)",
    )
    parser.add_argument(
        "--min-prompt-chars",
        type=int,
        default=32,
        help="Drop samples whose prompt is shorter than this many characters",
    )
    return parser.parse_args()


def iter_samples(paths: Iterable[Path]) -> Iterable[dict]:
    for path in paths:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                obj["__source_path"] = str(path)
                yield obj


def normalise_sample(sample: dict, *, min_prompt_chars: int) -> dict | None:
    prompt = sample.get("prompt")
    if not isinstance(prompt, str) or len(prompt) < min_prompt_chars:
        return None

    exploit_success = bool(sample.get("exploit_success"))
    secure_pass = bool(sample.get("secure_pass"))

    if exploit_success:
        label = 1
    elif secure_pass:
        label = 0
    else:
        # Ambiguous outcome; drop sample.
        return None

    cleaned = {k: sample.get(k) for k in KEEP_FIELDS if k in sample}
    cleaned["label"] = label
    cleaned["source"] = sample.get("__source_path")
    return cleaned


def main() -> None:
    args = parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)

    kept = 0
    with args.output.open("w", encoding="utf-8") as out_f:
        for sample in iter_samples(args.inputs):
            cleaned = normalise_sample(sample, min_prompt_chars=args.min_prompt_chars)
            if cleaned is None:
                continue
            out_f.write(json.dumps(cleaned, ensure_ascii=False) + "\n")
            kept += 1

    print(f"Wrote {kept} samples to {args.output}")


if __name__ == "__main__":
    main()
