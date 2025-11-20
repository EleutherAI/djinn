#!/usr/bin/env python3
"""Evaluate previously saved probe checkpoints on a feature dataset."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import torch

from djinn.probe.train_probes import load_and_align_features, roc_auc_score
from djinn.utils.classifier import Classifier


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("features", type=Path, help="NPZ file produced by extract_latents.py")
    parser.add_argument(
        "--probe-dir",
        type=Path,
        required=True,
        help="Directory containing probe_w<window>.pt checkpoints saved by train_probes.py",
    )
    parser.add_argument("--windows", type=int, nargs="*", help="Specific windows to evaluate (default: all available)")
    parser.add_argument("--device", type=str, default=None)
    parser.add_argument("--metrics-out", type=Path, help="Optional JSON file to write evaluation metrics")
    return parser.parse_args()


def to_tensor(array: np.ndarray, device: torch.device) -> torch.Tensor:
    return torch.from_numpy(array.astype(np.float32)).to(device=device)


def load_checkpoint(path: Path, device: torch.device) -> dict:
    payload = torch.load(path, map_location="cpu", weights_only=False)
    if not isinstance(payload, dict):
        raise ValueError(f"Checkpoint {path} is not a dictionary payload")
    payload["mean"] = torch.from_numpy(np.asarray(payload["mean"], dtype=np.float32)).to(device=device)
    payload["std"] = torch.from_numpy(np.asarray(payload["std"], dtype=np.float32)).to(device=device)
    state_dict = {k: v.to(device=device) for k, v in payload["state_dict"].items()}
    payload["state_dict"] = state_dict
    return payload


def evaluate_probe(
    clf: Classifier,
    mean: torch.Tensor,
    std: torch.Tensor,
    features,
    labels,
    device: torch.device,
) -> dict[str, float]:
    inputs = to_tensor(features, device)
    labels_tensor = torch.from_numpy(labels.astype(np.float32)).to(device)
    inputs_std = (inputs - mean) / std
    metrics = clf.evaluate(inputs_std, labels_tensor)
    with torch.no_grad():
        logits = clf(inputs_std).cpu().numpy()
    metrics["roc_auc"] = float("nan")
    if not (labels == labels[0]).all():
        metrics["roc_auc"] = roc_auc_score(labels, logits)
    return metrics


def main() -> None:
    args = parse_args()
    device = torch.device(args.device) if args.device else torch.device("cuda" if torch.cuda.is_available() else "cpu")

    windows, window_features, labels = load_and_align_features(args.features, args.windows)

    results: dict[int, dict[str, float]] = {}

    for window in windows:
        ckpt_path = args.probe_dir / f"probe_w{window}.pt"
        if not ckpt_path.exists():
            raise FileNotFoundError(f"Checkpoint not found for window {window}: {ckpt_path}")

        checkpoint = load_checkpoint(ckpt_path, device)
        clf = Classifier(checkpoint["input_dim"], device=device)
        clf.load_state_dict(checkpoint["state_dict"])

        metrics = evaluate_probe(
            clf,
            checkpoint["mean"],
            checkpoint["std"],
            window_features[window],
            labels,
            device,
        )
        results[window] = metrics

    header = f"{'window':>6}  {'accuracy':>9}  {'bce':>9}  {'roc_auc':>9}"
    print(header)
    for window in windows:
        metrics = results[window]
        roc_auc = metrics.get("roc_auc", float("nan"))
        loss = metrics.get("loss", float("nan"))
        bce = metrics.get("bce", loss)
        print(
            f"{window:6d}  "
            f"{metrics['accuracy']:.4f}  "
            f"{bce:.4f}  "
            f"{roc_auc:.4f}"
        )

    if args.metrics_out:
        args.metrics_out.parent.mkdir(parents=True, exist_ok=True)
        serialisable = {str(window): metrics for window, metrics in results.items()}
        with args.metrics_out.open("w", encoding="utf-8") as fh:
            json.dump(serialisable, fh, indent=2)
        print(f"Wrote metrics to {args.metrics_out}")


if __name__ == "__main__":
    main()

