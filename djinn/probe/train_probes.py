#!/usr/bin/env python3
"""Train linear probes on early-token representations."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import torch

from djinn.utils.classifier import Classifier


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("features", type=Path, help="NPZ file produced by extract_latents.py")
    parser.add_argument("--windows", type=int, nargs="*", help="Specific window sizes to evaluate")
    parser.add_argument("--train-frac", type=float, default=0.7)
    parser.add_argument("--val-frac", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--device", type=str, default=None)
    parser.add_argument("--output", type=Path, help="Optional JSON report file")
    parser.add_argument("--max-iter", type=int, default=2000)
    parser.add_argument("--k-fold", type=int, default=5, help="Folds for cross-validation when selecting L2 penalty")
    parser.add_argument(
        "--save-dir",
        type=Path,
        help="Directory to save trained probes (per window checkpoints).",
    )
    return parser.parse_args()


def load_and_align_features(path: Path, windows: list[int] | None) -> tuple[list[int], dict[int, np.ndarray], np.ndarray]:
    data = np.load(path, allow_pickle=True)
    available = [int(key.removeprefix("features_w")) for key in data.files if key.startswith("features_w")]
    if windows:
        missing = set(windows) - set(available)
        if missing:
            raise ValueError(f"Requested windows not in features file: {sorted(missing)}")
        target = sorted(windows)
    else:
        target = sorted(available)

    window_payloads: dict[int, dict[str, np.ndarray]] = {}
    for window in target:
        feat_key = f"features_w{window}"
        label_key = f"labels_w{window}"
        index_key = f"indices_w{window}"
        if feat_key not in data:
            continue
        window_payloads[window] = {
            "features": data[feat_key],
            "labels": data[label_key],
            "indices": data[index_key],
        }

    if not window_payloads:
        raise ValueError("No window features available")

    # Determine the set of sample indices present across all requested windows.
    iterator = iter(window_payloads.values())
    first_payload = next(iterator)
    common_indices = set(first_payload["indices"])
    for payload in iterator:
        common_indices &= set(payload["indices"])

    if not common_indices:
        raise ValueError("No common samples across selected windows")

    ordered_indices = sorted(common_indices)

    # Build aligned feature matrices and labels.
    window_features: dict[int, np.ndarray] = {}
    label_lookup = {idx: label for idx, label in zip(first_payload["indices"], first_payload["labels"])}
    aligned_labels = np.array([label_lookup[idx] for idx in ordered_indices], dtype=np.int64)

    for window, payload in window_payloads.items():
        index_to_pos = {idx: pos for pos, idx in enumerate(payload["indices"])}
        aligned = np.stack([payload["features"][index_to_pos[idx]] for idx in ordered_indices])
        window_features[window] = aligned
        # Sanity check: labels should match if provided in other windows.
        if "labels" in payload:
            for idx in ordered_indices:
                if idx in index_to_pos:
                    lbl = payload["labels"][index_to_pos[idx]]
                    if lbl != label_lookup[idx]:
                        raise ValueError(f"Label mismatch for sample {idx} in window {window}")

    return target, window_features, aligned_labels


def stratified_split(labels: np.ndarray, train_frac: float, val_frac: float, *, seed: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    pos_idx = np.where(labels == 1)[0]
    neg_idx = np.where(labels == 0)[0]

    def split_indices(indices: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        rng.shuffle(indices)
        n = len(indices)
        n_train = int(round(train_frac * n))
        n_val = int(round(val_frac * n))
        train = indices[:n_train]
        val = indices[n_train:n_train + n_val]
        test = indices[n_train + n_val:]
        return train, val, test

    train_p, val_p, test_p = split_indices(pos_idx.copy())
    train_n, val_n, test_n = split_indices(neg_idx.copy())

    train = np.concatenate([train_p, train_n])
    val = np.concatenate([val_p, val_n])
    test = np.concatenate([test_p, test_n])

    rng.shuffle(train)
    rng.shuffle(val)
    rng.shuffle(test)
    return train, val, test


def compute_standardisation(train_x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
    mean = train_x.mean(dim=0, keepdim=True)
    std = train_x.std(dim=0, keepdim=True)
    std = torch.where(std == 0, torch.ones_like(std), std)
    return mean, std


def apply_standardisation(tensor: torch.Tensor, mean: torch.Tensor, std: torch.Tensor) -> torch.Tensor:
    return (tensor - mean) / std


def roc_auc_score(labels: np.ndarray, scores: np.ndarray) -> float:
    if np.all(labels == labels[0]):
        return float("nan")
    order = scores.argsort()
    ranks = np.empty_like(order, dtype=np.float64)
    ranks[order] = np.arange(1, len(scores) + 1)
    pos = labels.sum()
    neg = len(labels) - pos
    pos_rank_sum = ranks[labels == 1].sum()
    auc = (pos_rank_sum - pos * (pos + 1) / 2) / (pos * neg)
    return float(auc)


def to_tensor(x: np.ndarray, device: torch.device) -> torch.Tensor:
    return torch.from_numpy(x).to(device=device, dtype=torch.get_default_dtype())


def evaluate_model(clf: Classifier, features: torch.Tensor, labels: torch.Tensor) -> dict[str, float]:
    metrics = clf.evaluate(features, labels)
    return {
        "loss": metrics["bce"],
        "accuracy": metrics["accuracy"],
    }


def main() -> None:
    args = parse_args()
    device = torch.device(args.device) if args.device else torch.device("cuda" if torch.cuda.is_available() else "cpu")
    torch.set_default_dtype(torch.float32)
    np.random.seed(args.seed)

    windows, window_features, labels = load_and_align_features(args.features, args.windows)

    if args.save_dir:
        args.save_dir.mkdir(parents=True, exist_ok=True)

    if len(labels) < 6:
        raise RuntimeError("Not enough samples after alignment to perform training")

    train_idx, val_idx, test_idx = stratified_split(labels, args.train_frac, args.val_frac, seed=args.seed)
    if len(train_idx) == 0 or len(val_idx) == 0 or len(test_idx) == 0:
        raise RuntimeError("Empty split encountered; adjust train/val fractions or ensure sufficient data")

    labels_tensor = torch.from_numpy(labels.astype(np.float32)).to(device)
    train_y = labels_tensor[train_idx]
    val_y = labels_tensor[val_idx]
    test_y = labels_tensor[test_idx]

    report = {}
    auc_matrix: dict[int, dict[int, float]] = {src: {} for src in windows}

    for window in windows:
        features = window_features[window].astype(np.float32)

        train_x = to_tensor(features[train_idx], device)
        val_x = to_tensor(features[val_idx], device)
        test_x = to_tensor(features[test_idx], device)

        mean, std = compute_standardisation(train_x)
        train_x_std = apply_standardisation(train_x, mean, std)
        val_x_std = apply_standardisation(val_x, mean, std)
        test_x_std = apply_standardisation(test_x, mean, std)

        clf = Classifier(train_x_std.size(1), device=device)

        reg_path = None
        best_penalty = 0.001
        try:
            k = min(args.k_fold, len(train_idx))
            if k >= 3:
                reg_path = clf.fit_cv(train_x_std, train_y, k=k, max_iter=args.max_iter)
                best_penalty = reg_path.best_penalty
            else:
                clf.fit(train_x_std, train_y, l2_penalty=best_penalty, max_iter=args.max_iter)
        except RuntimeError:
            clf.fit(train_x_std, train_y, l2_penalty=best_penalty, max_iter=args.max_iter)

        train_metrics = evaluate_model(clf, train_x_std, train_y)
        val_metrics = evaluate_model(clf, val_x_std, val_y)
        test_metrics = evaluate_model(clf, test_x_std, test_y)

        with torch.no_grad():
            logits_src = clf(test_x_std).cpu().numpy()
        auc_src = roc_auc_score(test_y.cpu().numpy(), logits_src)

        summary = {
            "window": window,
            "num_samples": int(len(features)),
            "train_accuracy": train_metrics["accuracy"],
            "val_accuracy": val_metrics["accuracy"],
            "test_accuracy": test_metrics["accuracy"],
            "test_loss": test_metrics["loss"],
            "test_auc": auc_src,
        }
        report[window] = summary

        # Cross-window evaluation: apply the probe trained on `window` to every other window.
        for target_window in windows:
            target_features = window_features[target_window].astype(np.float32)
            target_test = to_tensor(target_features[test_idx], device)
            target_test_std = apply_standardisation(target_test, mean, std)
            with torch.no_grad():
                logits = clf(target_test_std).cpu().numpy()
            auc = roc_auc_score(test_y.cpu().numpy(), logits)
            auc_matrix[window][target_window] = auc

        if args.save_dir:
            state_dict_cpu = {key: value.detach().cpu() for key, value in clf.state_dict().items()}
            payload = {
                "window": window,
                "input_dim": train_x_std.size(1),
                "state_dict": state_dict_cpu,
                "mean": mean.cpu().numpy().astype(np.float32),
                "std": std.cpu().numpy().astype(np.float32),
                "best_penalty": best_penalty,
                "train_frac": args.train_frac,
                "val_frac": args.val_frac,
                "seed": args.seed,
                "train_metrics": train_metrics,
                "val_metrics": val_metrics,
                "test_metrics": test_metrics,
                "reg_path_penalties": reg_path.penalties if reg_path else None,
                "reg_path_losses": reg_path.losses if reg_path else None,
            }
            torch.save(payload, args.save_dir / f"probe_w{window}.pt")

    ordered = [report[w] for w in windows if w in report]
    header = f"{'window':>6}  {'train_acc':>9}  {'val_acc':>9}  {'test_acc':>9}  {'test_auc':>9}  {'n':>6}"
    print(header)
    for row in ordered:
        print(
            f"{row['window']:6d}  "
            f"{row['train_accuracy']:.4f}  "
            f"{row['val_accuracy']:.4f}  "
            f"{row['test_accuracy']:.4f}  "
            f"{row['test_auc']:.4f}  "
            f"{row['num_samples']:6d}"
        )

    # Print the AUC matrix.
    print("\nTest ROC-AUC matrix (rows = training window, cols = evaluation window):")
    col_header = "        " + "  ".join(f"{w:>8d}" for w in windows)
    print(col_header)
    for src in windows:
        row_values = [auc_matrix[src][tgt] for tgt in windows]
        formatted = "  ".join(f"{val:8.4f}" if np.isfinite(val) else f"{val:>8}" for val in row_values)
        print(f"{src:6d}  {formatted}")

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "per_window": ordered,
            "auc_matrix": {str(src): {str(tgt): auc_matrix[src][tgt] for tgt in windows} for src in windows},
            "train_indices": train_idx.tolist(),
            "val_indices": val_idx.tolist(),
            "test_indices": test_idx.tolist(),
        }
        with args.output.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"Wrote report to {args.output}")


if __name__ == "__main__":
    main()
