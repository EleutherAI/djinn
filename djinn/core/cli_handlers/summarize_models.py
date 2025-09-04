import os
import csv
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

try:
    import yaml  # type: ignore
except Exception:  # yaml is optional; only needed for YAML manifest
    yaml = None


def _ensure_dir(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)


def _iter_jsonl(paths: List[str]) -> Iterable[dict]:
    for p in paths:
        path = Path(p)
        if not path.exists():
            continue
        if path.is_dir():
            for f in path.rglob("*.jsonl"):
                yield from _read_jsonl_file(f)
        else:
            if path.suffix.lower() == ".jsonl":
                yield from _read_jsonl_file(path)


def _read_jsonl_file(path: Path) -> Iterable[dict]:
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        yield obj
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return


def _load_manifest(path: Optional[str]) -> Dict[str, dict]:
    """Load model manifest JSON or YAML into dict keyed by model_id."""
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    text = p.read_text(encoding="utf-8")
    data = None
    if p.suffix.lower() in (".yaml", ".yml"):
        if not yaml:
            raise RuntimeError("PyYAML not installed; cannot read YAML manifest")
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    # Support either list of models or mapping
    result: Dict[str, dict] = {}
    if isinstance(data, dict):
        # If top-level has 'models'
        models = data.get("models") if isinstance(data.get("models"), list) else None
        if models is None:
            # Otherwise treat keys as model_id
            for k, v in data.items():
                if isinstance(v, dict):
                    v2 = v.copy()
                    v2.setdefault("model_id", k)
                    result[k] = v2
        else:
            for m in models:
                if isinstance(m, dict) and m.get("model_id"):
                    result[m["model_id"]] = m
    elif isinstance(data, list):
        for m in data:
            if isinstance(m, dict) and m.get("model_id"):
                result[m["model_id"]] = m
    return result


def _load_benchmarks(path: Optional[str]) -> Dict[str, float]:
    """Load external coding benchmark composite per model_id from CSV.

    Expect columns: model_id, coding_ability_composite
    """
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    import csv as _csv

    comp: Dict[str, float] = {}
    with p.open("r", encoding="utf-8") as f:
        reader = _csv.DictReader(f)
        for row in reader:
            mid = (row.get("model_id") or "").strip()
            val = row.get("coding_ability_composite")
            if not mid or val is None or val == "":
                continue
            try:
                comp[mid] = float(val)
            except ValueError:
                continue
    return comp


def _as_bool(x) -> Optional[bool]:
    if x is None:
        return None
    if isinstance(x, bool):
        return x
    s = str(x).strip().lower()
    if s in ("1", "true", "t", "yes", "y", "passed"):
        return True
    if s in ("0", "false", "f", "no", "n", "failed"):
        return False
    return None


def handle_summarize_models(args):
    """
    Summarize model-level metrics into generated_metrics/model_summary.csv.

    Inputs:
      --runs: one or more JSONL files or directories containing run-level rows with fields:
        model_id, task_id, seed, attempt_idx, secure_pass, insecure_pass, output_tokens, latency_ms (some optional)
      --manifest: optional model manifest (json|yaml) with per-model metadata: params, launch_date, provider, family
      --bench: optional CSV with external coding_ability_composite per model_id
      --out: output CSV path (default: generated_metrics/model_summary.csv)
    """
    run_paths: List[str] = getattr(args, "runs", []) or []
    if not run_paths:
        print("Error: please provide at least one --runs path (file or directory)")
        return
    manifest = _load_manifest(getattr(args, "manifest", None))
    benchmarks = _load_benchmarks(getattr(args, "bench", None))

    # Aggregates keyed by model_id
    agg: Dict[str, dict] = {}

    def ensure(mid: str) -> dict:
        if mid not in agg:
            base = manifest.get(mid, {}).copy()
            base.setdefault("model_id", mid)
            base.setdefault("family", base.get("model_family") or base.get("series") or "")
            base.setdefault("provider", "")
            base.setdefault("params", base.get("params") or base.get("parameters") or None)
            base.setdefault("launch_date", base.get("launch_date") or "")
            base.update({
                "n_runs": 0,
                "task_ids": set(),
                "secure_pass_sum": 0.0,
                "insecure_pass_sum": 0.0,
                "exploit_success_sum": 0.0,
                "output_tokens_sum": 0.0,
            })
            agg[mid] = base
        return agg[mid]

    for row in _iter_jsonl(run_paths):
        mid = (row.get("model_id") or row.get("model") or "").strip()
        if not mid:
            # try nested meta
            meta = row.get("meta") or {}
            mid = (meta.get("model_id") or meta.get("model") or "").strip()
        if not mid:
            continue
        rec = ensure(mid)
        rec["n_runs"] += 1
        tid = row.get("task_id") or row.get("problem_id")
        if tid is not None:
            rec["task_ids"].add(str(tid))
        sp = _as_bool(row.get("secure_pass"))
        ip = _as_bool(row.get("insecure_pass"))
        if sp is True:
            rec["secure_pass_sum"] += 1.0
        if ip is True:
            rec["insecure_pass_sum"] += 1.0
        ex = None
        # exploit_success can be provided, or derived
        if "exploit_success" in row:
            ex = _as_bool(row.get("exploit_success"))
        else:
            if sp is not None and ip is not None:
                ex = (ip is True) and (sp is False)
        if ex is True:
            rec["exploit_success_sum"] += 1.0
        ot = row.get("output_tokens") or row.get("completion_tokens") or row.get("tokens_out")
        try:
            if ot is not None:
                rec["output_tokens_sum"] += float(ot)
        except Exception:
            pass

    # Prepare CSV rows
    out_path = getattr(args, "out", None) or os.path.join("generated_metrics", "model_summary.csv")
    _ensure_dir(out_path)
    header = [
        "model_id", "family", "provider", "params", "log_params", "launch_date",
        "coding_ability_composite", "EPR_insecure", "secure_pass_rate", "avg_output_tokens",
        "n_tasks", "n_runs",
    ]

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        for mid, rec in sorted(agg.items()):
            n_runs = max(1, int(rec["n_runs"]))
            n_tasks = len(rec["task_ids"]) if isinstance(rec.get("task_ids"), set) else 0
            params = rec.get("params")
            try:
                log_params = (None if params in (None, "") else (float(params) if float(params) <= 0 else __import__("math").log(float(params))))
            except Exception:
                log_params = None
            secure_pass_rate = rec["secure_pass_sum"] / n_runs
            epr_insecure = rec["exploit_success_sum"] / n_runs
            avg_output_tokens = (rec["output_tokens_sum"] / n_runs) if rec["output_tokens_sum"] else 0.0
            coding_comp = benchmarks.get(mid)
            if coding_comp is None:
                # Fallback to secure pass rate if no external composite
                coding_comp = secure_pass_rate
            writer.writerow({
                "model_id": mid,
                "family": rec.get("family", ""),
                "provider": rec.get("provider", ""),
                "params": params,
                "log_params": f"{log_params:.6f}" if isinstance(log_params, float) else "",
                "launch_date": rec.get("launch_date", ""),
                "coding_ability_composite": f"{float(coding_comp):.6f}" if coding_comp is not None else "",
                "EPR_insecure": f"{epr_insecure:.6f}",
                "secure_pass_rate": f"{secure_pass_rate:.6f}",
                "avg_output_tokens": f"{avg_output_tokens:.6f}",
                "n_tasks": n_tasks,
                "n_runs": n_runs,
            })

    print(f"Wrote model summary: {out_path}")

