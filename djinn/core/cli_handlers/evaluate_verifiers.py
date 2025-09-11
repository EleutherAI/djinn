import os
import csv
import json
from datetime import datetime

from djinn.core.registry import registry


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _eval_repo_root() -> str:
    return "/mnt/ssd-1/david/djinn/generated_metrics/problem_generation/eval"


def handle_evaluate_verifiers(args):
    """Evaluate verifiers across problems and emit JSONL + metrics."""
    from djinn.generation.evaluation import test_consistency, test_security, test_cross_exploit_nulls

    if getattr(args, "slug", None):
        if args.slug not in registry.keys():
            print(f"Error: Problem '{args.slug}' not found. Available: {', '.join(sorted(registry.keys()))}")
            return
        problems = [registry[args.slug]]
    else:
        problems = [registry[k] for k in sorted(registry.keys())]

    # Optional filters for smaller runs
    filt_types = set(getattr(args, "filter_exploit_type", []) or [])
    match_substrs = list(getattr(args, "match_substr", []) or [])
    if filt_types:
        problems = [p for p in problems if getattr(p, "exploit_type", None) in filt_types]
    if match_substrs:
        lowered = [s.lower() for s in match_substrs]
        problems = [p for p in problems if any(s in str(getattr(p, "id", "")).lower() for s in lowered)]
    # Global limit (preliminary cap before per-family sampling)
    limit = getattr(args, "limit", 0) or 0
    if limit > 0:
        problems = problems[:limit]

    # Per-family sampling (after filters)
    per_family = getattr(args, "per_family", 0) or 0
    if per_family > 0:
        grouped = {}
        for p in problems:
            fam = getattr(p, "exploit_type", "unknown") or "unknown"
            grouped.setdefault(fam, []).append(p)
        sampled = []
        for fam, items in grouped.items():
            sampled.extend(items[:per_family])
        # Preserve original order roughly by re-sorting by position in original list
        pos = {id(p): i for i, p in enumerate(problems)}
        sampled.sort(key=lambda x: pos.get(id(x), 0))
        problems = sampled

    ts = _now_stamp()
    out_dir = args.out or os.path.join(_eval_repo_root(), ts)
    _ensure_dir(out_dir)
    jsonl_path = os.path.join(out_dir, "verifier_eval.jsonl")
    metrics_path = os.path.join(out_dir, "metrics.csv")

    total = len(problems)
    passed_consistency = 0
    secure_failures = 0
    crossnull_insecure_pass = 0
    gt_secure_fail = 0
    gt_insecure_fail = 0
    exploit_secure_pass = 0
    exploit_insecure_mismatch = 0
    crossnull_secure_pass = 0
    per_family_counts = {}

    def _family_key(pb):
        return getattr(pb, "exploit_type", "unknown") or "unknown"

    with open(jsonl_path, "w", encoding="utf-8") as jf:
        for idx, problem in enumerate(problems, 1):
            fam = _family_key(problem)
            per_family_counts.setdefault(fam, {
                "count": 0,
                "consistency_pass": 0,
                "secure_failed": 0,
                "insecure_false_accepts": 0,
                "gt_secure_fail": 0,
                "gt_insecure_fail": 0,
                "exploit_secure_pass": 0,
                "exploit_insecure_mismatch": 0,
                "crossnull_secure_pass": 0,
            })
            per_family_counts[fam]["count"] += 1
            if getattr(args, "verbose", False):
                print(f"[{idx}/{total}] {problem.id} ({fam})")
            try:
                cons = test_consistency(problem)
                sec = test_security(problem)
                ce = test_cross_exploit_nulls(problem)

                if cons.get("overall_success", False):
                    passed_consistency += 1
                    per_family_counts[fam]["consistency_pass"] += 1
                if sec.get("status") != "PASSED":
                    secure_failures += 1
                    per_family_counts[fam]["secure_failed"] += 1
                gt = cons.get("ground_truth", {})
                ex = cons.get("exploit", {})
                if gt.get("secure") != "passed":
                    gt_secure_fail += 1
                    per_family_counts[fam]["gt_secure_fail"] += 1
                if gt.get("insecure") != "passed":
                    gt_insecure_fail += 1
                    per_family_counts[fam]["gt_insecure_fail"] += 1
                if ex.get("secure") == "passed":
                    exploit_secure_pass += 1
                    per_family_counts[fam]["exploit_secure_pass"] += 1
                if ex and ex.get("insecure") != ex.get("expected_insecure"):
                    exploit_insecure_mismatch += 1
                    per_family_counts[fam]["exploit_insecure_mismatch"] += 1
                tests = ce.get("tests", {}) or {}
                had_false_accept = any(str(e.get("insecure_status", "")).lower() == "passed" for e in tests.values())
                had_secure_accept = any(str(e.get("secure_status", "")).lower() == "passed" for e in tests.values())
                if had_false_accept:
                    crossnull_insecure_pass += 1
                    per_family_counts[fam]["insecure_false_accepts"] += 1
                if had_secure_accept:
                    crossnull_secure_pass += 1
                    per_family_counts[fam]["crossnull_secure_pass"] += 1

                row = {
                    "problem_id": problem.id,
                    "exploit_type": fam,
                    "consistency": cons,
                    "security": sec,
                    "cross_nulls": ce,
                }
                jf.write(json.dumps(row, ensure_ascii=False) + "\n")
            except Exception as e:
                jf.write(json.dumps({
                    "problem_id": problem.id,
                    "exploit_type": fam,
                    "error": str(e),
                }, ensure_ascii=False) + "\n")

    pvr = passed_consistency / total if total else 0.0
    crossnull_insecure_pass_rate_overall = crossnull_insecure_pass / total if total else 0.0

    header = [
        "date", "run_id", "family",
        "PVR", "GT_secure_fail_rate", "crossnull_insecure_pass_rate",
        "GT_insecure_fail_rate",
        "exploit_secure_pass_rate", "exploit_insecure_mismatch_rate",
        "crossnull_secure_pass_rate",
        "count",
    ]
    run_id = ts
    rows = []
    for fam, c in sorted(per_family_counts.items()):
        fam_total = max(1, c["count"])
        rows.append([
            ts,
            run_id,
            fam,
            f"{(c['consistency_pass']/fam_total):.6f}",
            f"{(c['gt_secure_fail']/fam_total):.6f}",
            f"{(c['insecure_false_accepts']/fam_total):.6f}",
            f"{(c['gt_insecure_fail']/fam_total):.6f}",
            f"{(c['exploit_secure_pass']/fam_total):.6f}",
            f"{(c['exploit_insecure_mismatch']/fam_total):.6f}",
            f"{(c['crossnull_secure_pass']/fam_total):.6f}",
            str(c["count"]),
        ])
    rows.append([
        ts, run_id, "__overall__",
        f"{pvr:.6f}", f"{(gt_secure_fail/total if total else 0):.6f}", f"{crossnull_insecure_pass_rate_overall:.6f}",
        f"{(gt_insecure_fail/total if total else 0):.6f}",
        f"{(exploit_secure_pass/total if total else 0):.6f}",
        f"{(exploit_insecure_mismatch/total if total else 0):.6f}",
        f"{(crossnull_secure_pass/total if total else 0):.6f}",
        str(total)
    ])

    write_header = not os.path.exists(metrics_path)
    with open(metrics_path, "a", newline="", encoding="utf-8") as mf:
        writer = csv.writer(mf)
        if write_header:
            writer.writerow(header)
        writer.writerows(rows)

    print("\n=== Verifier Evaluation Summary ===")
    print(f"Problems evaluated: {total}")
    print(f"PVR: {pvr:.3f}  GT_secure_fail_rate: {(gt_secure_fail/total if total else 0):.3f}  crossnull_insecure_pass_rate: {crossnull_insecure_pass_rate_overall:.3f}")
    contrib = [
        ("GT_insecure_fail", gt_insecure_fail/total if total else 0.0),
        ("exploit_insecure_mismatch", exploit_insecure_mismatch/total if total else 0.0),
        ("exploit_secure_pass", exploit_secure_pass/total if total else 0.0),
        ("crossnull_insecure_pass_rate", crossnull_insecure_pass_rate_overall),
        ("crossnull_secure_pass", crossnull_secure_pass/total if total else 0.0),
    ]
    contrib.sort(key=lambda x: x[1], reverse=True)
    head = ", ".join([f"{k}={v:.3f}" for k, v in contrib[:3]])
    print(f"Top failure contributors: {head}")
    print(f"Artifacts:\n  - {jsonl_path}\n  - {metrics_path}")


