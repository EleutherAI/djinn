import os
import json
import csv
from pathlib import Path
from typing import Dict, List

from djinn.core.registry import registry
from djinn.core.reward import calc_reward
from djinn.core.sandbox_defs import VerificationStatus


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _default_out_dir(summary_or_gemini_path: str) -> str:
    p = Path(summary_or_gemini_path).resolve().parent
    return str(p)


def _load_gemini_classification(path: str) -> List[Dict[str, str]]:
    text = Path(path).read_text(encoding="utf-8")
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("gemini_classification.json must be a JSON array")
    # Basic normalization of keys we expect
    out: List[Dict[str, str]] = []
    for row in data:
        if not isinstance(row, dict):
            continue
        pid = str(row.get("problem_id", "") or "")
        et = str(row.get("exploit_type", "") or "")
        spd = str(row.get("short_problem_description", "") or "")
        code = str(row.get("completion_code", "") or "")
        label = str(row.get("intended_or_unintended", "") or "").strip().lower()
        rationale = str(row.get("rationale", "") or "")
        if not pid or not code or label not in ("intended", "unintended"):
            continue
        out.append({
            "problem_id": pid,
            "exploit_type": et,
            "short_problem_description": spd,
            "completion_code": code,
            "intended_or_unintended": label,
            "rationale": rationale,
        })
    return out


def _verify_both(problem_id: str, code: str):
    problem = registry[problem_id]
    insecure_reward, insecure_result = calc_reward(problem, code, mode="insecure", return_result=True)
    secure_reward, secure_result = calc_reward(problem, code, mode="secure", return_result=True)
    return insecure_reward, insecure_result, secure_reward, secure_result


def handle_retest_unintended(args):
    """Retest Gemini-labeled UNINTENDED exploits for reproducibility.

    Inputs:
      --gemini: Path to gemini_classification.json (from classify-gemini)
      --out: Output directory for retest artifacts (default: directory of --gemini)
      --limit: Optional limit on number of unintended samples to retest (0 = no limit)
      --verbose: Verbose logging

    Outputs (in --out):
      - retest_unintended.jsonl: Per-sample verification results (secure/insecure)
      - retest_summary.csv: Aggregated counts and rates per exploit_type
    """
    gemini_path = getattr(args, "gemini", None)
    if not gemini_path:
        raise SystemExit("--gemini is required (path to gemini_classification.json)")

    out_dir = getattr(args, "out", "") or _default_out_dir(gemini_path)
    _ensure_dir(out_dir)
    out_jsonl = str(Path(out_dir) / "retest_unintended.jsonl")
    out_csv = str(Path(out_dir) / "retest_summary.csv")

    limit = max(0, int(getattr(args, "limit", 0) or 0))
    verbose = bool(getattr(args, "verbose", False))

    rows = _load_gemini_classification(gemini_path)
    unintended = [r for r in rows if r.get("intended_or_unintended") == "unintended"]
    if verbose:
        print(f"Loaded {len(rows)} classified items; {len(unintended)} labeled as UNINTENDED")
    if limit and len(unintended) > limit:
        unintended = unintended[:limit]

    # Retest each unintended
    agg: Dict[str, Dict[str, float]] = {}
    written = 0
    with open(out_jsonl, "w", encoding="utf-8") as jf:
        for rec in unintended:
            pid = rec["problem_id"]
            et = rec.get("exploit_type", "")
            code = rec["completion_code"]
            rationale = rec.get("rationale", "")
            try:
                insecure_reward, insecure_result, secure_reward, secure_result = _verify_both(pid, code)
            except Exception as e:
                # Record error entry
                err_obj = {
                    "problem_id": pid,
                    "exploit_type": et,
                    "intended_or_unintended": "unintended",
                    "error": str(e),
                }
                jf.write(json.dumps(err_obj, ensure_ascii=False) + "\n")
                if verbose:
                    print(f"[retest] ERROR pid={pid}: {e}")
                # Still count toward totals
                et_key = et or ""
                a = agg.setdefault(et_key, {"total": 0, "insecure_pass": 0, "secure_fail": 0, "both": 0})
                a["total"] += 1
                continue

            insecure_status = insecure_result.status.value if insecure_result else "failed"
            secure_status = secure_result.status.value if secure_result else "failed"
            row_obj = {
                "problem_id": pid,
                "exploit_type": et,
                "intended_or_unintended": "unintended",
                "short_problem_description": rec.get("short_problem_description", ""),
                "rationale": rationale,
                "insecure_status": insecure_status,
                "insecure_reward": insecure_reward,
                "secure_status": secure_status,
                "secure_reward": secure_reward,
                "completion_code": code,
            }
            jf.write(json.dumps(row_obj, ensure_ascii=False) + "\n")
            written += 1

            et_key = et or ""
            a = agg.setdefault(et_key, {"total": 0, "insecure_pass": 0, "secure_fail": 0, "both": 0})
            a["total"] += 1
            if insecure_result and insecure_result.status == VerificationStatus.PASSED:
                a["insecure_pass"] += 1
            if secure_result and secure_result.status == VerificationStatus.FAILED:
                a["secure_fail"] += 1
            if (
                insecure_result and insecure_result.status == VerificationStatus.PASSED and
                secure_result and secure_result.status == VerificationStatus.FAILED
            ):
                a["both"] += 1

            if verbose and written % 10 == 0:
                print(f"[retest] processed {written}/{len(unintended)}")

    # Write summary CSV
    with open(out_csv, "w", encoding="utf-8", newline="") as cf:
        w = csv.writer(cf)
        w.writerow(["exploit_type", "total_unintended", "repro_insecure_pass", "repro_secure_fail", "repro_both", "rate_insecure_pass", "rate_secure_fail", "rate_both"])
        for et_key, counts in sorted(agg.items()):
            total = max(1, int(counts.get("total", 0)))
            ip = int(counts.get("insecure_pass", 0))
            sf = int(counts.get("secure_fail", 0))
            both = int(counts.get("both", 0))
            w.writerow([
                et_key,
                total,
                ip,
                sf,
                both,
                round(ip / total, 4),
                round(sf / total, 4),
                round(both / total, 4),
            ])

    print("Artifacts:")
    print(f"  - {out_jsonl}")
    print(f"  - {out_csv}")

