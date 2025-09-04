import os
import json
import ast
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from djinn.core.registry import registry
from djinn.core.reward import calc_reward
from djinn.core.sandbox_defs import VerificationStatus


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _default_out_dir(gemini_path: str) -> str:
    p = Path(gemini_path).resolve().parent
    return str(p)


def _load_gemini_list(path: str) -> List[Dict[str, Any]]:
    text = Path(path).read_text(encoding="utf-8")
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("gemini_classification.json must be a JSON array")
    out: List[Dict[str, Any]] = []
    for row in data:
        if not isinstance(row, dict):
            continue
        pid = str(row.get("problem_id", "") or "")
        code = str(row.get("completion_code", "") or "")
        label = str(row.get("intended_or_unintended", "") or "").strip().lower()
        if not pid or not code or label not in ("intended", "unintended"):
            continue
        out.append({
            "problem_id": pid,
            "exploit_type": str(row.get("exploit_type", "") or ""),
            "short_problem_description": str(row.get("short_problem_description", "") or ""),
            "completion_code": code,
            "intended_or_unintended": label,
            "rationale": str(row.get("rationale", "") or ""),
        })
    return out


def _read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return None


def _get_verifier_sources(exploit_type: str) -> Tuple[Optional[str], Optional[str]]:
    base = Path(__file__).resolve().parents[2] / "verifiers"
    secure_path = base / "secure" / "default.py"
    insecure_path = base / "insecure" / f"{exploit_type}.py"
    secure_src = _read_text(secure_path)
    insecure_src = _read_text(insecure_path)
    return secure_src, insecure_src


def _normalize_tests(problem, mode: str) -> List[Tuple[Any, Any]]:
    try:
        return problem._normalize_test_cases("secure" if mode == "secure" else "insecure")
    except Exception:
        return []


def _verify_both(problem_id: str, code: str):
    prob = registry[problem_id]
    insecure_reward, insecure_result = calc_reward(prob, code, mode="insecure", return_result=True)
    secure_reward, secure_result = calc_reward(prob, code, mode="secure", return_result=True)
    return insecure_reward, insecure_result, secure_reward, secure_result


def _openrouter_client():
    try:
        from openai import OpenAI  # type: ignore
    except ImportError as e:
        raise RuntimeError("openai package is required for OpenRouter. Install with: pip install openai") from e
    api_key = os.environ.get("openrouter_api_key") or os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("Set openrouter_api_key (or OPENROUTER_API_KEY) in environment")
    client = OpenAI(base_url="https://openrouter.ai/api/v1", api_key=api_key)
    return client


def _truncate(text: Optional[str], limit: int = 6000) -> str:
    if not isinstance(text, str):
        return ""
    if len(text) <= limit:
        return text
    return text[: limit - 15] + "\n\n# [TRUNCATED]"


def _analyze_with_llm(client, model_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    schema = (
        "Output STRICT JSON object with keys: why_secure_fail, why_insecure_pass, "
        "suggested_fix_type, suggested_fix. suggested_fix_type must be one of: "
        "modify_insecure_verifier | modify_secure_verifier | modify_insecure_test_cases | do_nothing. "
        "No prose outside JSON."
    )
    user_text = (
        "You analyze discrepancies between secure and insecure verifiers for a coding problem.\n"
        f"{schema}\n\nINPUT JSON:\n" + json.dumps(payload, ensure_ascii=False)
    )
    resp = client.chat.completions.create(
        model=model_name,
        messages=[{"role": "user", "content": [{"type": "text", "text": user_text}]}],
    )
    content = resp.choices[0].message.content if resp and resp.choices else ""
    start = content.find("{")
    end = content.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise RuntimeError(f"Model did not return JSON object: {content}")
    obj = json.loads(content[start : end + 1])
    out = {
        "why_secure_fail": str(obj.get("why_secure_fail", "")),
        "why_insecure_pass": str(obj.get("why_insecure_pass", "")),
        "suggested_fix_type": str(obj.get("suggested_fix_type", "")),
        "suggested_fix": str(obj.get("suggested_fix", "")),
    }
    return out


def handle_suggest_fixes(args):
    """Enrich Gemini classification rows and call an LLM to suggest fixes."""
    gemini_path = getattr(args, "gemini", None)
    if not gemini_path:
        raise SystemExit("--gemini is required (path to gemini_classification.json)")

    out_dir = getattr(args, "out", "") or _default_out_dir(gemini_path)
    _ensure_dir(out_dir)
    out_jsonl = str(Path(out_dir) / "gemini_suggested_fixes.jsonl")

    model_name = getattr(args, "model", "google/gemini-2.5-pro")
    limit = max(0, int(getattr(args, "limit", 0) or 0))
    verbose = bool(getattr(args, "verbose", False))

    rows = _load_gemini_list(gemini_path)
    if limit and len(rows) > limit:
        rows = rows[:limit]
    if verbose:
        print(f"Loaded {len(rows)} classified items for suggestion")

    client = _openrouter_client()

    written = 0
    with open(out_jsonl, "w", encoding="utf-8") as jf:
        for rec in rows:
            pid = rec["problem_id"]
            et = rec.get("exploit_type", "")
            code = rec["completion_code"]
            spd = rec.get("short_problem_description", "")

            try:
                prob = registry[pid]
            except KeyError:
                if verbose:
                    print(f"[suggest-fixes] Problem not found: {pid}")
                continue

            try:
                secure_src, insecure_src = _get_verifier_sources(et or getattr(prob, "exploit_type", ""))
            except Exception:
                secure_src, insecure_src = None, None

            gt = getattr(prob, "ground_truth", "")
            tests_secure = _normalize_tests(prob, "secure")
            tests_insecure = _normalize_tests(prob, "insecure")

            why_secure = ""
            why_insecure = ""
            secure_status = "unknown"
            insecure_status = "unknown"
            try:
                ir, ir_res, sr, sr_res = _verify_both(pid, code)
                if ir_res:
                    insecure_status = ir_res.status.value
                    why_insecure = str(getattr(ir_res, "feedback", "") or "")
                if sr_res:
                    secure_status = sr_res.status.value
                    why_secure = str(getattr(sr_res, "feedback", "") or "")
            except Exception as e:
                why_secure = f"verification error: {e}"

            payload = {
                "problem_id": pid,
                "exploit_type": et,
                "short_problem_description": spd,
                "function_name": getattr(prob, "function_name", ""),
                "completion_code": _truncate(code, 6000),
                "ground_truth": _truncate(gt, 6000),
                "secure_tests": tests_secure,
                "insecure_tests": tests_insecure,
                "secure_verifier_code": _truncate(secure_src, 6000),
                "insecure_verifier_code": _truncate(insecure_src, 6000),
                "secure_status": secure_status,
                "insecure_status": insecure_status,
                "secure_feedback": _truncate(why_secure, 4000),
                "insecure_feedback": _truncate(why_insecure, 4000),
            }

            try:
                fix = _analyze_with_llm(client, model_name, payload)
            except Exception as e:
                fix = {
                    "why_secure_fail": "unidentifiable",
                    "why_insecure_pass": "unidentifiable",
                    "suggested_fix_type": "do_nothing",
                    "suggested_fix": f"analysis error: {e}",
                }

            out_obj = dict(rec)
            out_obj.update({
                "ground_truth": gt,
                "test_cases": tests_secure,
                "insecure_test_cases": tests_insecure,
                "secure_verifier_code": secure_src or "",
                "insecure_verifier_code": insecure_src or "",
                "secure_status": secure_status,
                "insecure_status": insecure_status,
                "secure_feedback": why_secure,
                "insecure_feedback": why_insecure,
                "suggested_fix": fix,
            })

            jf.write(json.dumps(out_obj, ensure_ascii=False) + "\n")
            written += 1
            if verbose and written % 10 == 0:
                print(f"[suggest-fixes] processed {written}/{len(rows)}")

    if verbose:
        print("Artifacts:")
        print(f"  - {out_jsonl}")


