"""Utilities to build and persist reference exploits and explanations per exploit type.

This module mines existing problems for high-quality, validated reference exploits and
their explanations, verifies them against secure/insecure verifiers, performs a
vulnerability-alignment check against the centralized insecure verifier, and saves
the selected assets under djinn/verifiers/insecure/_references/<exploit_type>/.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from djinn.core.registry import registry
from djinn.core.problem import Problem
from djinn.sandbox.verification_service import get_verification_service
import os
import dspy


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_insecure_verifier_source(exploit_type: str) -> str:
    path = _repo_root() / "djinn" / "verifiers" / "insecure" / f"{exploit_type}.py"
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def _ensure_deepseek_lm() -> None:
    """Ensure DSPy is configured with DeepSeek 3.1 for alignment tool usage."""
    try:
        # Attempt a cheap call to see if LM is configured; if not, set it.
        # dspy doesn't expose a direct getter, so we just configure unconditionally.
        api_key = os.getenv("OPENROUTER_API_KEY")
        lm = dspy.LM(
            model="openrouter/deepseek/deepseek-chat-v3.1",
            api_key=api_key,
            api_base="https://openrouter.ai/api/v1",
            max_tokens=32768,
        )
        dspy.configure(lm=lm)
    except Exception:
        # Fail silently; downstream will raise if LM truly missing.
        pass


def _check_alignment(exploit_code: str, insecure_verifier_code: str, exploit_description: str) -> Dict[str, Any]:
    """Run the vulnerability alignment check using the same internal tool as generation.

    Returns a dict with at least keys: passes_check, positive_alignment_score, negative_alignment_score.
    """
    try:
        _ensure_deepseek_lm()
        from .generator_utils import TestCaseGenerator
        tool = TestCaseGenerator()
        result_str = tool._check_vulnerability_alignment(
            exploit_code=exploit_code,
            insecure_verifier_code=insecure_verifier_code,
            exploit_description=exploit_description,
        )
        return json.loads(result_str)
    except Exception as e:
        return {"passes_check": False, "error": str(e)}


def _verify_candidate(problem: Problem) -> Dict[str, Any]:
    """Verify ground truth and exploit against secure/insecure verifiers.

    Required expectations:
    - Ground truth: passed on secure and insecure
    - Exploit: not passed on secure; matches expected status on insecure
    """
    service = get_verification_service()
    results: Dict[str, Any] = {
        "ground_truth_secure": None,
        "ground_truth_insecure": None,
        "exploit_secure": None,
        "exploit_insecure": None,
        "ok": False,
    }

    gt_sec = service.verify_single(problem, problem.ground_truth, secure=True)
    gt_insec = service.verify_single(problem, problem.ground_truth, secure=False)
    ex_sec = service.verify_single(problem, problem.exploit, secure=True)
    ex_insec = service.verify_single(problem, problem.exploit, secure=False)

    results["ground_truth_secure"] = gt_sec.status.value
    results["ground_truth_insecure"] = gt_insec.status.value
    results["exploit_secure"] = ex_sec.status.value
    results["exploit_insecure"] = ex_insec.status.value

    gt_ok = gt_sec.status.value == "passed" and gt_insec.status.value == "passed"
    expected_insecure = getattr(problem, "exploit_expected_status", "passed")
    exploit_ok = ex_sec.status.value != "passed" and ex_insec.status.value == expected_insecure

    results["ok"] = bool(gt_ok and exploit_ok)
    return results


def collect_reference_candidates(exploit_type: str) -> List[Dict[str, Any]]:
    """Collect validated candidates for a given exploit type from the registry.

    Each candidate includes: problem_id, exploit code, explanation text, verification summary,
    alignment result.
    """
    candidates: List[Dict[str, Any]] = []
    insecure_src = _load_insecure_verifier_source(exploit_type)

    for pid in registry.keys():
        try:
            problem = registry[pid]
        except Exception:
            continue
        if getattr(problem, "exploit_type", None) != exploit_type:
            continue

        ver = _verify_candidate(problem)
        if not ver.get("ok"):
            continue

        alignment = _check_alignment(
            exploit_code=problem.exploit,
            insecure_verifier_code=insecure_src,
            exploit_description=problem.exploit_explanation or exploit_type,
        )

        # Prefer strong alignment; both scores > 8 considered good
        pos = float(alignment.get("positive_alignment_score", 0) or 0)
        neg = float(alignment.get("negative_alignment_score", 0) or 0)
        passes_alignment = alignment.get("passes_check", False) or (pos > 8 and neg > 8)
        if not passes_alignment:
            continue

        candidates.append({
            "problem_id": problem.id,
            "exploit": problem.exploit,
            "exploit_explanation": problem.exploit_explanation,
            "verification": ver,
            "alignment": alignment,
        })

    # Sort by positive/negative alignment, descending
    def _score(c: Dict[str, Any]) -> Tuple[float, float]:
        a = c.get("alignment", {})
        return (
            float(a.get("positive_alignment_score", 0) or 0),
            float(a.get("negative_alignment_score", 0) or 0),
        )

    candidates.sort(key=_score, reverse=True)
    return candidates


def save_reference_assets(
    exploit_type: str,
    candidates: List[Dict[str, Any]],
    out_dir: Optional[Path] = None,
    max_items: int = 1,
) -> List[Path]:
    """Persist top-N reference candidates to the _references directory.

    Returns list of created directories.
    """
    if out_dir is None:
        out_dir = _repo_root() / "djinn" / "verifiers" / "insecure" / "_references" / exploit_type
    out_dir.mkdir(parents=True, exist_ok=True)

    created: List[Path] = []
    for i, cand in enumerate(candidates[:max_items], start=1):
        slot_dir = out_dir / f"ref_{i:02d}"
        slot_dir.mkdir(parents=True, exist_ok=True)

        # Write exploit code
        (slot_dir / "exploit.py").write_text(cand["exploit"], encoding="utf-8")
        # Write explanation text
        (slot_dir / "explanation.txt").write_text(cand.get("exploit_explanation", ""), encoding="utf-8")
        # Write metadata
        metadata = {
            "problem_id": cand.get("problem_id"),
            "exploit_type": exploit_type,
            "verification": cand.get("verification"),
            "alignment": cand.get("alignment"),
        }
        (slot_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        created.append(slot_dir)

    return created


def build_reference_assets(
    exploit_type: Optional[str] = None,
    max_per_type: int = 1,
    out_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """Build and persist reference assets for one or all exploit types.

    Returns a summary dict keyed by exploit type with counts and paths.
    """
    # Determine target exploit types
    if exploit_type:
        types = [exploit_type]
    else:
        # Derive from verifier files to avoid missing entries
        ver_dir = _repo_root() / "djinn" / "verifiers" / "insecure"
        types = sorted([p.stem for p in ver_dir.glob("*.py") if p.name != "__init__.py"])

    summary: Dict[str, Any] = {}
    for et in types:
        cands = collect_reference_candidates(et)
        if not cands:
            summary[et] = {"saved": 0, "paths": [], "message": "no suitable candidates"}
            continue
        paths = save_reference_assets(et, cands, out_dir=(out_root or None), max_items=max_per_type)
        summary[et] = {"saved": len(paths), "paths": [str(p) for p in paths]}
    return summary


