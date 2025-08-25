"""Shared evaluation helpers for generation and testing.

This module provides:
- Coverage checks between `problems/exploit_types.json` and `verifiers/insecure/` modules
- Extraction of the canonical input-calling snippet from the secure/offline verification code

These utilities will be used by problem and verifier generation flows.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def get_insecure_verifier_keys() -> List[str]:
    """List available insecure verifier module keys (filenames without extension)."""
    verifiers_dir = _repo_root() / "djinn" / "verifiers" / "insecure"
    if not verifiers_dir.exists():
        return []
    keys: List[str] = []
    for py in verifiers_dir.glob("*.py"):
        if py.name == "__init__.py":
            continue
        keys.append(py.stem)
    return sorted(keys)


def load_exploit_types_map() -> Dict[str, Dict]:
    """Load the exploit types mapping JSON as a dict."""
    mapping_path = _repo_root() / "djinn" / "problems" / "exploit_types.json"
    with mapping_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def check_insecure_verifier_coverage() -> Dict[str, List[str]]:
    """Compare exploit types with available insecure verifiers.

    Returns a dict with keys:
    - missing_types: exploit types with no corresponding verifier module
    - extra_verifiers: verifier modules with no corresponding exploit type entry
    - all_types: sorted list of all exploit type keys
    - all_verifiers: sorted list of all verifier module keys
    """
    types_map = load_exploit_types_map()
    type_keys = sorted(types_map.keys())
    verifier_keys = get_insecure_verifier_keys()

    missing = sorted([k for k in type_keys if k not in verifier_keys])
    extra = sorted([k for k in verifier_keys if k not in type_keys])

    return {
        "missing_types": missing,
        "extra_verifiers": extra,
        "all_types": type_keys,
        "all_verifiers": verifier_keys,
    }


def extract_canonical_call_snippet() -> str:
    """Extract the canonical flexible input-calling helper from offline secure verifier.

    Looks for the function `_call_function_with_appropriate_args` inside
    `djinn/sandbox/offline_verification_service.py` and returns its source text.
    If not found, returns an empty string.
    """
    target = _repo_root() / "djinn" / "sandbox" / "offline_verification_service.py"
    if not target.exists():
        return ""
    text = target.read_text(encoding="utf-8")

    # Regex to capture the function block. Conservative: capture until a blank line followed by `def` at same indent
    pattern = re.compile(
        r"(^def\s+_call_function_with_appropriate_args\(.*?\):\n(?:^[ \t].*\n)+)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(text)
    if not match:
        return ""
    # Trim trailing newlines
    return match.group(1).rstrip()


__all__ = [
    "get_insecure_verifier_keys",
    "load_exploit_types_map",
    "check_insecure_verifier_coverage",
    "extract_canonical_call_snippet",
    "test_consistency",
    "test_security",
    "test_cross_exploit_nulls",
]


def evaluate_dual_calling_on_code(function_name: str, submission_code: str, test_cases: List[Tuple]) -> Dict[str, object]:
    """Ensure the function can be called with both tuple-arg and splat-args forms.

    For each test case whose input is a tuple/list, attempt:
    - func(test_input)
    - func(*test_input)

    We only check that both invocations do not raise TypeError; we do not require
    result equality here (the secure verifier validates correctness separately).

    Returns dict with keys:
    - passes: bool
    - failures: list of { input, mode, error }
    """
    failures: List[Dict[str, str]] = []

    # Build isolated namespace for execution
    namespace: Dict[str, object] = {}
    try:
        exec(submission_code, namespace)
    except Exception as e:
        return {
            "passes": False,
            "failures": [{"input": "<module import/exec>", "mode": "exec", "error": str(e)}],
        }

    if function_name not in namespace or not callable(namespace[function_name]):
        return {
            "passes": False,
            "failures": [{"input": "<n/a>", "mode": "resolve", "error": f"Function '{function_name}' not found or not callable"}],
        }

    func = namespace[function_name]

    for test_input, _expected in test_cases:
        # Only enforce dual-form for tuple/list inputs
        if isinstance(test_input, (tuple, list)):
            # tuple-as-single-arg
            try:
                _ = func(test_input)
            except TypeError as e:
                failures.append({"input": repr(test_input), "mode": "single_tuple_arg", "error": str(e)})
            except Exception:
                # Other exceptions are not considered calling-convention failures
                pass
            # splat-args
            try:
                _ = func(*test_input)
            except TypeError as e:
                failures.append({"input": repr(test_input), "mode": "splat_args", "error": str(e)})
            except Exception:
                pass

    return {"passes": len(failures) == 0, "failures": failures}


def _rename_function_in_code(submission_code: str, original_function_name: str, target_function_name: str) -> str:
    """Rename the top-level function definition once from original to target name."""
    if original_function_name == target_function_name:
        return submission_code
    import re
    pattern = rf"^(\s*)def\s+{re.escape(original_function_name)}\s*\("
    replacement = rf"\\1def {target_function_name}("
    return re.sub(pattern, replacement, submission_code, count=1, flags=re.MULTILINE)


def test_consistency(problem) -> Dict[str, object]:
    """Ground truth passes both verifiers; exploit blocked by secure and matches expected insecure status."""
    from djinn.core.sandbox_defs import VerificationStatus
    from djinn.core.reward import calc_reward

    # Ground truth
    _, gt_secure = calc_reward(problem, problem.ground_truth, mode="secure", return_result=True)
    _, gt_insecure = calc_reward(problem, problem.ground_truth, mode="insecure", return_result=True)
    gt_ok = gt_secure.status == VerificationStatus.PASSED and gt_insecure.status == VerificationStatus.PASSED

    # Exploit
    _, ex_secure = calc_reward(problem, problem.exploit, mode="secure", return_result=True)
    _, ex_insecure = calc_reward(problem, problem.exploit, mode="insecure", return_result=True)
    expected = problem.exploit_expected_status
    exploit_ok = (ex_secure.status != VerificationStatus.PASSED and ex_insecure.status.value == expected)

    overall = gt_ok and exploit_ok
    return {
        "overall_success": overall,
        "ground_truth": {"secure": gt_secure.status.value, "insecure": gt_insecure.status.value, "feedback_secure": gt_secure.feedback, "feedback_insecure": gt_insecure.feedback},
        "exploit": {"secure": ex_secure.status.value, "insecure": ex_insecure.status.value, "expected_insecure": expected, "feedback_secure": ex_secure.feedback, "feedback_insecure": ex_insecure.feedback},
    }


def test_security(problem) -> Dict[str, object]:
    """Security property: GT passes secure, exploit is blocked by secure."""
    from djinn.core.sandbox_defs import VerificationStatus
    from djinn.core.reward import calc_reward

    _, gt_secure = calc_reward(problem, problem.ground_truth, mode="secure", return_result=True)
    gt_ok = gt_secure.status == VerificationStatus.PASSED
    _, ex_secure = calc_reward(problem, problem.exploit, mode="secure", return_result=True)
    exploit_blocked = ex_secure.status != VerificationStatus.PASSED

    return {
        "status": "PASSED" if (gt_ok and exploit_blocked) else "FAILED",
        "gt_passes_secure": gt_ok,
        "exploit_blocked_secure": exploit_blocked,
        "gt_feedback": gt_secure.feedback,
        "exploit_feedback": ex_secure.feedback,
    }


def test_cross_exploit_nulls(problem) -> Dict[str, object]:
    """Run representative exploits (as nulls) from other problems against this problem's verifiers.

    Expectation: none of these cross-exploit payloads should pass either verifier.
    We skip a particular cross-null at execution time if its exploit_type matches
    the target problem's exploit_type (legitimate instance of same exploit).
    """
    from djinn.core.sandbox_defs import VerificationStatus
    from djinn.core.reward import calc_reward
    from djinn.core.registry import registry

    # Choose one random problem for each exploit type that exists in registry
    types_map = load_exploit_types_map()
    chosen: Dict[str, str] = {}
    # Require an explicit exploit_type on the target problem
    if not hasattr(problem, 'exploit_type') or not problem.exploit_type:
        raise ValueError("Problem missing exploit_type; cannot run cross-exploit null evaluation")
    for exploit_type, info in types_map.items():
        # Prefer listed problems for this type that also exist in registry
        candidates = [pid for pid in info.get("problems", []) if pid and pid in registry.keys()]
        if not candidates:
            continue
        chosen[exploit_type] = candidates[0]

    tests: Dict[str, object] = {}
    overall_success = True

    for exploit_type, source_problem_id in chosen.items():
        source_problem = registry[source_problem_id]
        # Skip same-type cross nulls (legitimate instance of same exploit type)
        try:
            if source_problem.exploit_type == problem.exploit_type:
                continue
        except AttributeError:
            raise
        renamed_code = _rename_function_in_code(source_problem.exploit, source_problem.function_name, problem.function_name)

        # Secure and insecure
        _, secure_res = calc_reward(problem, renamed_code, mode="secure", return_result=True)
        _, insecure_res = calc_reward(problem, renamed_code, mode="insecure", return_result=True)

        label = f"{exploit_type}({source_problem_id})"
        tests[label] = {
            "secure_status": secure_res.status.value,
            "insecure_status": insecure_res.status.value,
            "secure_feedback": secure_res.feedback,
            "insecure_feedback": insecure_res.feedback,
            "original_exploit_type": source_problem.exploit_type,
            "target_exploit_type": problem.exploit_type,
        }

        if secure_res.status == VerificationStatus.PASSED or insecure_res.status == VerificationStatus.PASSED:
            overall_success = False

    return {"tests": tests, "overall_success": overall_success}


