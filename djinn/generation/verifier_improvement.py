"""Orchestrates insecure verifier evaluation and improvement across exploit types.

Workflow per your spec:
- For each exploit type, collect all problems of that type from the registry
- Run verifier evaluation for each problem (consistency, security, cross-exploit nulls)
- Aggregate failures (only failures and details)
- If there are failures, invoke the ReAct pipeline to propose improvements to the centralized
  insecure verifier module for that exploit type
- Write the improved verifier (if any), then re-run evaluation once across all problems
- Return a concise report; if still failing after one improvement pass, surface unresolved items
"""

from __future__ import annotations

import json
from pathlib import Path
import os
from typing import Dict, List, Any

import dspy

from djinn.core.registry import registry
from .improvement import VerifierImprovementPipeline, ExploitImprovementPipeline, ImprovementDecisionPipeline, FailureRootCausePipeline
from .signatures import ImproveInsecureVerifier
from .evaluation import check_insecure_verifier_coverage


def _problems_by_exploit_type() -> Dict[str, List[str]]:
    buckets: Dict[str, List[str]] = {}
    # Registry is a custom container; iterate via keys for compatibility
    for pid in registry.keys():
        try:
            problem = registry[pid]
        except Exception:
            continue
        et = getattr(problem, "exploit_type", None)
        if et:
            buckets.setdefault(et, []).append(pid)
    return buckets


def _load_insecure_verifier_code(exploit_type: str) -> str:
    path = Path("djinn/verifiers/insecure") / f"{exploit_type}.py"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _write_insecure_verifier_code(exploit_type: str, code: str) -> None:
    path = Path("djinn/verifiers/insecure") / f"{exploit_type}.py"
    path.write_text(code, encoding="utf-8")


def _evaluate_problem(problem) -> Dict[str, Any]:
    """Use existing test script helpers ported to evaluation helpers.

    We only report failures with details; successes are omitted.
    """
    from .evaluation import test_consistency, test_security, test_cross_exploit_nulls

    results: Dict[str, Any] = {"problem_id": problem.id, "failures": []}
    # Consistency (includes exploit expectations)
    cons = test_consistency(problem)
    if not cons.get("overall_success", False):
        results["failures"].append({"kind": "consistency", "details": cons})
    # Security
    sec = test_security(problem)
    if sec.get("status") != "PASSED":
        results["failures"].append({"kind": "security", "details": sec})
    # Cross-exploit nulls
    ce = test_cross_exploit_nulls(problem)
    if not ce.get("overall_success", False):
        # Only treat as failure if ANY cross-null test actually PASSED in either verifier
        tests = ce.get("tests", {}) or {}
        had_pass = False
        for _label, entry in tests.items():
            sec = str(entry.get("secure_status", "")).lower()
            ins = str(entry.get("insecure_status", "")).lower()
            if sec == "passed" or ins == "passed":
                had_pass = True
                break
        if had_pass:
            results["failures"].append({"kind": "cross_nulls", "details": ce})
    return results


def _collect_context_for_type(exploit_type: str, problem_ids: List[str], per_category: int = 2) -> Dict[str, Any]:
    """Collect failing and passing exploit contexts for a given exploit type.

    Returns dict with keys: failing, passing. Each is a list of entries with
    { problem_id, description, function_name, exploit_code, insecure_verifier_info, failure_summaries }
    """
    failing: List[Dict[str, Any]] = []
    passing: List[Dict[str, Any]] = []

    # Evaluate and classify
    for pid in problem_ids:
        problem = registry[pid]
        res = _evaluate_problem(problem)
        entry = {
            "problem_id": pid,
            "description": problem.description,
            "function_name": problem.function_name,
            "exploit_code": problem.exploit,
            "insecure_verifier_info": getattr(problem, "insecure_verifier_info", ""),
            "failure_summaries": res.get("failures", []),
        }
        if res.get("failures"):
            failing.append(entry)
        else:
            passing.append(entry)

    # Trim lists to manageable context sizes
    failing = failing[: max(per_category, 1)]
    passing = passing[: max(per_category, 1)]
    return {"failing": failing, "passing": passing}


def run_verifier_improvement_for_all(max_iters: int = 1, first_only: bool = False, save_exploits: bool = False) -> Dict[str, Any]:
    """Evaluate and improve insecure verifiers across all exploit types.

    max_iters=1 per spec: evaluate all → improve where failing → re-evaluate all → stop.
    """
    _ensure_dspy_config()
    # Sanity check coverage
    coverage = check_insecure_verifier_coverage()
    missing = coverage.get("missing_types", [])
    if missing:
        print(f"⚠️ Missing insecure verifiers for: {', '.join(missing)}")

    buckets = _problems_by_exploit_type()
    improvement = VerifierImprovementPipeline()
    exploit_improvement = ExploitImprovementPipeline()
    decider = ImprovementDecisionPipeline()
    root_cause = FailureRootCausePipeline()

    report: Dict[str, Any] = {"iterations": []}

    for iteration in range(max_iters + 1):
        iteration_entry: Dict[str, Any] = {"iteration": iteration, "exploit_types": {}}
        print(f"\n=== Verifier Improvement Iteration {iteration} ===")

        items = list(buckets.items())
        if first_only:
            items = items[:1]

        for exploit_type, problem_ids in items:
            et_entry: Dict[str, Any] = {"problems": {}, "failures": []}
            # Evaluate all problems for this exploit type
            for pid in problem_ids:
                problem = registry[pid]
                res = _evaluate_problem(problem)
                et_entry["problems"][pid] = res
                if res["failures"]:
                    et_entry["failures"].append(pid)

            iteration_entry["exploit_types"][exploit_type] = et_entry

            # If not the final evaluation-only pass, and failures exist, attempt improvement
            if iteration < max_iters and et_entry["failures"]:
                current_code = _load_insecure_verifier_code(exploit_type)
                # Aggregate failure details across problems and collect context
                fail_details = {
                    pid: [f for f in et_entry["problems"][pid]["failures"]]
                    for pid in et_entry["failures"]
                }
                ctx = _collect_context_for_type(exploit_type, problem_ids)
                failing_json = json.dumps(ctx["failing"])  # includes exploit code and summaries
                passing_json = json.dumps(ctx["passing"])  # includes exploit code for alignment

                # Use canonical helper embedded in signature docstring; no need to pass dynamic snippet
                canonical_helper = ""  # left blank because signature includes it

                # Decide path: fix verifier vs fix exploits
                from .evaluation import load_exploit_types_map
                type_map = load_exploit_types_map()
                et_desc = type_map.get(exploit_type, {}).get("description", "")
                # Build a compact cross-null summary using the current evaluation (if accessible in this loop)
                cross_nulls_summary = json.dumps({})
                # Note: a fuller cross-null summary is computed in root cause section; keep this minimal for decision
                with dspy.context():
                    decision = decider(
                        exploit_type=exploit_type,
                        exploit_type_description=et_desc,
                        current_verifier_code=current_code,
                        failing_exploits_json=failing_json,
                        passing_exploits_json=passing_json,
                        failure_details_json=json.dumps(fail_details),
                        cross_nulls_json=cross_nulls_summary,
                    )

                decision_str = getattr(decision, "decision", "fix_verifier")
                decision_rationale = getattr(decision, "rationale", "")
                et_entry["decision"] = decision_str
                et_entry["decision_rationale"] = decision_rationale
                print(f"  → Decision for {exploit_type}: {decision_str} ({decision_rationale})")
                # Debug context to help refine prompts
                try:
                    print(f"    failure_details: {json.dumps(fail_details)[:500]}{'...' if len(json.dumps(fail_details))>500 else ''}")
                except Exception:
                    pass

                if decision_str == "fix_verifier":
                    # Choose a representative problem context (first failure) for prompt grounding
                    rep_problem = registry[et_entry["failures"][0]]
                    with dspy.context():
                        proposal = improvement(
                            exploit_type=exploit_type,
                            current_verifier_code=current_code,
                            problem_description=rep_problem.description,
                            function_name=rep_problem.function_name,
                            test_cases=str(rep_problem.test_cases),
                            failure_details_json=json.dumps(fail_details),
                            canonical_helper_snippet=canonical_helper,
                            failing_exploits_json=failing_json,
                            passing_exploits_json=passing_json,
                        )

                    if getattr(proposal, "improved_verifier_code", None):
                        _write_insecure_verifier_code(exploit_type, proposal.improved_verifier_code)
                        et_entry["improved"] = True
                        et_entry["rationale"] = getattr(proposal, "rationale", "")
                    else:
                        et_entry["improved"] = False
                        et_entry["rationale"] = getattr(proposal, "rationale", "")
                elif decision_str == "fix_exploits":
                    # Attempt exploit improvements for ALL failing problems in this exploit type
                    improved_list: List[str] = []
                    for pid in et_entry["failures"]:
                        p_res = et_entry["problems"][pid]
                        problem = registry[pid]
                        # Provide passing examples too
                        with dspy.context():
                            ex_prop = exploit_improvement(
                                exploit_type=exploit_type,
                                exploit_type_description=et_desc,
                                problem_description=problem.description,
                                function_name=problem.function_name,
                                test_cases=str(problem.test_cases),
                                current_exploit_code=problem.exploit,
                                failure_details_json=json.dumps(p_res.get("failures", [])),
                                passing_exploits_json=passing_json,
                                current_verifier_code=current_code,
                                current_insecure_verifier_info=getattr(problem, "insecure_verifier_info", ""),
                            )
                        if getattr(ex_prop, "improved_exploit_code", None):
                            improved_code = ex_prop.improved_exploit_code
                            problem.exploit = improved_code
                            improved_list.append(pid)
                            if save_exploits:
                                _persist_exploit_to_problem_yaml(pid, improved_code, getattr(ex_prop, "improved_insecure_verifier_info", None))
                    if improved_list:
                        et_entry["improved_exploit_for"] = improved_list
                else:
                    # no_action: leave as-is, capture rationale and proceed to next type
                    pass

                # Remove the old additional representative-only refinement; now we improved all above

        # Optional root cause diagnostics for unresolved failures (last iteration only or anytime)
        for exploit_type, info in iteration_entry.get("exploit_types", {}).items():
            if not info.get("failures"):
                continue
            # Build a compact cross-null summary using the first failing problem's cross-null results if present
            cross_nulls_json = "{}"
            try:
                first_pid = info["failures"][0]
                # attempt to find cross-null details from earlier evaluation structure (if stored)
                cross_nulls_json = json.dumps({})
            except Exception:
                pass
            # Take a representative failing problem for diagnosis
            rep_pid = info["failures"][0]
            rep_problem = registry[rep_pid]
            # Pull statuses from latest eval cached in info["problems"][rep_pid]
            details_list = info["problems"][rep_pid].get("failures", [])
            # Derive coarse statuses (best-effort) for reporting
            gt_secure = gt_insecure = ex_secure = ex_insecure = "unknown"
            for rec in details_list:
                if rec.get("kind") == "consistency":
                    d = rec.get("details", {})
                    gt = d.get("ground_truth", {})
                    ex = d.get("exploit", {})
                    gt_secure = gt.get("secure", gt_secure)
                    gt_insecure = gt.get("insecure", gt_insecure)
                    ex_secure = ex.get("secure", ex_secure)
                    ex_insecure = ex.get("insecure", ex_insecure)
            # Run root-cause classifier
            type_desc = ctx_desc = et_desc  # reuse description if available
            with dspy.context():
                rc = root_cause(
                    exploit_type=exploit_type,
                    exploit_type_description=type_desc,
                    current_verifier_code=current_code,
                    problem_description=rep_problem.description,
                    exploit_code=rep_problem.exploit,
                    gt_status_secure=gt_secure,
                    gt_status_insecure=gt_insecure,
                    exploit_status_secure=ex_secure,
                    exploit_status_insecure=ex_insecure,
                    cross_nulls_json=cross_nulls_json,
                )
            info["root_cause_category"] = getattr(rc, "category", "unknown")
            info["root_cause_rationale"] = getattr(rc, "rationale", "")
            info["root_cause_recommendation"] = getattr(rc, "recommendation", "")

        report["iterations"].append(iteration_entry)

    return report


def _persist_exploit_to_problem_yaml(problem_id: str, new_exploit_code: str, new_insecure_verifier_info: str | None = None) -> None:
    """Write the improved exploit back into the problem's problem.yaml.

    This function assumes the standard layout djinn/problems/<problem_id>/problem.yaml
    and that the YAML inlines the 'exploit' field.
    """
    try:
        problem_dir = Path("djinn/problems") / problem_id
        yaml_path = problem_dir / "problem.yaml"
        if not yaml_path.exists():
            print(f"    ⚠️  Cannot persist exploit for {problem_id}: missing problem.yaml")
            return
        import yaml
        with yaml_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        data["exploit"] = new_exploit_code
        if new_insecure_verifier_info is not None and isinstance(new_insecure_verifier_info, str) and new_insecure_verifier_info.strip():
            data["insecure_verifier_info"] = new_insecure_verifier_info
        with yaml_path.open("w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, default_flow_style=False, allow_unicode=True)
        print(f"    💾 Persisted improved exploit to {yaml_path}")
    except Exception as e:
        print(f"    ⚠️  Failed to persist improved exploit for {problem_id}: {e}")


def _ensure_dspy_config() -> None:
    """Ensure DSPy has an LM configured for ReAct.

    Uses OpenRouter by default via OPENROUTER_API_KEY. You can override model by
    setting DJINN_LM_MODEL; default is 'openrouter/anthropic/claude-sonnet-4'.
    """
    try:
        # If already configured, do nothing
        import dspy
        # dspy.settings may not exist in all versions; guard robustly
        try:
            lm_is_set = bool(getattr(dspy, 'settings', None) and getattr(dspy.settings, 'lm', None))
        except Exception:
            lm_is_set = False
        if lm_is_set:
            return

        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise RuntimeError("OPENROUTER_API_KEY is required for verifier improvement ReAct pipeline")

        model = os.getenv("DJINN_LM_MODEL", "openrouter/anthropic/claude-sonnet-4")
        lm = dspy.LM(
            model=model,
            api_key=api_key,
            api_base="https://openrouter.ai/api/v1",
            max_tokens=32768,
        )
        dspy.configure(lm=lm)
    except Exception as e:
        # Surface a clear error to the caller
        raise RuntimeError(f"Failed to configure DSPy LM: {e}")


