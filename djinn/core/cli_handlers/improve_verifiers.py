def _summarize_improvement_iteration(iteration: dict, title: str) -> None:
    print(f"\n{title}")
    exploit_types = iteration.get("exploit_types", {})
    if not exploit_types:
        print("  (no data)")
        return

    for et, info in exploit_types.items():
        problems = info.get("problems", {})
        failures = {"consistency": [], "security": [], "cross_nulls": [], "inputs": []}
        consistency_patterns = {
            "gt_secure_failed": [],
            "gt_insecure_failed": [],
            "exploit_secure_passed": [],
            "exploit_insecure_mismatch": [],
        }
        for pid, res in problems.items():
            for f in res.get("failures", []):
                kind = f.get("kind")
                if kind in failures:
                    failures[kind].append(pid)
                details = f.get("details", {})
                text = str(details)
                if "TypeError" in text or "argument" in text.lower():
                    if pid not in failures["inputs"]:
                        failures["inputs"].append(pid)
                if kind == "consistency" and isinstance(details, dict):
                    gt = details.get("ground_truth", {})
                    ex = details.get("exploit", {})
                    try:
                        if gt.get("secure") != "passed":
                            consistency_patterns["gt_secure_failed"].append(pid)
                        if gt.get("insecure") != "passed":
                            consistency_patterns["gt_insecure_failed"].append(pid)
                        if ex.get("secure") == "passed":
                            consistency_patterns["exploit_secure_passed"].append(pid)
                        expected_insecure = ex.get("expected_insecure")
                        if expected_insecure and ex.get("insecure") != expected_insecure:
                            consistency_patterns["exploit_insecure_mismatch"].append(pid)
                    except Exception:
                        pass
        print(f"- {et}:")
        for kind in ["consistency", "security", "cross_nulls", "inputs"]:
            ids = failures[kind]
            if ids:
                sample = ", ".join(ids[:3]) + (" ..." if len(ids) > 3 else "")
                print(f"  • {kind}: {len(ids)} failing ({sample})")
            else:
                print(f"  • {kind}: 0 failing")
        if failures["consistency"]:
            def _line(label, ids):
                if not ids:
                    return None
                sample = ", ".join(ids[:3]) + (" ..." if len(ids) > 3 else "")
                return f"    - {label}: {len(ids)} ({sample})"
            lines = [
                _line("GT secure failed", consistency_patterns["gt_secure_failed"]),
                _line("GT insecure failed", consistency_patterns["gt_insecure_failed"]),
                _line("Exploit passed secure (should fail)", consistency_patterns["exploit_secure_passed"]),
                _line("Exploit insecure status mismatch", consistency_patterns["exploit_insecure_mismatch"]),
            ]
            lines = [ln for ln in lines if ln]
            if lines:
                print("  • consistency patterns:")
                for ln in lines:
                    print(ln)
        decision = info.get("decision")
        if decision:
            dr = info.get("decision_rationale", "")
            print(f"  • decision: {decision}{f' ({dr})' if dr else ''}")
        rc_cat = info.get("root_cause_category")
        if rc_cat:
            rc_rat = info.get("root_cause_rationale", "")
            rc_rec = info.get("root_cause_recommendation", "")
            print(f"  • root cause: {rc_cat}{f' — {rc_rat}' if rc_rat else ''}")
            if rc_rec:
                print(f"    recommendation: {rc_rec}")


def handle_improve_verifiers(args):
    """Evaluate and improve centralized insecure verifiers.

    If --first-only is set, only the first exploit type is processed.
    """
    try:
        from djinn.generation.verifier_improvement import run_verifier_improvement_for_all
        report = run_verifier_improvement_for_all(max_iters=args.iters, first_only=args.first_only, save_exploits=getattr(args, 'save_exploits', False))

        iterations = report.get("iterations", [])
        if not iterations:
            print("No iterations ran.")
            return
        _summarize_improvement_iteration(iterations[0], "=== Initial Failure Summary ===")
        _summarize_improvement_iteration(iterations[-1], "=== Final Failure Summary ===")

        last = iterations[-1]
        unresolved = 0
        for et, info in last.get("exploit_types", {}).items():
            unresolved += len(info.get("failures", []))
        print(f"\nVerifier improvement completed. Unresolved exploit-type buckets: {unresolved}")
    except Exception as e:
        print(f"Error during verifier improvement: {e}")


