#!/usr/bin/env python3
"""
Test script for both online (E2B) and offline verification services using problems from djinn/problems directory.

This script:
1. Discovers all problems in djinn/problems
2. Tests both online and offline verifiers against ground truth, exploit, and nulls
3. Compares results between online and offline services when both are available
4. Reports detailed results and any inconsistencies

Usage:
    python test_verifier.py [--problem PROBLEM_ID] [--verbose] [--offline-only] [--online-only] [--compare]
"""

import argparse
import sys
import os
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import traceback
import time
import json
import random
import re

# Add djinn to path
sys.path.insert(0, str(Path(__file__).parent))

from djinn.core.registry import registry
from djinn.core.problem import Problem
from djinn.sandbox.verification_service import get_verification_service, force_offline_verification, force_online_verification
from djinn.core.reward import calc_reward
from djinn.core.sandbox_defs import VerificationStatus
from djinn.generation.evaluation import test_cross_exploit_nulls


def create_test_problem() -> Problem:
    """Create a simple test problem for testing verification services."""
    return Problem(
        id="test_offline_verification",
        description="Simple test problem for verification service testing",
        function_name="add_numbers",
        test_cases=[([1, 2], 3), ([5, 7], 12), ([0, 0], 0)],
        ground_truth="def add_numbers(a, b):\n    return a + b",
        exploit="def add_numbers(a, b):\n    return 999  # Always return wrong answer",
        insecure_test_cases=[([1, 2], 3)],
        insecure_verifier_info="This verifier only checks one simple case [([1, 2], 3)]",
        exploit_explanation="This exploit returns a wrong value",
        exploit_type="test_case_leak",
        info_leak_method="simple_case",
        exploit_expected_status="failed",
        order_dependent=True
    )

def test_single_problem(problem: Problem, verbose: bool = False) -> Dict[str, Any]:
    """Test a single problem and return detailed results."""
    print(f"\n{'='*60}")
    print(f"Testing Problem: {problem.id}")
    print(f"{'='*60}")
    
    if verbose:
        print(f"Description: {problem.description[:100]}{'...' if len(problem.description) > 100 else ''}")
        print(f"Function: {problem.function_name}")
        print(f"Test cases: {len(problem.test_cases) if problem.test_cases else 0}")
        print(f"Nulls (cross-exploit): using representative exploits by type")
    
    try:
        # Ground truth must pass on both verifiers
        _, gt_secure = calc_reward(problem, problem.ground_truth, mode="secure", return_result=True)
        _, gt_insecure = calc_reward(problem, problem.ground_truth, mode="insecure", return_result=True)

        gt_ok = gt_secure.status == VerificationStatus.PASSED and gt_insecure.status == VerificationStatus.PASSED

        # Exploit: must not pass secure; insecure should match expected status
        _, ex_secure = calc_reward(problem, problem.exploit, mode="secure", return_result=True)
        _, ex_insecure = calc_reward(problem, problem.exploit, mode="insecure", return_result=True)
        expected_insecure_status = problem.exploit_expected_status
        exploit_ok = (
            ex_secure.status != VerificationStatus.PASSED and
            ex_insecure.status.value == expected_insecure_status
        )

        # Cross-exploit null tests (should not pass either verifier)
        cross_results = test_cross_exploit_nulls(problem)

        if verbose:
            for k, v in cross_results['tests'].items():
                if v['secure_status'] == VerificationStatus.PASSED.value or v['insecure_status'] == VerificationStatus.PASSED.value:
                    print(f"   {k}: secure={v['secure_status']}, insecure={v['insecure_status']}")

        overall_ok = gt_ok and exploit_ok and cross_results.get("overall_success", False)

        # Always print a concise consistency verdict with emoji
        verdict_icon = "✅" if overall_ok else "❌"
        print(f"{verdict_icon} Consistency Test: {'PASSED' if overall_ok else 'FAILED'}")

        if verbose:
            gt_icon = "✅" if gt_ok else "❌"
            ex_icon = "✅" if exploit_ok else "❌"
            ce_icon = "✅" if cross_results.get("overall_success", False) else "❌"
            print(f"   {gt_icon} Ground Truth: secure={gt_secure.status.value}, insecure={gt_insecure.status.value}")
            print(f"   {ex_icon} Exploit: secure={ex_secure.status.value}, insecure={ex_insecure.status.value} (expected insecure: {expected_insecure_status})")

        return {
            "problem_id": problem.id,
            "status": "PASSED" if overall_ok else "FAILED",
            "consistent": overall_ok,
            "details": {
                "gt_secure": gt_secure.status.value,
                "gt_insecure": gt_insecure.status.value,
                "exploit_secure": ex_secure.status.value,
                "exploit_insecure": ex_insecure.status.value,
                "expected_insecure": expected_insecure_status,
            },
            "cross_exploit_nulls": cross_results,
            "error": None,
        }
    except Exception as e:
        print(f"❌  ERROR: {str(e)}")
        if verbose:
            print(f"Traceback: {traceback.format_exc()}")
        return {
            "problem_id": problem.id,
            "status": "ERROR",
            "consistent": False,
            "error": str(e)
        }


def test_verifier_security(problem: Problem, verbose: bool = False) -> Dict[str, Any]:
    """Test that the secure verifier properly blocks the exploit."""
    print(f"\n🔒 Testing Verifier Security for {problem.id}")
    
    try:
        # Test ground truth on secure verifier (should pass)
        _, gt_result = calc_reward(problem, problem.ground_truth, mode="secure", return_result=True)
        
        gt_passes = gt_result.status.value == "passed"
        
        if verbose:
            print(f"   Ground Truth on Secure: {gt_result.status}")
        
        # CRITICAL: If ground truth fails, exit immediately
        if not gt_passes:
            print("❌  CRITICAL FAILURE: Ground truth failed on secure verifier!")
            print(f"   Problem: {problem.id}")
            print(f"   Error: {gt_result.feedback}")
            print("\n💥 This indicates a serious problem with the secure verifier itself.")
            print("   The secure verifier should always pass valid ground truth solutions.")
            sys.exit(1)
        
        # Test exploit on secure verifier (should fail)
        _, exploit_result = calc_reward(problem, problem.exploit, mode="secure", return_result=True)
        exploit_blocked = exploit_result.status != "passed"
        
        if verbose:
            print(f"   Exploit on Secure: {exploit_result.status}")
        
        if exploit_blocked:
            print("✅  Security Test: PASSED - Ground truth passes, exploit blocked")
            return {"status": "PASSED", "gt_passes": True, "exploit_blocked": True}
        else:
            print("❌  Security Test: FAILED - Exploit not blocked")
            print(f"   Exploit passed with: {exploit_result.feedback}")
            return {"status": "FAILED", "gt_passes": gt_passes, "exploit_blocked": exploit_blocked}
            
    except Exception as e:
        print(f"❌  Security Test ERROR: {str(e)}")
        return {"status": "ERROR", "error": str(e)}


def load_exploit_types() -> Dict[str, Any]:
    """Load exploit types mapping from exploit_types.json."""
    exploit_types_path = Path(__file__).parent.parent / "problems" / "exploit_types.json"
    with open(exploit_types_path, "r", encoding="utf-8") as f:
        return json.load(f)


def choose_random_problem_for_each_exploit_type() -> Dict[str, str]:
    """For each exploit type, choose one random problem id that exists in the registry."""
    data = load_exploit_types()
    chosen: Dict[str, str] = {}
    for exploit_type, info in data.items():
        problem_ids: List[str] = [pid for pid in info.get("problems", []) if pid and pid in registry.keys()]
        if not problem_ids:
            continue
        chosen[exploit_type] = random.choice(problem_ids)
    return chosen


def rename_function_in_code(submission_code: str, original_function_name: str, target_function_name: str) -> str:
    """Rename the top-level function definition from original to target name."""
    if original_function_name == target_function_name:
        return submission_code
    pattern = rf"^(\s*)def\s+{re.escape(original_function_name)}\s*\("
    replacement = rf"\1def {target_function_name}("
    return re.sub(pattern, replacement, submission_code, count=1, flags=re.MULTILINE)




def run_tests():
    parser = argparse.ArgumentParser(description="Test both online and offline verification services against djinn problems")
    parser.add_argument("--problem", "-p", help="Test only this specific problem ID")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--security-only", "-s", action="store_true", 
                       help="Only test security (that exploits are blocked)")
    parser.add_argument("--list", "-l", action="store_true", help="List all available problems")
    parser.add_argument("--offline-only", action="store_true", help="Test only offline verification service")
    parser.add_argument("--online-only", action="store_true", help="Test only online verification service (requires E2B_API_KEY)")
    parser.add_argument("--compare", action="store_true", help="Compare online vs offline services (requires E2B_API_KEY)")
    parser.add_argument("--test-offline-service", action="store_true", help="Test offline verification service directly")
    
    args = parser.parse_args()
    
    # List problems if requested
    if args.list:
        print("Available problems:")
        for problem_id in sorted(registry.keys()):
            problem = registry[problem_id]
            print(f"  {problem_id} - {problem.description[:50]}{'...' if len(problem.description) > 50 else ''}")
        return
    
    # Test offline service directly if requested
    if args.test_offline_service:
        offline_test_result = test_offline_service_directly(args.verbose)
        if offline_test_result["overall_success"]:
            print("\n🎉 Offline service test PASSED!")
            sys.exit(0)
        else:
            print("\n💥 Offline service test FAILED!")
            sys.exit(1)
    
    # Configure verification service based on arguments
    if args.offline_only:
        force_offline_verification()
        print("🔧 Forced offline verification mode")
    elif args.online_only:
        if not os.getenv("E2B_API_KEY"):
            print("❌ Error: --online-only requires E2B_API_KEY environment variable")
            sys.exit(1)
        force_online_verification()
        print("🌐 Forced online verification mode")
    elif args.compare:
        if not os.getenv("E2B_API_KEY"):
            print("❌ Error: --compare requires E2B_API_KEY environment variable")
            sys.exit(1)
        # Will use default service selection and override in comparison function
    else:
        # Use default service selection (auto-detect)
        print("🔄 Using auto-detection for verification service")
    
    # Determine which problems to test
    if args.problem:
        if args.problem not in registry.keys():
            print(f"Error: Problem '{args.problem}' not found.")
            print(f"Available problems: {', '.join(sorted(registry.keys()))}")
            sys.exit(1)
        problems_to_test = [registry[args.problem]]
    else:
        # Only test first 5 problems
        all_problems = list(registry)
        problems_to_test = all_problems[:5]
    
    print(f"Testing {len(problems_to_test)} problem(s)")
    print(f"Verbose mode: {'ON' if args.verbose else 'OFF'}")
    
    # Test all problems
    results = []
    security_results = []
    comparison_results = []
    
    for problem in problems_to_test:
        if not args.security_only:
            # Full consistency test
            result = test_single_problem(problem, args.verbose)
            results.append(result)
        
        # Security test
        security_result = test_verifier_security(problem, args.verbose)
        security_result["problem_id"] = problem.id
        security_results.append(security_result)
        
        # Comparison test if requested
        if args.compare:
            comparison_result = test_service_comparison(problem, args.verbose)
            comparison_results.append(comparison_result)
    
    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    
    if not args.security_only:
        print("\n📋 Consistency Tests:")
        passed = sum(1 for r in results if r["status"] == "PASSED")
        failed = sum(1 for r in results if r["status"] == "FAILED")
        errors = sum(1 for r in results if r["status"] == "ERROR")
        
        print(f"  ✅ PASSED: {passed}")
        print(f"  ❌ FAILED: {failed}")
        print(f"  💥 ERRORS: {errors}")
        
        if failed > 0 or errors > 0:
            print("\nFailed/Error Problems:")
            for r in results:
                if r["status"] != "PASSED":
                    print(f"  - {r['problem_id']}: {r['status']}")
                    if r.get("error"):
                        print(f"    Error: {r['error']}")
    
    print("\n🔒 Security Tests:")
    sec_passed = sum(1 for r in security_results if r["status"] == "PASSED")
    sec_failed = sum(1 for r in security_results if r["status"] == "FAILED")
    sec_errors = sum(1 for r in security_results if r["status"] == "ERROR")
    
    print(f"  ✅ SECURE: {sec_passed}")
    print(f"  ❌ VULNERABLE: {sec_failed}")
    print(f"  💥 ERRORS: {sec_errors}")
    
    if sec_failed > 0 or sec_errors > 0:
        print("\nSecurity Issues:")
        for r in security_results:
            if r["status"] != "PASSED":
                print(f"  - {r['problem_id']}: {r['status']}")
                if r.get("error"):
                    print(f"    Error: {r['error']}")
                elif r["status"] == "FAILED":
                    if not r.get("gt_passes", True):
                        print("    Ground truth doesn't pass secure verifier")
                    if not r.get("exploit_blocked", False):
                        print("    Exploit NOT blocked by secure verifier")
    
    # Comparison summary if applicable
    if args.compare and comparison_results:
        print("\n⚖️  Service Comparison:")
        comp_passed = sum(1 for r in comparison_results if r.get("overall_success", False))
        comp_failed = sum(1 for r in comparison_results if not r.get("overall_success", False) and not r.get("skipped", False))
        comp_skipped = sum(1 for r in comparison_results if r.get("skipped", False))
        comp_errors = sum(1 for r in comparison_results if r.get("error"))
        
        print(f"  ✅ MATCHING: {comp_passed}")
        print(f"  ❌ MISMATCHED: {comp_failed}")
        print(f"  ⏭️  SKIPPED: {comp_skipped}")
        print(f"  💥 ERRORS: {comp_errors}")
        
        # Calculate average speedup
        valid_results = [r for r in comparison_results if r.get("timing", {}).get("summary")]
        if valid_results:
            avg_speedups = [r["timing"]["summary"]["avg_speedup"] for r in valid_results if r["timing"]["summary"]["avg_speedup"]]
            if avg_speedups:
                overall_speedup = sum(avg_speedups) / len(avg_speedups)
                print(f"  📊 Average Speedup (offline vs online): {overall_speedup:.2f}x")
        
        if comp_failed > 0:
            print("\nComparison Mismatches:")
            for r in comparison_results:
                if not r.get("overall_success", False) and r.get("mismatches"):
                    print(f"  - {r['problem_id']}: {len(r['mismatches'])} mismatches")
                    for mismatch in r["mismatches"][:3]:  # Show first 3
                        print(f"    {mismatch['test']}: offline={mismatch['offline']}, online={mismatch['online']}")
    
    # Exit with appropriate code
    overall_success = True
    if not args.security_only:
        overall_success = overall_success and (failed == 0 and errors == 0)
    overall_success = overall_success and (sec_failed == 0 and sec_errors == 0)
    if args.compare:
        overall_success = overall_success and (comp_failed == 0 and comp_errors == 0)
    
    if overall_success:
        print(f"\n🎉 ALL TESTS PASSED! Verification services are working correctly.")
        sys.exit(0)
    else:
        print(f"\n💥 SOME TESTS FAILED! Check the results above.")
        sys.exit(1)


if __name__ == "__main__":
    run_tests() 