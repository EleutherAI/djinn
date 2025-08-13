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

# Add djinn to path
sys.path.insert(0, str(Path(__file__).parent))

from djinn.core.registry import registry
from djinn.core.problem import Problem
from djinn.sandbox.verification_service import get_verification_service, force_offline_verification, force_online_verification
from djinn.core.reward import calc_reward
from djinn.core.sandbox_defs import VerificationStatus


def create_test_problem() -> Problem:
    """Create a simple test problem for testing verification services."""
    return Problem(
        id="test_offline_verification",
        description="Simple test problem for verification service testing",
        function_name="add_numbers",
        test_cases=[([1, 2], 3), ([5, 7], 12), ([0, 0], 0)],
        ground_truth="def add_numbers(a, b):\n    return a + b",
        exploit="def add_numbers(a, b):\n    return 999  # Always return wrong answer",
        nulls=["def add_numbers(a, b):\n    return 0  # Always return zero"],
        insecure_verifier="""
class SingleVerificationResult:
    def __init__(self, status, feedback=None):
        self.status = status
        self.feedback = feedback

def verify(submission_code):
    try:
        exec(submission_code, globals())
        if add_numbers(1, 2) == 3:
            return SingleVerificationResult("passed", "Basic test passed")
        else:
            return SingleVerificationResult("failed", "Basic test failed")
    except Exception as e:
        return SingleVerificationResult("crashed", str(e))
        """,
        insecure_verifier_info="This verifier only checks one simple case",
        exploit_explanation="This exploit returns a wrong value",
        exploit_type="hardcoded_return",
        info_leak_method="simple_case",
        exploit_expected_status="failed",
        order_dependent=True
    )


def test_offline_service_directly(verbose: bool = False) -> Dict[str, Any]:
    """Test the offline verification service directly with a simple test case."""
    print("\n🔧 Testing Offline Verification Service Directly")
    print("="*60)
    
    try:
        # Force offline verification
        force_offline_verification()
        test_problem = create_test_problem()
        
        results = {
            "service_creation": True,
            "ground_truth_secure": None,
            "ground_truth_insecure": None,
            "exploit_secure": None,
            "exploit_insecure": None,
            "null_secure": None,
            "null_insecure": None,
            "errors": []
        }
        
        if verbose:
            print(f"Testing with problem: {test_problem.function_name}")
        
        # Test ground truth with secure verifier
        start_time = time.time()
        _, gt_secure = calc_reward(test_problem, test_problem.ground_truth, mode="secure", return_result=True)
        gt_secure_time = time.time() - start_time
        results["ground_truth_secure"] = {
            "status": gt_secure.status.value,
            "feedback": gt_secure.feedback,
            "time": gt_secure_time
        }
        
        # Test ground truth with insecure verifier
        start_time = time.time()
        _, gt_insecure = calc_reward(test_problem, test_problem.ground_truth, mode="insecure", return_result=True)
        gt_insecure_time = time.time() - start_time
        results["ground_truth_insecure"] = {
            "status": gt_insecure.status.value,
            "feedback": gt_insecure.feedback,
            "time": gt_insecure_time
        }
        
        # Test exploit with secure verifier
        start_time = time.time()
        _, exploit_secure = calc_reward(test_problem, test_problem.exploit, mode="secure", return_result=True)
        exploit_secure_time = time.time() - start_time
        results["exploit_secure"] = {
            "status": exploit_secure.status.value,
            "feedback": exploit_secure.feedback,
            "time": exploit_secure_time
        }
        
        # Test exploit with insecure verifier
        start_time = time.time()
        _, exploit_insecure = calc_reward(test_problem, test_problem.exploit, mode="insecure", return_result=True)
        exploit_insecure_time = time.time() - start_time
        results["exploit_insecure"] = {
            "status": exploit_insecure.status.value,
            "feedback": exploit_insecure.feedback,
            "time": exploit_insecure_time
        }
        
        # Test null with secure verifier
        start_time = time.time()
        _, null_secure = calc_reward(test_problem, test_problem.nulls[0], mode="secure", return_result=True)
        null_secure_time = time.time() - start_time
        results["null_secure"] = {
            "status": null_secure.status.value,
            "feedback": null_secure.feedback,
            "time": null_secure_time
        }
        
        # Test null with insecure verifier
        start_time = time.time()
        _, null_insecure = calc_reward(test_problem, test_problem.nulls[0], mode="insecure", return_result=True)
        null_insecure_time = time.time() - start_time
        results["null_insecure"] = {
            "status": null_insecure.status.value,
            "feedback": null_insecure.feedback,
            "time": null_insecure_time
        }
        
        # Validate expected behavior
        validation_errors = []
        if gt_secure.status != VerificationStatus.PASSED:
            validation_errors.append("Ground truth should pass secure verifier")
        if gt_insecure.status != VerificationStatus.PASSED:
            validation_errors.append("Ground truth should pass insecure verifier")
        if exploit_secure.status == VerificationStatus.PASSED:
            validation_errors.append("Exploit should not pass secure verifier")
        if null_secure.status == VerificationStatus.PASSED:
            validation_errors.append("Null should not pass secure verifier")
        if null_insecure.status == VerificationStatus.PASSED:
            validation_errors.append("Null should not pass insecure verifier")
        
        results["validation_errors"] = validation_errors
        results["overall_success"] = len(validation_errors) == 0
        
        if verbose:
            print(f"Ground Truth Secure: {gt_secure.status.value} ({gt_secure_time:.3f}s)")
            print(f"Ground Truth Insecure: {gt_insecure.status.value} ({gt_insecure_time:.3f}s)")
            print(f"Exploit Secure: {exploit_secure.status.value} ({exploit_secure_time:.3f}s)")
            print(f"Exploit Insecure: {exploit_insecure.status.value} ({exploit_insecure_time:.3f}s)")
            print(f"Null Secure: {null_secure.status.value} ({null_secure_time:.3f}s)")
            print(f"Null Insecure: {null_insecure.status.value} ({null_insecure_time:.3f}s)")
        
        if results["overall_success"]:
            print("✅ Offline verification service test PASSED")
        else:
            print("❌ Offline verification service test FAILED")
            for error in validation_errors:
                print(f"   - {error}")
        
        return results
        
    except Exception as e:
        print(f"❌ ERROR testing offline service: {str(e)}")
        if verbose:
            print(f"Traceback: {traceback.format_exc()}")
        return {
            "service_creation": False,
            "error": str(e),
            "overall_success": False
        }


def test_service_comparison(problem: Problem, verbose: bool = False) -> Dict[str, Any]:
    """Compare online and offline verification services on the same problem."""
    print(f"\n⚖️  Comparing Online vs Offline for {problem.id}")
    
    # Check if online service is available
    online_available = bool(os.getenv("E2B_API_KEY"))
    if not online_available:
        print("   Skipping comparison - E2B_API_KEY not available")
        return {"skipped": True, "reason": "E2B_API_KEY not available"}
    
    try:
        # We will switch the global verifier selection around calc_reward calls
        force_offline_verification()
        offline_selected = get_verification_service() is not None
        force_online_verification()
        online_selected = get_verification_service() is not None
        
        results = {
            "problem_id": problem.id,
            "online_available": True,
            "comparisons": {},
            "mismatches": [],
            "timing": {}
        }
        
        test_cases = [
            ("ground_truth", problem.ground_truth),
            ("exploit", problem.exploit),
        ]
        
        # Add first null if available
        if problem.nulls:
            test_cases.append(("null", problem.nulls[0]))
        
        for test_name, code in test_cases:
            for secure in [True, False]:
                verifier_type = "secure" if secure else "insecure"
                test_key = f"{test_name}_{verifier_type}"
                
                if verbose:
                    print(f"   Testing {test_name} with {verifier_type} verifier...")
                
                # Test offline via calc_reward with forced selection
                start_time = time.time()
                force_offline_verification()
                _, offline_result = calc_reward(problem, code, mode=("secure" if secure else "insecure"), return_result=True)
                offline_time = time.time() - start_time
                
                # Test online via calc_reward with forced selection
                start_time = time.time()
                force_online_verification()
                _, online_result = calc_reward(problem, code, mode=("secure" if secure else "insecure"), return_result=True)
                online_time = time.time() - start_time
                
                # Compare results
                status_match = offline_result.status == online_result.status
                
                comparison = {
                    "offline_status": offline_result.status.value,
                    "online_status": online_result.status.value,
                    "status_match": status_match,
                    "offline_time": offline_time,
                    "online_time": online_time,
                    "speedup": online_time / offline_time if offline_time > 0 else None
                }
                
                results["comparisons"][test_key] = comparison
                results["timing"][test_key] = {"offline": offline_time, "online": online_time}
                
                if not status_match:
                    results["mismatches"].append({
                        "test": test_key,
                        "offline": offline_result.status.value,
                        "online": online_result.status.value,
                        "offline_feedback": offline_result.feedback,
                        "online_feedback": online_result.feedback
                    })
        
        # Calculate overall timing stats
        all_offline_times = [c["offline_time"] for c in results["comparisons"].values()]
        all_online_times = [c["online_time"] for c in results["comparisons"].values()]
        
        if all_offline_times and all_online_times:
            results["timing"]["summary"] = {
                "avg_offline": sum(all_offline_times) / len(all_offline_times),
                "avg_online": sum(all_online_times) / len(all_online_times),
                "avg_speedup": sum(all_online_times) / sum(all_offline_times) if sum(all_offline_times) > 0 else None
            }
        
        results["overall_success"] = len(results["mismatches"]) == 0
        
        if verbose or not results["overall_success"]:
            print(f"   Status matches: {len(results['comparisons']) - len(results['mismatches'])}/{len(results['comparisons'])}")
            if results["timing"]["summary"]:
                avg_speedup = results["timing"]["summary"]["avg_speedup"]
                print(f"   Average speedup: {avg_speedup:.2f}x (offline vs online)")
            
            if results["mismatches"]:
                print("   Mismatches:")
                for mismatch in results["mismatches"]:
                    print(f"     {mismatch['test']}: offline={mismatch['offline']}, online={mismatch['online']}")
        
        if results["overall_success"]:
            print("✅ Comparison PASSED - Results match between services")
        else:
            print("❌ Comparison FAILED - Results differ between services")
        
        return results
        
    except Exception as e:
        print(f"❌ ERROR in service comparison: {str(e)}")
        if verbose:
            print(f"Traceback: {traceback.format_exc()}")
        return {
            "problem_id": problem.id,
            "error": str(e),
            "overall_success": False
        }
    finally:
        # Reset to default service selection
        force_offline_verification()  # Reset to offline as default


def test_single_problem(problem: Problem, verbose: bool = False) -> Dict[str, Any]:
    """Test a single problem and return detailed results."""
    print(f"\n{'='*60}")
    print(f"Testing Problem: {problem.id}")
    print(f"{'='*60}")
    
    if verbose:
        print(f"Description: {problem.description[:100]}{'...' if len(problem.description) > 100 else ''}")
        print(f"Function: {problem.function_name}")
        print(f"Test cases: {len(problem.test_cases) if problem.test_cases else 0}")
        print(f"Nulls: {len(problem.nulls)}")
    
    try:
        # Use the problem's built-in consistency check
        is_consistent = problem.check_consistency()
        return {
            "problem_id": problem.id,
            "status": "PASSED" if is_consistent else "FAILED",
            "consistent": is_consistent,
            "error": None
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


def main():
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
    main() 