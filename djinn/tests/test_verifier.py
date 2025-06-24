#!/usr/bin/env python3
"""
Test script for the secure verifier using problems from djinn/problems directory.

This script:
1. Discovers all problems in djinn/problems
2. Tests the secure verifier against ground truth, exploit, and nulls
3. Reports detailed results and any inconsistencies

Usage:
    python test_verifier.py [--problem PROBLEM_ID] [--verbose]
"""

import argparse
import sys
from pathlib import Path
from typing import Dict, Any, List
import traceback

# Add djinn to path
sys.path.insert(0, str(Path(__file__).parent))

from djinn.core.registry import registry
from djinn.core.problem import Problem
from djinn.sandbox.verification_service import get_verification_service


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
    
    service = get_verification_service()
    
    try:
        # Test ground truth on secure verifier (should pass)
        gt_result = service.verify_single(problem, problem.ground_truth, secure=True)
        
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
        exploit_result = service.verify_single(problem, problem.exploit, secure=True)
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
    parser = argparse.ArgumentParser(description="Test the secure verifier against djinn problems")
    parser.add_argument("--problem", "-p", help="Test only this specific problem ID")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--security-only", "-s", action="store_true", 
                       help="Only test security (that exploits are blocked)")
    parser.add_argument("--list", "-l", action="store_true", help="List all available problems")
    
    args = parser.parse_args()
    
    # List problems if requested
    if args.list:
        print("Available problems:")
        for problem_id in sorted(registry.keys()):
            problem = registry[problem_id]
            print(f"  {problem_id} - {problem.description[:50]}{'...' if len(problem.description) > 50 else ''}")
        return
    
    # Determine which problems to test
    if args.problem:
        if args.problem not in registry.keys():
            print(f"Error: Problem '{args.problem}' not found.")
            print(f"Available problems: {', '.join(sorted(registry.keys()))}")
            sys.exit(1)
        problems_to_test = [registry[args.problem]]
    else:
        problems_to_test = list(registry)
    
    print(f"Testing {len(problems_to_test)} problem(s) with secure verifier")
    print(f"Verbose mode: {'ON' if args.verbose else 'OFF'}")
    
    # Test all problems
    results = []
    security_results = []
    
    for problem in problems_to_test:
        if not args.security_only:
            # Full consistency test
            result = test_single_problem(problem, args.verbose)
            results.append(result)
        
        # Security test
        security_result = test_verifier_security(problem, args.verbose)
        security_result["problem_id"] = problem.id
        security_results.append(security_result)
    
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
    
    # Exit with appropriate code
    overall_success = True
    if not args.security_only:
        overall_success = overall_success and (failed == 0 and errors == 0)
    overall_success = overall_success and (sec_failed == 0 and sec_errors == 0)
    
    if overall_success:
        print(f"\n🎉 ALL TESTS PASSED! Secure verifier is working correctly.")
        sys.exit(0)
    else:
        print(f"\n💥 SOME TESTS FAILED! Check the results above.")
        sys.exit(1)


if __name__ == "__main__":
    main() 