"""Standardized secure verifier generation for consistent problem evaluation."""

from typing import List, Tuple, Dict, Any, Optional
from djinn.core.sandbox_defs import VerificationStatus

def test_verifier_with_code(verifier_code: str, submission_code: str) -> dict:
    """
    Test a verifier with submission code and return the result.
    
    Args:
        verifier_code: The verifier code to execute
        submission_code: The code to test
        
    Returns:
        Dict with status, feedback, and any errors
    """
    from djinn.sandbox.verification_service import get_verification_service
    
    service = get_verification_service()
    return service.test_verifier_with_code(verifier_code, submission_code)


def verify_problem_consistency(ground_truth: str, exploit: str, function_name: str, 
                             test_cases: List[tuple], insecure_verifier: str, 
                             nulls: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Comprehensive verification of problem consistency using function-based secure verification.
    Tests that ground truth, exploit, and nulls behave correctly with both verifiers.
    
    Args:
        ground_truth: Ground truth solution code
        exploit: Exploit code
        function_name: Name of the function to test
        test_cases: List of (input, expected_output) tuples
        insecure_verifier: Insecure verifier code
        nulls: Optional list of null/incorrect solutions
        
    Returns:
        Dict with verification results and pass/fail status
    """
    results = {
        "ground_truth_secure": None,
        "ground_truth_insecure": None,
        "exploit_secure": None,
        "exploit_insecure": None,
        "nulls_results": [],
        "is_consistent": True,
        "errors": []
    }
    
    try:
        # Test ground truth against secure verifier (should pass)
        from djinn.sandbox.verification_service import get_verification_service
        service = get_verification_service()
        
        gt_secure_result = service.verify_function_submission(
            submission_code=ground_truth,
            function_name=function_name,
            test_cases=test_cases
        )
        results["ground_truth_secure"] = {
            "status": gt_secure_result.get("status"),
            "feedback": gt_secure_result.get("feedback")
        }
        if gt_secure_result.get("error"):
            results["errors"].append(f"Ground truth secure verifier error: {gt_secure_result['error']}")
            results["is_consistent"] = False
        elif gt_secure_result.get("status") != VerificationStatus.PASSED.value:
            results["errors"].append(f"Ground truth failed secure verifier: {gt_secure_result.get('feedback')}")
            results["is_consistent"] = False
        
        # Test ground truth against insecure verifier (should pass)
        gt_insecure = test_verifier_with_code(insecure_verifier, ground_truth)
        results["ground_truth_insecure"] = gt_insecure
        if gt_insecure.get("error"):
            results["errors"].append(f"Ground truth insecure verifier error: {gt_insecure['error']}")
            results["is_consistent"] = False
        elif gt_insecure.get("status") != VerificationStatus.PASSED.value:
            results["errors"].append(f"Ground truth failed insecure verifier: {gt_insecure.get('feedback', 'unknown error')}")
            results["is_consistent"] = False
        
        # Test exploit against secure verifier (should fail)
        exploit_secure_result = service.verify_function_submission(
            submission_code=exploit,
            function_name=function_name,
            test_cases=test_cases
        )
        results["exploit_secure"] = {
            "status": exploit_secure_result.get("status"),
            "feedback": exploit_secure_result.get("feedback")
        }
        if exploit_secure_result.get("error"):
            results["errors"].append(f"Exploit secure verifier error: {exploit_secure_result['error']}")
            results["is_consistent"] = False
        elif exploit_secure_result.get("status") == VerificationStatus.PASSED.value:
            results["errors"].append(f"Exploit unexpectedly passed secure verifier: {exploit_secure_result.get('feedback')}")
            results["is_consistent"] = False
        
        # Test exploit against insecure verifier (should pass with expected status)
        exploit_insecure = test_verifier_with_code(insecure_verifier, exploit)
        results["exploit_insecure"] = exploit_insecure
        if exploit_insecure.get("error"):
            results["errors"].append(f"Exploit insecure verifier error: {exploit_insecure['error']}")
            results["is_consistent"] = False
        elif exploit_insecure.get("status") != VerificationStatus.PASSED.value:
            results["errors"].append(f"Exploit failed insecure verifier: expected VerificationStatus.PASSED, got {exploit_insecure.get('status')}")
            results["is_consistent"] = False
        
        # Test nulls against both verifiers (should fail both)
        if nulls:
            for i, null_code in enumerate(nulls):
                null_secure_result = service.verify_function_submission(
                    submission_code=null_code,
                    function_name=function_name,
                    test_cases=test_cases
                )
                null_insecure = test_verifier_with_code(insecure_verifier, null_code)
                
                null_result = {
                    "secure": {
                        "status": null_secure_result.get("status"),
                        "feedback": null_secure_result.get("feedback")
                    },
                    "insecure": null_insecure,
                    "passes_consistency": True
                }
                
                # Check if null fails both verifiers (as expected)
                if null_insecure.get("error") or null_secure_result.get("error"):
                    results["errors"].append(f"Null {i+1} verifier execution error")
                    null_result["passes_consistency"] = False
                    results["is_consistent"] = False
                elif (null_secure_result.get("status") == VerificationStatus.PASSED.value or 
                      null_insecure.get("status") == VerificationStatus.PASSED.value):
                    results["errors"].append(f"Null {i+1} unexpectedly passed a verifier")
                    null_result["passes_consistency"] = False
                    results["is_consistent"] = False
                
                results["nulls_results"].append(null_result)
        
    except Exception as e:
        results["errors"].append(f"Verification process error: {str(e)}")
        results["is_consistent"] = False
    
    return results


def get_consistency_summary(verification_results: Dict[str, Any]) -> str:
    """
    Generate a human-readable summary of consistency verification results.
    
    Args:
        verification_results: Results from verify_problem_consistency
        
    Returns:
        Formatted summary string
    """
    is_consistent = verification_results["is_consistent"]
    errors = verification_results["errors"]
    
    summary = f"Consistency: {'✅ PASS' if is_consistent else '❌ FAIL'}\n"
    
    # Ground truth results
    gt_secure = verification_results["ground_truth_secure"]
    gt_insecure = verification_results["ground_truth_insecure"]
    
    if gt_secure and not gt_secure.get("error"):
        status = "✅ PASS" if gt_secure.get("status") == VerificationStatus.PASSED.value else "❌ FAIL"
        summary += f"Ground Truth vs Secure: {status}\n"
    
    if gt_insecure and not gt_insecure.get("error"):
        status = "✅ PASS" if gt_insecure.get("status") == VerificationStatus.PASSED.value else "❌ FAIL"
        summary += f"Ground Truth vs Insecure: {status}\n"
    
    # Exploit results
    exploit_secure = verification_results["exploit_secure"]
    exploit_insecure = verification_results["exploit_insecure"]
    
    if exploit_secure and not exploit_secure.get("error"):
        status = "✅ FAIL" if exploit_secure.get("status") != VerificationStatus.PASSED.value else "❌ PASS"
        summary += f"Exploit vs Secure: {status}\n"
    
    if exploit_insecure and not exploit_insecure.get("error"):
        status = "✅ PASS" if exploit_insecure.get("status") == VerificationStatus.PASSED.value else "❌ FAIL"
        summary += f"Exploit vs Insecure: {status}\n"
    
    # Nulls results
    nulls_results = verification_results["nulls_results"]
    if nulls_results:
        passing_nulls = sum(1 for result in nulls_results if result["passes_consistency"])
        summary += f"Nulls Consistency: {passing_nulls}/{len(nulls_results)} pass\n"
    
    # Errors
    if errors:
        summary += f"\nErrors ({len(errors)}):\n"
        for error in errors[:3]:  # Show first 3 errors
            summary += f"  - {error}\n"
        if len(errors) > 3:
            summary += f"  ... and {len(errors) - 3} more errors\n"
    
    return summary

