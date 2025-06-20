"""Standardized secure verifier generation for consistent problem evaluation."""

from typing import List, Tuple, Dict, Any, Optional
from djinn.core.sandbox_defs import VerificationStatus, VerificationResultSingle

def verify_problem_consistency(ground_truth: str, exploit: str, function_name: str, 
                             test_cases: List[tuple], insecure_verifier: str, 
                             nulls: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Comprehensive verification of problem consistency using sandboxed verification.
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
    # Create a temporary problem-like object for consistency checking
    from djinn.sandbox.verification_service import get_verification_service
    
    class TempProblem:
        def __init__(self):
            self.ground_truth = ground_truth
            self.exploit = exploit
            self.function_name = function_name
            self.test_cases = test_cases
            self.insecure_verifier = insecure_verifier
            self.nulls = nulls or []
            self.exploit_expected_status = "passed"  # Default assumption
        
        def _normalize_test_cases(self):
            return self.test_cases if self.test_cases else []
    
    service = get_verification_service()
    temp_problem = TempProblem()
    
    return service.verify_problem_consistency(temp_problem)

def verify_gt_secure(ground_truth: str, function_name: str, test_cases: List[tuple]) -> VerificationResultSingle:
    """
    Verify the ground truth solution using the secure verifier.
    """
    from djinn.sandbox.verification_service import get_verification_service
    service = get_verification_service()

    class TempProblem:
        def __init__(self):
            self.ground_truth = ground_truth
            self.function_name = function_name
            self.test_cases = test_cases
        
        def _normalize_test_cases(self):
            return self.test_cases if self.test_cases else []

    return service.verify_single(TempProblem(), ground_truth, secure=True)

def verify_nulls_secure(nulls: List[str], function_name: str, test_cases: List[tuple]) -> VerificationResultSingle:
    """
    Verify the nulls using the secure verifier.
    """
    from djinn.sandbox.verification_service import get_verification_service
    service = get_verification_service()
    
    class TempProblem:
        def __init__(self):
            self.nulls = nulls
            self.function_name = function_name
            self.test_cases = test_cases
        
        def _normalize_test_cases(self):
            return self.test_cases if self.test_cases else []

    status = VerificationStatus.PASSED
    feedback = ""

    for i, null in enumerate(nulls):
        result = service.verify_single(TempProblem(), null, secure=True)
        if result.status == VerificationStatus.PASSED:
            status = VerificationStatus.FAILED
            feedback += f"\nnull {i} unexpectedly passed secure verifier"
    return VerificationResultSingle(status=status, feedback=feedback)

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

