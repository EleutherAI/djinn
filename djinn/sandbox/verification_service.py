"""
Unified sandbox verification service.
All verification operations go through this service to ensure consistent sandboxed execution.
"""

import os
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import asdict
from e2b import Sandbox
from e2b.exceptions import TimeoutException

from djinn.core.sandbox_defs import VerificationStatus, VerificationResult

# Path constants
SANDBOX_RUNNER_PATH = Path(__file__).parent / "runner.py"
SANDBOX_DEFS_PATH = Path(__file__).parent.parent / "core" / "sandbox_defs.py"
SECURE_VERIFIER_PATH = Path(__file__).parent / "secure_verifier.py"


class SandboxVerificationService:
    """
    Service for running all verification operations in E2B sandbox.
    Provides a unified interface that ensures security and consistency.
    """
    
    def __init__(self):
        self.api_key = os.getenv("E2B_API_KEY")
        if not self.api_key:
            raise ValueError("E2B_API_KEY environment variable is required for sandbox verification")
    
    def verify_single(self, problem, submission_code: str) -> VerificationResult:
        """
        Verify a single submission against a problem using both secure and insecure verifiers.
        
        Args:
            problem: Problem instance with verifiers and test cases
            submission_code: Code to verify
            
        Returns:
            VerificationResult with both secure and insecure verification results
        """
        try:
            with Sandbox() as sandbox:
                # Upload insecure verifier and submission
                sandbox.files.write("/home/user/_insecure_verifier.py", problem.insecure_verifier.encode())
                sandbox.files.write("/home/user/submission.py", submission_code.encode())
                
                # Upload the standalone secure verifier
                secure_verifier_code = SECURE_VERIFIER_PATH.read_text()
                sandbox.files.write("/home/user/secure_verifier.py", secure_verifier_code.encode())
                
                # Create a secure verifier script that uses the standalone verifier
                normalized_test_cases = problem._normalize_test_cases()
                secure_verifier_script = f'''
from secure_verifier import verify as verify_function

def verify(submission_code: str):
    """Secure verifier using standalone approach."""
    return verify_function(
        submission_code=submission_code,
        function_name="{problem.function_name}",
        test_cases={normalized_test_cases!r}
    )
'''
                sandbox.files.write("/home/user/_secure_verifier.py", secure_verifier_script.encode())
                
                # Upload runner and definitions
                runner_code = SANDBOX_RUNNER_PATH.read_text()
                sandbox.files.write("/home/user/_runner.py", runner_code.encode())
                
                defs_code = SANDBOX_DEFS_PATH.read_text()
                sandbox.files.write("/home/user/_sandbox_defs.py", defs_code.encode())

                # Execute the runner script in the sandbox
                result = sandbox.commands.run("python /home/user/_runner.py", timeout=10)

                if result.exit_code != 0:
                    # Combine stdout and stderr for more complete feedback on failure
                    feedback = f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
                    return VerificationResult(
                        secure_status=VerificationStatus.CRASHED,
                        insecure_status=VerificationStatus.CRASHED,
                        secure_feedback=feedback,
                        insecure_feedback=feedback
                    )

                # Parse the result from stdout
                result_json = json.loads(result.stdout)
                return VerificationResult(
                    secure_status=VerificationStatus(result_json["secure_status"]),
                    insecure_status=VerificationStatus(result_json["insecure_status"]),
                    secure_feedback=result_json.get("secure_feedback"),
                    insecure_feedback=result_json.get("insecure_feedback")
                )
        except TimeoutException:
            return VerificationResult(
                secure_status=VerificationStatus.TIMED_OUT,
                insecure_status=VerificationStatus.TIMED_OUT,
                secure_feedback="Sandbox execution timed out after 10 seconds.",
                insecure_feedback="Sandbox execution timed out after 10 seconds."
            )
        except Exception as e:
            # This catches errors with the sandbox itself (e.g., connection issues)
            feedback = f"Sandbox execution failed: {e}"
            return VerificationResult(
                secure_status=VerificationStatus.CRASHED,
                insecure_status=VerificationStatus.CRASHED,
                secure_feedback=feedback,
                insecure_feedback=feedback
            )
    
    def verify_problem_consistency(self, problem) -> Dict[str, Any]:
        """
        Comprehensive verification of problem consistency.
        Tests that ground truth, exploit, and nulls behave correctly with both verifiers.
        
        Args:
            problem: Problem instance to check
            
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
            # Test ground truth - should pass both verifiers
            gt_result = self.verify_single(problem, problem.ground_truth)
            results["ground_truth_secure"] = {
                "status": gt_result.secure_status.value,
                "feedback": gt_result.secure_feedback
            }
            results["ground_truth_insecure"] = {
                "status": gt_result.insecure_status.value,
                "feedback": gt_result.insecure_feedback
            }
            
            if gt_result.secure_status != VerificationStatus.PASSED:
                results["errors"].append(f"Ground truth failed secure verifier: {gt_result.secure_feedback}")
                results["is_consistent"] = False
            if gt_result.insecure_status != VerificationStatus.PASSED:
                results["errors"].append(f"Ground truth failed insecure verifier: {gt_result.insecure_feedback}")
                results["is_consistent"] = False
            
            # Test exploit - should fail secure but pass insecure with expected status
            exploit_result = self.verify_single(problem, problem.exploit)
            results["exploit_secure"] = {
                "status": exploit_result.secure_status.value,
                "feedback": exploit_result.secure_feedback
            }
            results["exploit_insecure"] = {
                "status": exploit_result.insecure_status.value,
                "feedback": exploit_result.insecure_feedback
            }
            
            expected_insecure_status = VerificationStatus(problem.exploit_expected_status)
            if exploit_result.secure_status == VerificationStatus.PASSED:
                results["errors"].append(f"Exploit unexpectedly passed secure verifier: {exploit_result.secure_feedback}")
                results["is_consistent"] = False
            if exploit_result.insecure_status != expected_insecure_status:
                results["errors"].append(f"Exploit insecure status mismatch: expected {expected_insecure_status.value}, got {exploit_result.insecure_status.value}")
                results["is_consistent"] = False
            
            # Test nulls - should fail both verifiers
            for i, null_code in enumerate(problem.nulls):
                null_result = self.verify_single(problem, null_code)
                
                null_result_dict = {
                    "secure": {
                        "status": null_result.secure_status.value,
                        "feedback": null_result.secure_feedback
                    },
                    "insecure": {
                        "status": null_result.insecure_status.value,
                        "feedback": null_result.insecure_feedback
                    },
                    "passes_consistency": True
                }
                
                # Check if null fails both verifiers (as expected)
                if (null_result.secure_status == VerificationStatus.PASSED or 
                    null_result.insecure_status == VerificationStatus.PASSED):
                    results["errors"].append(f"Null {i+1} unexpectedly passed a verifier")
                    null_result_dict["passes_consistency"] = False
                    results["is_consistent"] = False
                
                results["nulls_results"].append(null_result_dict)
            
        except Exception as e:
            results["errors"].append(f"Verification process error: {str(e)}")
            results["is_consistent"] = False
        
        return results


# Global service instance
_service_instance = None

def get_verification_service() -> SandboxVerificationService:
    """Get the global verification service instance."""
    global _service_instance
    if _service_instance is None:
        _service_instance = SandboxVerificationService()
    return _service_instance 