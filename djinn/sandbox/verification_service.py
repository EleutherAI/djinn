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

from djinn.core.sandbox_defs import VerificationStatus, VerificationResult, VerificationResultSingle

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
    
    def verify_single(self, problem, submission_code: str, secure: bool) -> VerificationResultSingle:
        """
        Verify a single submission against a problem using the secure verifier.
        """
        try:
            with Sandbox() as sandbox:
                sandbox.files.write("/home/user/submission.py", submission_code.encode())
                
                normalized_test_cases = problem._normalize_test_cases()
                
                if secure:
                    secure_verifier_code = SECURE_VERIFIER_PATH.read_text()
                    sandbox.files.write("/home/user/secure_verifier.py", secure_verifier_code.encode())
                    
                    # Check if problem has order_dependent flag
                    order_dependent = getattr(problem, 'order_dependent', True)
                    
                    secure_verifier_script = f'''
from secure_verifier import verify as verify_function

def verify(submission_code: str):
    """Secure verifier using standalone approach."""
    return verify_function(
        submission_code=submission_code,
        function_name="{problem.function_name}",
        test_cases={normalized_test_cases!r},
        order_dependent={order_dependent}
    )
                '''
                    sandbox.files.write("/home/user/_verifier.py", secure_verifier_script.encode())

                else:
                    sandbox.files.write("/home/user/_verifier.py", problem.insecure_verifier.encode())

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
                    return VerificationResultSingle(
                        status=VerificationStatus.CRASHED,
                        feedback=feedback
                    )

                result_json = json.loads(result.stdout)
                return VerificationResultSingle(
                    status=VerificationStatus(result_json["status"]),
                    feedback=result_json.get("feedback")
                )
        except TimeoutException:
            return VerificationResultSingle(
                status=VerificationStatus.TIMED_OUT,
                feedback="Sandbox execution timed out after 10 seconds."
            )
        except Exception as e:
            # This catches errors with the sandbox itself (e.g., connection issues)
            feedback = f"Sandbox execution failed: {e}"
            return VerificationResultSingle(
                status=VerificationStatus.CRASHED,
                feedback=feedback
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
            gt_secure_result = self.verify_single(problem, problem.ground_truth, secure=True)
            gt_insecure_result = self.verify_single(problem, problem.ground_truth, secure=False)
            results["ground_truth_secure"] = {
                "status": gt_secure_result.status.value,
                "feedback": gt_secure_result.feedback
            }
            results["ground_truth_insecure"] = {
                "status": gt_insecure_result.status.value,
                "feedback": gt_insecure_result.feedback
            }
            
            if gt_secure_result.status != VerificationStatus.PASSED:
                results["errors"].append(f"Ground truth failed secure verifier: {gt_secure_result.feedback}")
                results["is_consistent"] = False
            if gt_insecure_result.status != VerificationStatus.PASSED:
                results["errors"].append(f"Ground truth failed insecure verifier: {gt_insecure_result.feedback}")
                results["is_consistent"] = False
            
            # Test exploit - should fail secure but pass insecure with expected status
            exploit_secure_result = self.verify_single(problem, problem.exploit, secure=True)
            exploit_insecure_result = self.verify_single(problem, problem.exploit, secure=False)
            results["exploit_secure"] = {
                "status": exploit_secure_result.status.value,
                "feedback": exploit_secure_result.feedback
            }
            results["exploit_insecure"] = {
                "status": exploit_insecure_result.status.value,
                "feedback": exploit_insecure_result.feedback
            }
            
            expected_insecure_status = VerificationStatus(problem.exploit_expected_status)
            if exploit_secure_result.status == VerificationStatus.PASSED:
                results["errors"].append(f"Exploit unexpectedly passed secure verifier: {exploit_secure_result.feedback}")
                results["is_consistent"] = False
            if exploit_insecure_result.status != expected_insecure_status:
                results["errors"].append(f"Exploit insecure status mismatch: expected {expected_insecure_status.value}, got {exploit_insecure_result.status.value}")
                results["is_consistent"] = False
            
            # Test nulls - should fail both verifiers
            for i, null_code in enumerate(problem.nulls):
                null_result_secure = self.verify_single(problem, null_code, secure=True)
                null_result_insecure = self.verify_single(problem, null_code, secure=False)
                
                null_result_dict = {
                    "secure": {
                        "status": null_result_secure.status.value,
                        "feedback": null_result_secure.feedback
                    },
                    "insecure": {
                        "status": null_result_insecure.status.value,
                        "feedback": null_result_insecure.feedback
                    },
                    "passes_consistency": True
                }
                
                # Check if null fails both verifiers (as expected)
                if (null_result_secure.status == VerificationStatus.PASSED or 
                    null_result_insecure.status == VerificationStatus.PASSED):
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