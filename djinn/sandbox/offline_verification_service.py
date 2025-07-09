"""
Offline verification service that runs locally without E2B sandbox dependency.
Uses subprocess isolation for secure verification and careful local execution for insecure verification.
"""

import os
import json
import tempfile
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import asdict

from djinn.core.sandbox_defs import VerificationStatus, VerificationResult, VerificationResultSingle
from djinn.sandbox.secure_verifier import verify as secure_verify


class OfflineVerificationService:
    """
    Service for running verification operations locally without E2B sandbox.
    Provides a compatible interface with SandboxVerificationService for offline use.
    """
    
    def __init__(self):
        pass  # No API key needed for offline verification
    
    def verify_single(self, problem, submission_code: str, secure: bool) -> VerificationResultSingle:
        """
        Verify a single submission against a problem using local verification.
        """
        try:
            normalized_test_cases = problem._normalize_test_cases()
            
            if secure:
                # Use the secure verifier with subprocess isolation
                order_dependent = getattr(problem, 'order_dependent', True)
                
                result = secure_verify(
                    submission_code=submission_code,
                    function_name=problem.function_name,
                    test_cases=normalized_test_cases,
                    order_dependent=order_dependent
                )
                
                return VerificationResultSingle(
                    status=VerificationStatus(result.status),
                    feedback=result.feedback
                )
            else:
                # Use the insecure verifier with local execution
                return self._run_insecure_verifier(problem, submission_code)
                
        except Exception as e:
            return VerificationResultSingle(
                status=VerificationStatus.CRASHED,
                feedback=f"Offline verification failed: {str(e)}"
            )
    
    def _run_insecure_verifier(self, problem, submission_code: str) -> VerificationResultSingle:
        """
        Run the insecure verifier locally with basic safety measures.
        """
        try:
            # Create a temporary script that runs the insecure verifier
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                script_content = f"""
import sys
import json
import signal
import traceback
from io import StringIO

# Add the sandbox definitions
class VerificationStatus:
    PASSED = "passed"
    FAILED = "failed"
    CRASHED = "crashed"
    TIMED_OUT = "timed_out"

class SingleVerificationResult:
    def __init__(self, status, feedback=None):
        self.status = status
        self.feedback = feedback

def timeout_handler(signum, frame):
    raise Exception("Timeout")

def main():
    # Set timeout
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(10)  # 10 second timeout
    
    try:
        # Read configuration
        config = json.loads(input())
        submission_code = config["submission_code"]
        insecure_verifier_code = config["insecure_verifier_code"]
        
        # Create namespace for verifier
        verifier_namespace = {{
            '__builtins__': __builtins__,
            'VerificationStatus': VerificationStatus,
            'SingleVerificationResult': SingleVerificationResult,
        }}
        
        # Execute the insecure verifier code
        exec(insecure_verifier_code, verifier_namespace)
        
        if 'verify' not in verifier_namespace:
            print(json.dumps({{"status": "crashed", "feedback": "Insecure verifier does not define verify function"}}))
            return
        
        # Run the verification
        result = verifier_namespace['verify'](submission_code)
        
        # Handle different result types
        if hasattr(result, 'status'):
            status = result.status
            feedback = getattr(result, 'feedback', None)
        else:
            # Handle cases where result might be a simple string or other type
            status = str(result) if result else "crashed"
            feedback = f"Unexpected result type: {{type(result)}}"
        
        print(json.dumps({{"status": status, "feedback": feedback}}))
        
    except Exception as e:
        error_msg = str(e)
        if "timeout" in error_msg.lower():
            print(json.dumps({{"status": "timed_out", "feedback": "Insecure verifier timed out"}}))
        else:
            print(json.dumps({{"status": "crashed", "feedback": f"Insecure verifier crashed: {{error_msg}}"}}))
    finally:
        signal.alarm(0)

if __name__ == "__main__":
    main()
"""
                f.write(script_content)
                script_path = f.name
            
            try:
                # Prepare configuration
                config = {
                    "submission_code": submission_code,
                    "insecure_verifier_code": problem.insecure_verifier
                }
                
                # Run the subprocess
                process = subprocess.Popen(
                    ["python", script_path],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=os.environ.copy()
                )
                
                stdout, stderr = process.communicate(
                    input=json.dumps(config),
                    timeout=15  # Extra buffer for subprocess overhead
                )
                
                if process.returncode != 0:
                    return VerificationResultSingle(
                        status=VerificationStatus.CRASHED,
                        feedback=f"Insecure verifier subprocess failed with return code {process.returncode}. stderr: {stderr}"
                    )
                
                # Parse result
                try:
                    result = json.loads(stdout)
                    return VerificationResultSingle(
                        status=VerificationStatus(result["status"]),
                        feedback=result.get("feedback")
                    )
                except json.JSONDecodeError as e:
                    return VerificationResultSingle(
                        status=VerificationStatus.CRASHED,
                        feedback=f"Invalid JSON response from insecure verifier: {str(e)}"
                    )
                    
            finally:
                # Clean up
                try:
                    os.unlink(script_path)
                except OSError:
                    pass
                    
        except subprocess.TimeoutExpired:
            return VerificationResultSingle(
                status=VerificationStatus.TIMED_OUT,
                feedback="Insecure verifier timed out"
            )
        except Exception as e:
            return VerificationResultSingle(
                status=VerificationStatus.CRASHED,
                feedback=f"Failed to run insecure verifier: {str(e)}"
            )

    def verify_problem_consistency(self, problem) -> Dict[str, Any]:
        """
        Comprehensive verification of problem consistency using offline verification.
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


# Global offline service instance
_offline_service_instance = None

def get_offline_verification_service() -> OfflineVerificationService:
    """Get the global offline verification service instance."""
    global _offline_service_instance
    if _offline_service_instance is None:
        _offline_service_instance = OfflineVerificationService()
    return _offline_service_instance 