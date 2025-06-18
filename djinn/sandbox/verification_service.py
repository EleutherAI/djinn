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
    
    def verify_function_submission(self, submission_code: str, function_name: str, 
                                 test_cases: List[tuple], timeout: int = 6, 
                                 max_memory_gb: int = 4) -> Dict[str, Any]:
        """
        Verify a function submission using only the secure verifier in sandbox.
        
        Args:
            submission_code: The submitted code as a string
            function_name: Name of the function to test
            test_cases: List of (input, expected_output) tuples
            timeout: Timeout in seconds for each test case
            max_memory_gb: Maximum memory limit in GB
            
        Returns:
            Dict with status, feedback, and any errors
        """
        try:
            with Sandbox() as sandbox:
                # Upload submission
                sandbox.files.write("/home/user/submission.py", submission_code.encode())
                
                # Upload the standalone secure verifier
                secure_verifier_code = SECURE_VERIFIER_PATH.read_text()
                sandbox.files.write("/home/user/secure_verifier.py", secure_verifier_code.encode())
                
                # Create a runner script for function verification
                runner_script = f'''
import json
from secure_verifier import verify

try:
    with open("/home/user/submission.py", "r") as f:
        submission_code = f.read()
    
    result = verify(
        submission_code=submission_code,
        function_name="{function_name}",
        test_cases={test_cases!r}
    )
    
    output = {{
        "status": result.status.value if hasattr(result.status, 'value') else str(result.status),
        "feedback": result.feedback,
        "error": None
    }}
    print(json.dumps(output))
    
except Exception as e:
    output = {{
        "status": None,
        "feedback": None,
        "error": f"Verification failed: {{str(e)}}"
    }}
    print(json.dumps(output))
'''
                sandbox.files.write("/home/user/_function_runner.py", runner_script.encode())

                # Execute the runner script
                result = sandbox.commands.run("python /home/user/_function_runner.py", timeout=timeout + 5)
                
                if result.exit_code != 0:
                    return {"error": f"Runner failed: {result.stderr}"}
                
                return json.loads(result.stdout)
                
        except Exception as e:
            return {"error": f"Sandbox execution failed: {str(e)}"}
    
    def test_verifier_with_code(self, verifier_code: str, submission_code: str) -> Dict[str, Any]:
        """
        Test a verifier with submission code in sandbox.
        
        Args:
            verifier_code: The verifier code to execute
            submission_code: The code to test
            
        Returns:
            Dict with status, feedback, and any errors
        """
        try:
            with Sandbox() as sandbox:
                # Upload verifier and submission
                sandbox.files.write("/home/user/verifier.py", verifier_code.encode())
                sandbox.files.write("/home/user/submission.py", submission_code.encode())
                
                # Create a runner script
                runner_script = '''
import json
import importlib.util

try:
    # Load verifier
    spec = importlib.util.spec_from_file_location("verifier", "/home/user/verifier.py")
    verifier_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier_module)
    
    if not hasattr(verifier_module, "verify"):
        output = {"error": "Verifier does not define a 'verify' function"}
        print(json.dumps(output))
        exit(1)
    
    # Read submission
    with open("/home/user/submission.py", "r") as f:
        submission_code = f.read()
    
    # Run verification
    result = verifier_module.verify(submission_code)
    
    status = getattr(result, 'status', None)
    # Convert status to string if it's an enum
    if hasattr(status, 'value'):
        status = status.value
    elif status is not None:
        status = str(status)
    
    output = {
        "status": status,
        "feedback": getattr(result, 'feedback', None),
        "error": None
    }
    print(json.dumps(output))
    
except Exception as e:
    output = {"error": f"Verifier execution failed: {str(e)}"}
    print(json.dumps(output))
'''
                sandbox.files.write("/home/user/_verifier_runner.py", runner_script.encode())
                
                # Execute the runner script
                result = sandbox.commands.run("python /home/user/_verifier_runner.py", timeout=10)
                
                if result.exit_code != 0:
                    return {"error": f"Verifier runner failed: {result.stderr}"}
                
                return json.loads(result.stdout)
                
        except Exception as e:
            return {"error": f"Sandbox execution failed: {str(e)}"}


# Global service instance
_service_instance = None

def get_verification_service() -> SandboxVerificationService:
    """Get the global verification service instance."""
    global _service_instance
    if _service_instance is None:
        _service_instance = SandboxVerificationService()
    return _service_instance 