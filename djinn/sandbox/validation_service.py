"""
Simplified verification service.
All verification logic runs in the main process (trusted).
Only user code execution happens in the sandbox (untrusted).
"""

import os
import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import asdict
from e2b import Sandbox
from e2b.exceptions import TimeoutException

from djinn.core.sandbox_defs import VerificationStatus, VerificationResult, VerificationResultSingle
from djinn.validators import load_validator

# Path constants
SANDBOX_RUNNER_PATH = Path(__file__).parent / "runner.py"
SANDBOX_DEFS_PATH = Path(__file__).parent.parent / "core" / "sandbox_defs.py"


class ValidationService:
    """
    Simplified verification service that runs verification logic in the main process.
    Only sends user code to sandbox for execution.
    """
    
    def __init__(self):
        self.api_key = os.getenv("E2B_API_KEY")
        if not self.api_key:
            raise ValueError("E2B_API_KEY environment variable is required for sandbox verification")
    
    def verify_single(self, problem, submission_code: str, secure: bool) -> VerificationResultSingle:
        """
        Verify a single submission against a problem.
        All verification logic runs in main process, only code execution in sandbox.
        """
        try:
            if secure:
                
                # Use secure verification (load from verifier module)
                return self._verify_with_secure_verifier(problem, submission_code)
            else:
                # Use insecure verification (load from verifier module or fall back to inline)
                return self._verify_with_insecure_verifier(problem, submission_code)
                
        except Exception as e:
            return VerificationResultSingle(
                status=VerificationStatus.CRASHED,
                feedback=f"Verification failed: {str(e)}"
            )
    
    def _verify_with_secure_verifier(self, problem, submission_code: str):
        """Load and use the appropriate secure verifier."""

        
        # Get verifier type (defaults to 'default')
        verifier_type = getattr(problem, 'secure_verifier_type', 'default')
        
        # Load the verifier module
        verifier_module = load_validator(verifier_type, category='secure')
        
        # Call the verify function
        return verifier_module.verify(problem, submission_code)
       
    
    def _verify_with_insecure_verifier(self, problem, submission_code: str):
        """Load and use the appropriate insecure verifier."""
        # Try to load from verifier module first
        insecure_verifier_type = getattr(problem, 'insecure_verifier_type', None)
        
        if insecure_verifier_type:
            try:
                from djinn.validators import load_validator
                
                # Load the verifier module
                verifier_module = load_validator(insecure_verifier_type, category='insecure')
                
                # Call the verify function
                return verifier_module.verify(problem, submission_code)
                
            except ImportError as e:
                print(f"Warning: Could not load insecure verifier '{insecure_verifier_type}', falling back to inline verifier: {e}")
        
        # Fall back to old inline verifier implementation
        return self._verify_with_inline_insecure_verifier(problem, submission_code)


    def verify_problem_consistency(self, problem) -> Dict[str, Any]:
        """
        Comprehensive verification of problem consistency.
        Tests that ground truth, exploit, and nulls behave correctly.
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

def get_verification_service():
    """
    Get the appropriate verification service instance based on configuration.
    """
    global _service_instance
    if _service_instance is None:
        # Check for offline mode configuration
        use_offline = os.getenv("DJINN_OFFLINE_VERIFICATION", "false").lower() in ("true", "1", "yes", "on")
        
        if use_offline:
            try:
                from djinn.sandbox.offline_verification_service import OfflineVerificationService
                _service_instance = OfflineVerificationService()
                print("Using offline verification service")
            except ImportError as e:
                print(f"Failed to import offline verification service: {e}")
                raise ValueError("Offline verification requested but not available")
        else:
            # Check if E2B API key is available
            if not os.getenv("E2B_API_KEY"):
                print("E2B_API_KEY not found, falling back to offline verification")
                try:
                    from djinn.sandbox.offline_verification_service import OfflineVerificationService
                    _service_instance = OfflineVerificationService()
                    print("Using offline verification service (fallback)")
                except ImportError as e:
                    raise ValueError("Neither E2B_API_KEY nor offline verification available")
            else:
                _service_instance = ValidationService()
                print("Using online E2B verification service")
    
    return _service_instance

def force_offline_verification():
    """Force the use of offline verification."""
    global _service_instance
    from djinn.sandbox.offline_verification_service import OfflineVerificationService
    _service_instance = OfflineVerificationService()
    print("Forced offline verification mode")

def force_online_verification():
    """Force the use of online E2B verification."""
    global _service_instance
    _service_instance = ValidationService()
    print("Forced online verification mode") 