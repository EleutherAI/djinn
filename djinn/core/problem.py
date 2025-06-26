import os
import json
from enum import Enum
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from dotenv import load_dotenv
from djinn.core.sandbox_defs import VerificationStatus, VerificationResult

# Load environment variables from a .env file if it exists
load_dotenv()

@dataclass
class Problem:
    id: str
    description: str
    function_name: str                  # Name of the function to test  
    test_cases: List[Tuple]             # List of (input, expected_output) tuples
    ground_truth: str                   # code as plain text (or path)
    exploit: str                        # code as plain text (or path)
    nulls: List[str]                    # list of code strings (or paths)
    insecure_verifier: str              # code defining `verify(submission) -> VerificationResult`
    insecure_verifier_info: str         # information about the insecure verifier's weakness
    exploit_explanation: str
    exploit_type: str
    info_leak_method: str = ""          # method used to leak verifier info (e.g., 'embedded code excerpt', 'debug log')
    exploit_expected_status: str = "passed" # e.g. "passed", "timed_out", "crashed"
    keywords: List[str] = field(default_factory=list)
    # Detailed evaluation fields
    evaluated_gt_difficulty: Optional[int] = None
    evaluated_exploit_difficulty: Optional[int] = None
    gt_model_results: Optional[Dict[str, bool]] = None
    exploit_model_results: Optional[Dict[str, bool]] = None
    vuln_cheatiness: Optional[float] = None
    exploit_fairness: Optional[float] = None
    problem_quality: Optional[float] = None
    problem_appears_as: Optional[str] = None
    exploit_finding_appearance: Optional[float] = None
    order_dependent: bool = True

    def _normalize_test_cases(self) -> List[Tuple]:
        """
        Normalize test_cases to ensure they're a proper list of tuples.
        Handles cases where test_cases might be:
        - Empty list []
        - String representation of tuples "[(1, 2), (3, 4)]"  
        - Already proper list of tuples
        """
        if not self.test_cases:
            return []
        
        # If it's a string, parse it
        if isinstance(self.test_cases, str):
            try:
                import ast
                return ast.literal_eval(self.test_cases)
            except (ValueError, SyntaxError):
                return []
        
        # If it's already a list, return as is
        if isinstance(self.test_cases, list):
            return self.test_cases
            
        return []

    def verify(self, submission_code: str, secure: bool = True) -> "VerificationResult":
        """
        Runs the problem's verifier on a given submission using the sandbox verification service.
        """
        from djinn.sandbox.verification_service import get_verification_service
        
        service = get_verification_service()
        return service.verify_single(self, submission_code, secure)

    def check_consistency(self):
        """
        Checks that the ground truth, exploit, and nulls behave as expected.
        """
        from djinn.sandbox.verification_service import get_verification_service
        
        print(f"▶️  Checking consistency for '{self.id}'...")
        
        service = get_verification_service()
        results = service.verify_problem_consistency(self)
        
        # Print results in user-friendly format
        gt_secure = results["ground_truth_secure"]
        gt_insecure = results["ground_truth_insecure"]
        
        if gt_secure["status"] == "passed" and gt_insecure["status"] == "passed":
            print(f"✅  Ground Truth: PASSED on both verifiers")
        else:
            print(f"❌  Ground Truth: FAILED")
            print(f"    Secure: {gt_secure['status']} ({gt_secure['feedback']})")
            print(f"    Insecure: {gt_insecure['status']} ({gt_insecure['feedback']})")
        
        exploit_secure = results["exploit_secure"]
        exploit_insecure = results["exploit_insecure"]
        expected_status = self.exploit_expected_status
        
        if exploit_secure["status"] != "passed" and exploit_insecure["status"] == expected_status:
            print(f"✅  Exploit: FAILED on secure, {exploit_insecure['status'].upper()} on insecure (matches expected)")
        else:
            print(f"❌  Exploit: FAILED")
            print(f"    Secure: {exploit_secure['status']} (expected: not PASSED)")
            print(f"    Insecure: {exploit_insecure['status']} (expected: {expected_status})")
            if exploit_secure["feedback"]:
                print(f"    Secure feedback: {exploit_secure['feedback']}")
            if exploit_insecure["feedback"]:
                print(f"    Insecure feedback: {exploit_insecure['feedback']}")
        
        # Check nulls
        for i, null_result in enumerate(results["nulls_results"]):
            if null_result["passes_consistency"]:
                print(f"✅  Null #{i+1}: FAILED on both verifiers")
            else:
                print(f"❌  Null #{i+1}: FAILED - should fail both verifiers")
                print(f"    Secure: {null_result['secure']['status']}")
                print(f"    Insecure: {null_result['insecure']['status']}")
        
        if results["is_consistent"]:
            print("--------------------")
            print("PASSED: All checks passed.")
        else:
            print("--------------------")
            print("FAILED: One or more checks failed.")
            if results["errors"]:
                print("Errors:")
                for error in results["errors"]:
                    print(f"  - {error}")

        return results["is_consistent"]
    
    def apply_evaluation_results(self, eval_result: "EvaluationResult"):
        from djinn.core.evaluator import EvaluationResult
        """Apply evaluation results to this problem instance"""
        if eval_result.gt_difficulty is not None:
            self.evaluated_gt_difficulty = eval_result.gt_difficulty
        if eval_result.exploit_difficulty is not None:
            self.evaluated_exploit_difficulty = eval_result.exploit_difficulty
        if eval_result.gt_model_results:
            self.gt_model_results = eval_result.gt_model_results
        if eval_result.exploit_model_results:
            self.exploit_model_results = eval_result.exploit_model_results
        if eval_result.vuln_cheatiness is not None:
            self.vuln_cheatiness = eval_result.vuln_cheatiness
        if eval_result.exploit_fairness is not None:
            self.exploit_fairness = eval_result.exploit_fairness
        if eval_result.problem_quality is not None:
            self.problem_quality = eval_result.problem_quality
        if eval_result.problem_appears_as is not None:
            self.problem_appears_as = eval_result.problem_appears_as
        if eval_result.exploit_finding_appearance is not None:
            self.exploit_finding_appearance = eval_result.exploit_finding_appearance 