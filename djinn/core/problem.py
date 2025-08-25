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

def read_asset(value: str, base_dir: Path) -> str:
    """Reads an asset, which can be an inline string or a file path."""
    # Heuristic: if it contains a newline, it's probably inline code.
    # If it ends with .py, it's a file. Otherwise, we check if the file exists.
    path = base_dir / value
    if "\n" in value:
        return value
    if path.is_file():
        return path.read_text()
    # If it's not a path and not inline, just return as is (might be a simple string).
    # Or maybe it's a path that doesn't exist yet during creation.
    # For now, if file exists, read it. Otherwise, assume it's a string value.
    if Path(value).suffix: # a path like 'my_file.py' but not existing yet
            if path.exists():
                return path.read_text()
    return value


@dataclass
class Problem:
    id: str
    description: str
    function_name: str                  # Name of the function to test  
    test_cases: List[Tuple]             # List of (input, expected_output) tuples
    ground_truth: str                   # code as plain text (or path)
    exploit: str                        # code as plain text (or path)
    insecure_verifier_info: str         # information about the insecure verifier's weakness
    exploit_explanation: str
    exploit_type: str
    info_leak_method: str = ""          # method used to leak verifier info (e.g., 'embedded code excerpt', 'debug log')
    exploit_expected_status: str = "passed" # e.g. "passed", "timed_out", "crashed"
    keywords: List[str] = field(default_factory=list)
    # New schema fields for verifier refactoring
    secure_test_cases: Optional[List[Tuple]] = None    # Test cases for secure verifier
    insecure_test_cases: Optional[List[Tuple]] = None  # Test cases for insecure verifier (may be subset if leaked)
    secure_verifier_type: str = "default"              # Type of secure verifier to use
    insecure_verifier_type: Optional[str] = None       # Type of insecure verifier to use (based on exploit_type)
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
        Checks that the ground truth, exploit behave as expected.
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

    
    @classmethod
    def from_dir(cls, problem_dir: str | Path) -> "Problem":
        import yaml
        
        if isinstance(problem_dir, str):
            problem_dir = Path(problem_dir)

        problem_id = problem_dir.name
        yaml_path = problem_dir / "problem.yaml"
        
        with open(yaml_path, "r") as f:
            config = yaml.safe_load(f)

        # Read fields from YAML, loading from files if necessary
        description = config.get("description", "")
        exploit_explanation = config.get("exploit_explanation", "")
        exploit_expected_status = config.get("exploit_expected_status", "passed")
        insecure_verifier_info = config.get("insecure_verifier_info", "")
        labels = config.get("labels", [])

        ground_truth = read_asset(config["ground_truth"], problem_dir)
        exploit = read_asset(config["exploit"], problem_dir)

        return cls(
            id=problem_id,
            description=description,
            ground_truth=ground_truth,
            exploit=exploit,
            insecure_verifier_info=insecure_verifier_info,
            exploit_explanation=exploit_explanation,
            exploit_expected_status=exploit_expected_status,
            keywords=labels,
            exploit_type=config.get("exploit_type", ""),
            info_leak_method=config.get("info_leak_method", ""),
            insecure_test_cases=config.get("insecure_test_cases"),
            evaluated_gt_difficulty=config.get("evaluated_gt_difficulty"),
            evaluated_exploit_difficulty=config.get("evaluated_exploit_difficulty"),
            gt_model_results=config.get("gt_model_results"),
            exploit_model_results=config.get("exploit_model_results"),
            vuln_cheatiness=config.get("vuln_cheatiness"),
            exploit_fairness=config.get("exploit_fairness"),
            problem_quality=config.get("problem_quality"),
            problem_appears_as=config.get("problem_appears_as"),
            exploit_finding_appearance=config.get("exploit_finding_appearance"),
            test_cases=config.get("test_cases", []),
            function_name=config.get("function_name", "")
        )