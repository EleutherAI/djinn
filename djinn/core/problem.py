import os
import json
from enum import Enum
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional
from dotenv import load_dotenv
from djinn.core.sandbox_defs import VerificationStatus, VerificationResult
from e2b import Sandbox
from e2b.exceptions import TimeoutException

# Load environment variables from a .env file if it exists
load_dotenv()

SANDBOX_RUNNER_PATH = Path(__file__).parent.parent / "sandbox" / "runner.py"
SANDBOX_DEFS_PATH = Path(__file__).parent / "sandbox_defs.py"

@dataclass
class Problem:
    id: str
    description: str
    ground_truth: str                   # code as plain text (or path)
    exploit: str                        # code as plain text (or path)
    nulls: List[str]                    # list of code strings (or paths)
    secure_verifier: str                # code defining `verify(submission) -> VerificationResult`
    insecure_verifier: str              # code defining `verify(submission) -> VerificationResult`
    insecure_verifier_info: str         # information about the insecure verifier's weakness
    exploit_explanation: str
    exploit_expected_status: str = "passed" # e.g. "passed", "timed_out", "crashed"
    keywords: List[str] = field(default_factory=list)
    gt_difficulty: int = 1
    exploit_difficulty: int = 1

    def _verify_local(self, submission_code: str) -> "VerificationResult":
        """
        Runs both secure and insecure verifiers on a given submission using local exec.
        WARNING: This is not sandboxed and is insecure.
        """
        def run_single_verifier(verifier_code: str) -> tuple[VerificationStatus, Optional[str]]:
            verifier_globals = {}
            try:
                exec(verifier_code, verifier_globals)
                verify_func = verifier_globals["verify"]
                result = verify_func(submission_code)
                return result.status, result.feedback
            except Exception as e:
                return VerificationStatus.CRASHED, str(e)
        
        secure_status, secure_feedback = run_single_verifier(self.secure_verifier)
        insecure_status, insecure_feedback = run_single_verifier(self.insecure_verifier)
        
        return VerificationResult(
            secure_status=secure_status,
            insecure_status=insecure_status,
            secure_feedback=secure_feedback,
            insecure_feedback=insecure_feedback
        )

    def _verify_sandboxed(self, submission_code: str) -> "VerificationResult":
        """
        Runs both secure and insecure verifiers on a given submission inside an E2B sandbox.
        """
        try:
            with Sandbox() as sandbox:
                # Upload verifiers, submission, runner, and shared definitions
                sandbox.files.write("/home/user/_secure_verifier.py", self.secure_verifier.encode())
                sandbox.files.write("/home/user/_insecure_verifier.py", self.insecure_verifier.encode())
                sandbox.files.write("/home/user/submission.py", submission_code.encode())
                
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

    def verify(self, submission_code: str) -> "VerificationResult":
        """
        Runs the problem's verifier on a given submission.
        Uses E2B sandbox if E2B_API_KEY is set, otherwise falls back to local exec.
        """
        if os.getenv("E2B_API_KEY"):
            return self._verify_sandboxed(submission_code)
        else:
            print("WARNING: E2B_API_KEY not set. Running verification locally without sandboxing. This is insecure.")
            return self._verify_local(submission_code)

    def check_consistency(self):
        """
        Checks that the ground truth, exploit, and nulls behave as expected.
        """
        print(f"▶️  Checking consistency for '{self.id}'...")

        # 1. Check ground truth
        gt_result = self.verify(self.ground_truth)
        if gt_result.secure_status == VerificationStatus.PASSED and gt_result.insecure_status == VerificationStatus.PASSED:
            print(f"✅  Ground Truth: PASSED on both verifiers")
        else:
            print(f"❌  Ground Truth: FAILED")
            print(f"    Secure: {gt_result.secure_status.value} ({gt_result.secure_feedback})")
            print(f"    Insecure: {gt_result.insecure_status.value} ({gt_result.insecure_feedback})")
            return False

        # 2. Check exploit
        exploit_result = self.verify(self.exploit)
        expected_insecure_status = VerificationStatus(self.exploit_expected_status)
        if exploit_result.secure_status != VerificationStatus.PASSED and exploit_result.insecure_status == expected_insecure_status:
            print(f"✅  Exploit: FAILED on secure, {exploit_result.insecure_status.value.upper()} on insecure (matches expected)")
        else:
            print(f"❌  Exploit: FAILED")
            print(f"    Secure: {exploit_result.secure_status.value} (expected: not PASSED)")
            print(f"    Insecure: {exploit_result.insecure_status.value} (expected: {expected_insecure_status.value})")
            if exploit_result.secure_feedback:
                print(f"    Secure feedback: {exploit_result.secure_feedback}")
            if exploit_result.insecure_feedback:
                print(f"    Insecure feedback: {exploit_result.insecure_feedback}")
            return False

        # 3. Check nulls
        all_nulls_passed = True
        for i, null_code in enumerate(self.nulls):
            null_result = self.verify(null_code)
            if null_result.secure_status != VerificationStatus.PASSED and null_result.insecure_status != VerificationStatus.PASSED:
                print(f"✅  Null #{i+1}: FAILED on both verifiers")
            else:
                print(f"❌  Null #{i+1}: FAILED - should fail both verifiers")
                print(f"    Secure: {null_result.secure_status.value}")
                print(f"    Insecure: {null_result.insecure_status.value}")
                all_nulls_passed = False
        
        if all_nulls_passed:
            print("--------------------")
            print("PASSED: All checks passed.")
        else:
            print("--------------------")
            print("FAILED: One or more null checks failed.")

        return all_nulls_passed 