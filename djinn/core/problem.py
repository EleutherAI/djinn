from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional

class VerificationStatus(Enum):
    PASSED = "passed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CRASHED = "crashed"
    SECURITY_VIOLATION = "security_violation"

@dataclass
class VerificationResult:
    status: VerificationStatus
    feedback: Optional[str] = None # e.g., "Failed on input: [1,2,3]. Expected: 6, Got: 5"

@dataclass
class Problem:
    id: str
    description: str
    ground_truth: str                   # code as plain text (or path)
    exploit: str                        # code as plain text (or path)
    nulls: List[str]                    # list of code strings (or paths)
    verifier: str                       # code defining `verify(submission) -> VerificationResult`
    exploit_explanation: str
    exploit_expected_status: str = "passed" # e.g. "passed", "timed_out", "crashed"
    labels: List[str] = field(default_factory=list)
    gt_difficulty: int = 1
    exploit_difficulty: int = 1

    def verify(self, submission_code: str) -> "VerificationResult":
        """
        Runs the problem's verifier on a given submission.
        NOTE: This is a simple, non-sandboxed implementation.
        """
        verifier_globals = {}
        try:
            exec(self.verifier, verifier_globals)
            verify_func = verifier_globals["verify"]
            return verify_func(submission_code)
        except Exception as e:
            return VerificationResult(status=VerificationStatus.CRASHED, feedback=str(e))

    def check_consistency(self):
        """
        Checks that the ground truth, exploit, and nulls behave as expected.
        """
        print(f"▶️  Checking consistency for '{self.id}'...")

        # 1. Check ground truth
        gt_result = self.verify(self.ground_truth)
        if gt_result.status == VerificationStatus.PASSED:
            print(f"✅  Ground Truth: PASSED")
        else:
            print(f"❌  Ground Truth: FAILED (status: {gt_result.status.value})")
            return False

        # 2. Check exploit
        exploit_result = self.verify(self.exploit)
        expected_status = VerificationStatus(self.exploit_expected_status)
        if exploit_result.status == expected_status:
            print(f"✅  Exploit: {exploit_result.status.value.upper()} (matches expected)")
        else:
            print(f"❌  Exploit: FAILED (expected: {expected_status.value}, got: {exploit_result.status.value})")
            return False

        # 3. Check nulls
        all_nulls_passed = True
        for i, null_code in enumerate(self.nulls):
            null_result = self.verify(null_code)
            if null_result.status != VerificationStatus.PASSED:
                print(f"✅  Null #{i+1}: {null_result.status.value.upper()}")
            else:
                print(f"❌  Null #{i+1}: FAILED (expected not PASSED, but got PASSED)")
                all_nulls_passed = False
        
        if all_nulls_passed:
            print("--------------------")
            print("PASSED: All checks passed.")
        else:
            print("--------------------")
            print("FAILED: One or more null checks failed.")

        return all_nulls_passed 