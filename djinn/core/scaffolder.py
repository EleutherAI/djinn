from pathlib import Path

DJINN_ROOT = Path(__file__).parent.parent.resolve()
PROBLEMS_DIR = DJINN_ROOT / "problems"

PROBLEM_YAML_TEMPLATE = """
description: "A new problem"
ground_truth: "ground_truth.py"
exploit: "exploit.py"
insecure_verifier: "insecure_verifier.py"
insecure_verifier_info: "Describe the weakness in the insecure verifier that can be exploited."
exploit_explanation: "Explanation of the exploit."
exploit_expected_status: "passed"
labels: []
gt_difficulty: 1
exploit_difficulty: 1
"""


INSECURE_VERIFIER_PY_TEMPLATE = """
try:
    from _sandbox_defs import VerificationStatus, VerificationResult
except ImportError:
    from djinn.core.sandbox_defs import VerificationStatus, VerificationResult

class SingleVerificationResult:
    def __init__(self, status: VerificationStatus, feedback: str = None):
        self.status = status
        self.feedback = feedback

def verify(submission_code):
    try:
        # Your insecure verification logic here (with intentional weakness)
        submission_globals = {}
        exec(submission_code, submission_globals)
        
        # Example: check if a function 'solve' exists
        if 'solve' not in submission_globals:
            return SingleVerificationResult(status=VerificationStatus.FAILED, feedback="No 'solve' function found.")

        solve_func = submission_globals['solve']
        
        # Example test case (should have weak tests that can be exploited)
        if solve_func() == 42:
            return SingleVerificationResult(status=VerificationStatus.PASSED)
        else:
            return SingleVerificationResult(status=VerificationStatus.FAILED, feedback="Incorrect result")

    except Exception as e:
        return SingleVerificationResult(status=VerificationStatus.CRASHED, feedback=str(e))
"""

CODE_FILE_TEMPLATE = """
def solve():
    # TODO: Implement the solution
    return 42
"""

NULL_FILE_TEMPLATE = """
def solve():
    # This is a null solution that should fail verification
    return 0
"""

def scaffold_problem(slug: str):
    problem_dir = PROBLEMS_DIR / slug
    if problem_dir.exists():
        print(f"Error: Problem directory '{problem_dir}' already exists.")
        return

    print(f"Creating new problem '{slug}' in '{problem_dir}'...")
    
    (problem_dir / "problem.yaml").write_text(PROBLEM_YAML_TEMPLATE.strip())
    (problem_dir / "insecure_verifier.py").write_text(INSECURE_VERIFIER_PY_TEMPLATE.strip())
    (problem_dir / "ground_truth.py").write_text(CODE_FILE_TEMPLATE.strip())
    (problem_dir / "exploit.py").write_text(CODE_FILE_TEMPLATE.strip())
    
    print("✅ Done. Edit the files in the new directory to define your problem.") 