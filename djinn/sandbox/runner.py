import json
import importlib.util
from dataclasses import asdict
from _sandbox_defs import VerificationStatus, VerificationResultSingle

def load_verifier(verifier_path: str, module_name: str):
    """Load a verifier module from the given path."""
    spec = importlib.util.spec_from_file_location(module_name, verifier_path)
    verifier_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier_module)
    return verifier_module

def run_single_verifier(verifier_module, submission_code: str) -> tuple[VerificationStatus, str]:
    """Run a single verifier and return status and feedback."""
    try:
        result = verifier_module.verify(submission_code)
        return result.status, result.feedback
    except Exception as e:
        return VerificationStatus.CRASHED, str(e)

def main():
    """
    This script is executed inside the E2B sandbox. It loads both verifiers
    and the submission, runs both verifications, and prints the result to stdout.
    """
    result = None
    try:
        # Load both verifier modules
        secure_verifier = load_verifier("/home/user/_verifier.py", "_secure_verifier")

        # Read the submission code
        with open("/home/user/submission.py", "r") as f:
            submission_code = f.read()

        # Run both verifiers
        status, feedback = run_single_verifier(secure_verifier, submission_code)

        result = VerificationResultSingle(
            status=status,
            feedback=feedback
        )

    except Exception as e:
        # If any unexpected error occurs, report it as a crash for both
        result = VerificationResultSingle(
            status=VerificationStatus.CRASHED,
            feedback=str(e)
        )
    finally:
        # Serialize the result to JSON and print to stdout
        if result:
            output = asdict(result)
            # Convert enums to their string values for JSON serialization
            output['status'] = output['status'].value if hasattr(output['status'], 'value') else output['status']
            print(json.dumps(output))

if __name__ == "__main__":
    main()
