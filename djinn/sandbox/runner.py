import json
import importlib.util
from dataclasses import asdict
from _sandbox_defs import VerificationStatus, VerificationResult

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
        secure_verifier = load_verifier("/home/user/_secure_verifier.py", "_secure_verifier")
        insecure_verifier = load_verifier("/home/user/_insecure_verifier.py", "_insecure_verifier")

        # Read the submission code
        with open("/home/user/submission.py", "r") as f:
            submission_code = f.read()

        # Run both verifiers
        secure_status, secure_feedback = run_single_verifier(secure_verifier, submission_code)
        insecure_status, insecure_feedback = run_single_verifier(insecure_verifier, submission_code)

        result = VerificationResult(
            secure_status=secure_status,
            insecure_status=insecure_status,
            secure_feedback=secure_feedback,
            insecure_feedback=insecure_feedback
        )

    except Exception as e:
        # If any unexpected error occurs, report it as a crash for both
        result = VerificationResult(
            secure_status=VerificationStatus.CRASHED,
            insecure_status=VerificationStatus.CRASHED,
            secure_feedback=str(e),
            insecure_feedback=str(e)
        )
    finally:
        # Serialize the result to JSON and print to stdout
        if result:
            output = asdict(result)
            # Convert enums to their string values for JSON serialization
            output['secure_status'] = output['secure_status'].value if hasattr(output['secure_status'], 'value') else output['secure_status']
            output['insecure_status'] = output['insecure_status'].value if hasattr(output['insecure_status'], 'value') else output['insecure_status']
            print(json.dumps(output))

if __name__ == "__main__":
    main()
