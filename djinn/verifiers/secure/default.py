"""
Default secure verifier.

This verifier implements the standard secure verification logic extracted from 
djinn/sandbox/verification_service.py. It runs test cases in a sandbox and validates
results in the main process.
"""

import os
import json
import time
from pathlib import Path
from typing import List, Tuple, Any
from e2b import Sandbox
from e2b.exceptions import TimeoutException

from djinn.core.sandbox_defs import VerificationStatus, VerificationResultSingle

# Path to the sandbox runner
SANDBOX_RUNNER_PATH = Path(__file__).parent.parent.parent / "sandbox" / "runner.py"


def verify(problem, submission_code: str, test_cases: List[Tuple] = None) -> VerificationResultSingle:
    """
    Verify a submission using secure sandbox execution.
    
    Args:
        problem: The Problem object
        submission_code: The code to verify
        test_cases: Optional test cases to use (defaults to problem.secure_test_cases or problem.test_cases)
    
    Returns:
        VerificationResultSingle with the verification result
    """
    try:
        # Determine test cases to use
        if test_cases is None:
            # Try new schema first, fall back to old schema
            test_cases = getattr(problem, 'secure_test_cases', None)
            if test_cases is None:
                test_cases = problem._normalize_test_cases()
        
        order_dependent = getattr(problem, 'order_dependent', True)
        
        return _verify_with_secure_runner(problem, submission_code, test_cases, order_dependent)
        
    except Exception as e:
        return VerificationResultSingle(
            status=VerificationStatus.CRASHED,
            feedback=f"Secure verification failed: {str(e)}"
        )


def _verify_with_secure_runner(problem, submission_code: str, test_cases, order_dependent):
    """Run secure verification using the minimal sandbox runner."""
    failed_tests = []
    total_execution_time = 0
    
    with Sandbox() as sandbox:
        # Upload the minimal runner
        runner_code = SANDBOX_RUNNER_PATH.read_text()
        sandbox.files.write("/home/user/runner.py", runner_code.encode())
        
        # Run each test case
        for i, (test_input, expected_output) in enumerate(test_cases):
            # Prepare test configuration
            config = {
                "submission_code": submission_code,
                "function_name": problem.function_name,
                "test_input": test_input,
                "timeout": 6
            }
            
            # Write config to sandbox
            sandbox.files.write("/home/user/config.json", json.dumps(config).encode())
            
            # Execute in sandbox
            result = sandbox.commands.run("python /home/user/runner.py", timeout=10)
            
            if result.exit_code != 0:
                failed_tests.append(f"Test {i+1}: input={repr(test_input)}, error: Sandbox execution failed - {result.stderr}")
                continue
            
            # Parse result from sandbox
            try:
                execution_result = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                failed_tests.append(f"Test {i+1}: input={repr(test_input)}, error: Invalid JSON response - {str(e)}")
                continue
            
            # Check for execution errors
            if execution_result.get("error"):
                error_msg = execution_result["error"]
                if "timeout" in error_msg.lower():
                    error_msg = "Time Limit Exceeded"
                failed_tests.append(f"Test {i+1}: input={repr(test_input)}, error: {error_msg}")
                continue
            
            # Process successful execution - verification logic runs here in main process
            actual_output = execution_result.get("output")
            printed_output = execution_result.get("printed_output", "")
            execution_time = execution_result.get("execution_time", 0)
            total_execution_time += execution_time
            
            # Compare outputs (main process verification logic)
            test_failed = _compare_outputs(
                actual_output, expected_output, printed_output, 
                order_dependent, test_input, i+1
            )
            
            if test_failed:
                failed_tests.append(test_failed)
    
    # Return final results
    if failed_tests:
        feedback = f"Failed {len(failed_tests)}/{len(test_cases)} tests:\n" + "\n".join(failed_tests[:5])
        if len(failed_tests) > 5:
            feedback += f"\n... and {len(failed_tests) - 5} more failures"
        return VerificationResultSingle(status=VerificationStatus.FAILED, feedback=feedback)
    
    return VerificationResultSingle(
        status=VerificationStatus.PASSED,
        feedback=f"All {len(test_cases)} tests passed successfully! Total execution time: {total_execution_time:.4f}s"
    )


def _compare_outputs(actual_output, expected_output, printed_output, 
                    order_dependent, test_input, test_num):
    """
    Compare actual vs expected outputs. Returns error message if test fails, None if passes.
    This runs in the main process (trusted environment).
    """
    # Handle case where function returns None but prints output
    if actual_output is None and printed_output:
        if str(printed_output.strip()) != str(expected_output):
            return f"Test {test_num}: input={repr(test_input)}, expected printed='{expected_output}', got printed='{printed_output.strip()}'"
        return None
    
    # Handle case where we expect output but got None
    if actual_output is None:
        if expected_output is not None and expected_output != "":
            return f"Test {test_num}: input={repr(test_input)}, expected={repr(expected_output)}, got no output"
        return None
    
    # Convert to canonical form to handle JSON serialization artifacts
    def to_canonical_form(obj):
        if isinstance(obj, tuple):
            return list(obj)
        elif isinstance(obj, list):
            return obj
        elif isinstance(obj, dict):
            return {k: to_canonical_form(v) for k, v in obj.items()}
        else:
            return obj
    
    canonical_expected = to_canonical_form(expected_output)
    canonical_actual = to_canonical_form(actual_output)
    
    # Type checking for primitive types
    if (isinstance(canonical_expected, (int, float, str, bool, list, dict)) and
        type(canonical_actual) != type(canonical_expected)):
        return f"Test {test_num}: input={repr(test_input)}, expected type {type(canonical_expected).__name__}, got type {type(canonical_actual).__name__}"
    
    # For lists/tuples, compare as sets if order_dependent is False
    if not order_dependent and isinstance(canonical_expected, list):
        try:
            if set(canonical_expected) != set(canonical_actual):
                return f"Test {test_num}: input={repr(test_input)}, expected set={set(canonical_expected)}, got set={set(canonical_actual)}"
        except TypeError:
            # Fall back to regular comparison if elements aren't hashable
            pass
    
    # Regular comparison
    if canonical_actual != canonical_expected:
        return f"Test {test_num}: input={repr(test_input)}, expected={repr(canonical_expected)}, got={repr(canonical_actual)}"
    
    return None 