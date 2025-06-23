"""
Standalone secure verifier for use in sandboxed environments.
Contains all necessary verification logic without external dependencies.
"""

import signal
import time
import faulthandler
import platform
import sys
import traceback
import subprocess
import json
import tempfile
import os
import inspect
from io import StringIO
from typing import List, Tuple


class VerificationStatus:
    PASSED = "passed"
    FAILED = "failed"
    CRASHED = "crashed"
    TIMED_OUT = "timed_out"


class SingleVerificationResult:
    def __init__(self, status, feedback):
        self.status = status
        self.feedback = feedback

    def to_dict(self):
        return {"status": self.status, "feedback": self.feedback}
    
    @classmethod
    def from_dict(cls, data):
        return cls(data["status"], data["feedback"])


def timeout_handler(signum, frame):
    """Handler for timeout signals."""
    raise Exception("TimeoutException")


def reliability_guard(maximum_memory_bytes=None):
    """
    This disables various destructive functions and prevents the generated code
    from interfering with the test (e.g. fork bomb, killing other processes,
    removing filesystem files, etc.)
    WARNING
    This function is NOT a security sandbox. Untrusted code, including, model-
    generated code, should not be blindly executed outside of one. See the
    Codex paper for more information about OpenAI's code sandbox, and proceed
    with caution.
    """
    import sys  # Import sys at the beginning to avoid scoping issues
    
    # Use sys.modules to coordinate between different verification modules
    if hasattr(sys, '_djinn_reliability_guard_applied'):
        return
    
    if maximum_memory_bytes is not None:
        # Only import resource if it hasn't been disabled yet
        if sys.modules.get("resource") is not None:
            import resource
            resource.setrlimit(
                resource.RLIMIT_AS, (maximum_memory_bytes, maximum_memory_bytes)
            )
            resource.setrlimit(
                resource.RLIMIT_DATA, (maximum_memory_bytes, maximum_memory_bytes)
            )
            if not platform.uname().system == "Darwin":
                resource.setrlimit(
                    resource.RLIMIT_STACK, (maximum_memory_bytes, maximum_memory_bytes)
                )

    faulthandler.disable()

    import builtins
    builtins.quit = None

    import os
    os.environ["OMP_NUM_THREADS"] = "1"
    
    # Disable dangerous functions
    dangerous_funcs = [
        'kill', 'system', 'putenv', 'remove', 'removedirs', 'rmdir', 'fchdir',
        'setuid', 'fork', 'forkpty', 'killpg', 'rename', 'renames', 'truncate',
        'replace', 'unlink', 'fchmod', 'fchown', 'chmod', 'chown', 'chroot',
        'lchflags', 'lchmod', 'lchown', 'getcwd', 'chdir'
    ]
    for func in dangerous_funcs:
        if hasattr(os, func):
            setattr(os, func, None)

    import shutil
    shutil.rmtree = None
    shutil.move = None
    shutil.chown = None

    import subprocess
    subprocess.Popen = None

    __builtins__["help"] = None

    sys.modules["ipdb"] = None
    sys.modules["joblib"] = None
    sys.modules["resource"] = None
    sys.modules["psutil"] = None
    sys.modules["tkinter"] = None
    
    # Mark as applied using a sys attribute that all modules can see
    sys._djinn_reliability_guard_applied = True


def create_subprocess_runner_script():
    """Create the script that will run in the subprocess to execute user code only."""
    return '''
import sys
import json
import signal
import time
import inspect
from io import StringIO

def timeout_handler(signum, frame):
    raise Exception("TimeoutException")

def call_function_with_appropriate_args(func, test_input):
    """
    Call a function with test_input, using function signature inspection
    to determine the appropriate way to unpack arguments.
    """
    try:
        # Get function signature
        sig = inspect.signature(func)
        param_count = len(sig.parameters)
        
        # Handle different cases based on parameter count and input type
        if param_count == 0:
            # Function takes no arguments
            return func()
        elif param_count == 1:
            # Function takes exactly one argument - pass test_input as-is
            return func(test_input)
        else:
            # Function takes multiple arguments
            if isinstance(test_input, (tuple, list)):
                if len(test_input) == param_count:
                    # Perfect match - unpack the arguments
                    return func(*test_input)
                elif len(test_input) == 1:
                    # Single item in container, but function wants multiple args
                    # This might be a case where test_input should be passed as-is
                    return func(test_input)
                else:
                    # Mismatch in argument count - try unpacking anyway and let it fail naturally
                    return func(*test_input)
            else:
                # test_input is not a tuple/list but function wants multiple args
                # This is likely an error case, but pass it as single argument
                return func(test_input)
                
    except (ValueError, TypeError):
        # If signature inspection fails, fall back to original logic
        if isinstance(test_input, tuple):
            return func(*test_input)
        else:
            return func(test_input)

def main():
    # Read configuration from stdin
    config = json.loads(input())
    submission_code = config["submission_code"]
    function_name = config["function_name"]
    test_input = config["test_input"]
    timeout = config["timeout"]
    
    # Set up timeout
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)
    
    try:
        # Execute submission in clean namespace
        namespace = {"__builtins__": __builtins__}
        exec(submission_code, namespace)
        
        if function_name not in namespace:
            print(json.dumps({
                "error": f"Function '{function_name}' not found in submission"
            }))
            return
            
        submitted_function = namespace[function_name]
        
        if not callable(submitted_function):
            print(json.dumps({
                "error": f"'{function_name}' exists but is not callable"
            }))
            return
        
        # Capture stdout
        old_stdout = sys.stdout
        sys.stdout = captured_output = StringIO()
        
        start_time = time.time()
        
        # Call function
        actual_output = call_function_with_appropriate_args(submitted_function, test_input)
        
        execution_time = time.time() - start_time
        printed_output = captured_output.getvalue().strip()
        sys.stdout = old_stdout
        
        # Return result
        print(json.dumps({
            "actual_output": actual_output,
            "printed_output": printed_output,
            "execution_time": execution_time,
            "error": None
        }))
        
    except SyntaxError as e:
        print(json.dumps({"error": f"Syntax error: {str(e)}"}))
    except Exception as e:
        import traceback
        error_msg = str(e)
        if "timeoutexception" in error_msg.lower():
            error_msg = "Time Limit Exceeded"
        elif not error_msg or error_msg == "":
            # Handle case where str(e) returns empty string or None
            error_msg = f"Unknown error: {type(e).__name__}"
            
        # Add detailed error information
        error_details = {
            "error": error_msg,
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc()
        }
        print(json.dumps(error_details))
    finally:
        signal.alarm(0)

if __name__ == "__main__":
    main()
'''


def verify_function_submission_subprocess(submission_code: str, function_name: str, test_cases: List[tuple], 
                                        timeout: int = 6, max_memory_gb: int = 4, order_dependent: bool = True) -> SingleVerificationResult:
    """
    Verify a submission using subprocess isolation.
    The subprocess only executes user code - all verification logic runs in the main process.
    """
    # Import subprocess before reliability guard potentially disables it
    import subprocess as sp
    
    try:
        # Create temporary script file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(create_subprocess_runner_script())
            script_path = f.name
        
        try:
            failed_tests = []
            total_execution_time = 0
            
            # Run each test case individually
            for i, (test_input, expected_output) in enumerate(test_cases):
                # Prepare configuration for this test
                config = {
                    "submission_code": submission_code,
                    "function_name": function_name,
                    "test_input": test_input,
                    "timeout": timeout
                }
                
                # Run subprocess with memory limit
                max_memory_bytes = max_memory_gb * 1024 * 1024 * 1024
                env = os.environ.copy()
                env["PYTHONPATH"] = ""  # Clean Python path
                
                # Use ulimit to set memory limits (Unix-specific)
                cmd = f"ulimit -v {max_memory_bytes // 1024}; python {script_path}"
                
                process = sp.Popen(
                    ["bash", "-c", cmd],
                    stdin=sp.PIPE,
                    stdout=sp.PIPE,
                    stderr=sp.PIPE,
                    text=True,
                    env=env
                )
                
                # Send config and get results with timeout
                try:
                    stdout, stderr = process.communicate(
                        input=json.dumps(config),
                        timeout=timeout + 2  # Extra buffer for subprocess overhead
                    )
                except sp.TimeoutExpired:
                    process.kill()
                    failed_tests.append(f"Test {i+1}: input={repr(test_input)}, error: Time Limit Exceeded")
                    continue
                
                if process.returncode != 0:
                    error_msg = f"Subprocess crashed with return code {process.returncode}"
                    if stderr.strip():
                        error_msg += f", stderr: {stderr.strip()}"
                    failed_tests.append(f"Test {i+1}: input={repr(test_input)}, error: {error_msg}")
                    continue
                
                # Parse results
                try:
                    result = json.loads(stdout)
                except json.JSONDecodeError as e:
                    error_msg = f"Invalid JSON response from subprocess: {str(e)}"
                    if stdout.strip():
                        error_msg += f", stdout: {stdout.strip()[:200]}"
                    if stderr.strip():
                        error_msg += f", stderr: {stderr.strip()[:200]}"
                    failed_tests.append(f"Test {i+1}: input={repr(test_input)}, error: {error_msg}")
                    continue
                
                if "error" in result and result["error"] is not None:
                    error_msg = result['error']
                    # Check if we have extended error information
                    if isinstance(result, dict) and "error_type" in result:
                        error_msg = f"{result['error']} (Type: {result['error_type']})"
                        if "traceback" in result:
                            # Include first few lines of traceback for debugging
                            traceback_lines = result['traceback'].split('\n')[:5]
                            error_msg += f"\nTraceback: {' | '.join(traceback_lines)}"
                    failed_tests.append(f"Test {i+1}: input={repr(test_input)}, error: {error_msg}")
                    continue
                
                # Process successful result - verification logic runs here in main process
                actual_output = result["actual_output"]
                printed_output = result["printed_output"]
                execution_time = result["execution_time"]
                total_execution_time += execution_time or 0
                
                # Compare outputs with type checking to prevent __eq__ exploits
                if actual_output is not None:
                    # Convert to canonical form to handle JSON serialization artifacts (tuple->list)
                    def to_canonical_form(obj):
                        """Convert to canonical form for comparison, handling tuple/list equivalence."""
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
                    
                    # Check types match for primitive types (after canonicalization)
                    if (isinstance(canonical_expected, (int, float, str, bool, list, dict)) and
                        type(canonical_actual) != type(canonical_expected)):
                        failed_tests.append(f"Test {i+1}: input={repr(test_input)}, expected type {type(canonical_expected).__name__}, got type {type(canonical_actual).__name__}")
                    else:
                        # Handle order-independent comparison for lists
                        if not order_dependent and isinstance(canonical_expected, list) and isinstance(canonical_actual, list):
                            # Compare as sets for order-independent comparison
                            expected_set = set(canonical_expected) if all(isinstance(x, (str, int, float, bool, tuple)) for x in canonical_expected) else canonical_expected
                            actual_set = set(canonical_actual) if all(isinstance(x, (str, int, float, bool, tuple)) for x in canonical_actual) else canonical_actual
                            
                            if isinstance(expected_set, set) and isinstance(actual_set, set):
                                if expected_set != actual_set:
                                    failed_tests.append(f"Test {i+1}: input={repr(test_input)}, expected={repr(expected_output)} (order independent), got={repr(actual_output)}")
                            else:
                                # Fall back to regular comparison if elements aren't hashable
                                if sorted(canonical_expected) != sorted(canonical_actual):
                                    failed_tests.append(f"Test {i+1}: input={repr(test_input)}, expected={repr(expected_output)} (order independent), got={repr(actual_output)}")
                        elif canonical_actual != canonical_expected:
                            failed_tests.append(f"Test {i+1}: input={repr(test_input)}, expected={repr(expected_output)}, got={repr(actual_output)}")
                elif printed_output:
                    if str(printed_output) != str(expected_output):
                        failed_tests.append(f"Test {i+1}: input={repr(test_input)}, expected printed='{expected_output}', got printed='{printed_output}'")
                else:
                    if expected_output is not None and expected_output != "":
                        failed_tests.append(f"Test {i+1}: input={repr(test_input)}, expected={repr(expected_output)}, got no output")
            
            # Final results
            if failed_tests:
                feedback = f"Failed {len(failed_tests)}/{len(test_cases)} tests:\n" + "\n".join(failed_tests[:5])
                if len(failed_tests) > 5:
                    feedback += f"\n... and {len(failed_tests) - 5} more failures"
                return SingleVerificationResult(status=VerificationStatus.FAILED, feedback=feedback)
            
            return SingleVerificationResult(
                status=VerificationStatus.PASSED,
                feedback=f"All {len(test_cases)} tests passed successfully! Total execution time: {total_execution_time:.4f}s"
            )
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(script_path)
            except OSError:
                pass
                
    except Exception as e:
        return SingleVerificationResult(
            status=VerificationStatus.CRASHED,
            feedback=f"Subprocess verification failed: {str(e)}"
        )


def verify(submission_code: str, function_name: str, test_cases: List[tuple], order_dependent: bool = True) -> SingleVerificationResult:
    """
    Main verify function that can be called from sandbox runner.
    
    Args:
        submission_code: The submitted code as a string
        function_name: Name of the function to test
        test_cases: List of (input, expected_output) tuples
        order_dependent: Whether the order of list/tuple outputs matters for comparison
        
    Returns:
        SingleVerificationResult with status and feedback
    """
    return verify_function_submission_subprocess(
        submission_code=submission_code,
        function_name=function_name,
        test_cases=test_cases,
        timeout=6,
        max_memory_gb=4,
        order_dependent=order_dependent
    )