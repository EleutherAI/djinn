"""
Standalone secure verifier for use in sandboxed environments.
Contains all necessary verification logic without external dependencies.
"""

import signal
import time
import faulthandler
import platform
import sys
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


def verify_function_submission(submission_code: str, function_name: str, test_cases: List[tuple], 
                             timeout: int = 6, max_memory_gb: int = 4) -> SingleVerificationResult:
    """
    Verify a submission that should implement a specific function.
    
    Args:
        submission_code: The submitted code as a string
        function_name: Name of the function to test
        test_cases: List of (input, expected_output) tuples
        timeout: Timeout in seconds for each test case
        max_memory_gb: Maximum memory limit in GB
        
    Returns:
        SingleVerificationResult with status and feedback
    """
    # Set up timeout handler
    signal.signal(signal.SIGALRM, timeout_handler)
    
    # Apply security guards
    max_memory_bytes = max_memory_gb * 1024 * 1024 * 1024
    reliability_guard(max_memory_bytes)
    
    try:
        # Execute the submission code in a clean namespace
        namespace = {"__builtins__": __builtins__}
        exec(submission_code, namespace)
        
        # Check if the required function exists
        if function_name not in namespace:
            return SingleVerificationResult(
                status=VerificationStatus.FAILED,
                feedback=f"Function '{function_name}' not found in submission. Please implement the required function."
            )
        
        submitted_function = namespace[function_name]
        
        # Verify it's actually callable
        if not callable(submitted_function):
            return SingleVerificationResult(
                status=VerificationStatus.FAILED,
                feedback=f"'{function_name}' exists but is not a callable function."
            )
        
        # Test all cases with timeout protection
        failed_tests = []
        total_execution_time = 0
        
        for i, (test_input, expected_output) in enumerate(test_cases):
            signal.alarm(timeout)
            faulthandler.enable()
            
            try:
                # Capture stdout to handle functions that print
                old_stdout = sys.stdout
                sys.stdout = captured_output = StringIO()
                
                start_time = time.time()
                
                # Call the function
                if isinstance(test_input, tuple):
                    actual_output = submitted_function(*test_input)
                else:
                    actual_output = submitted_function(test_input)
                
                execution_time = time.time() - start_time
                total_execution_time += execution_time
                
                # Get any printed output
                printed_output = captured_output.getvalue().strip()
                sys.stdout = old_stdout
                
                # Reset alarm
                signal.alarm(0)
                
                # Compare outputs (prioritize return values over printed output)
                if actual_output is not None:
                    # Function returned a value, compare return values
                    if actual_output != expected_output:
                        failed_tests.append(f"Test {i+1}: input={repr(test_input)}, expected={repr(expected_output)}, got={repr(actual_output)}")
                elif printed_output:
                    # Function printed output, compare printed output  
                    if str(printed_output) != str(expected_output):
                        failed_tests.append(f"Test {i+1}: input={repr(test_input)}, expected printed='{expected_output}', got printed='{printed_output}'")
                else:
                    # Function returned None and printed nothing
                    if expected_output is not None and expected_output != "":
                        failed_tests.append(f"Test {i+1}: input={repr(test_input)}, expected={repr(expected_output)}, got no output")
                        
            except Exception as e:
                sys.stdout = old_stdout
                signal.alarm(0)
                
                if "timeoutexception" in repr(e).lower():
                    failed_tests.append(f"Test {i+1}: input={repr(test_input)}, error: Time Limit Exceeded")
                else:
                    failed_tests.append(f"Test {i+1}: input={repr(test_input)}, error: {str(e)}")
            finally:
                signal.alarm(0)
                faulthandler.disable()
        
        if failed_tests:
            feedback = f"Failed {len(failed_tests)}/{len(test_cases)} tests:\n" + "\n".join(failed_tests[:5])
            if len(failed_tests) > 5:
                feedback += f"\n... and {len(failed_tests) - 5} more failures"
            return SingleVerificationResult(status=VerificationStatus.FAILED, feedback=feedback)
        
        return SingleVerificationResult(
            status=VerificationStatus.PASSED,
            feedback=f"All {len(test_cases)} tests passed successfully! Total execution time: {total_execution_time:.4f}s"
        )
        
    except SyntaxError as e:
        return SingleVerificationResult(
            status=VerificationStatus.FAILED,
            feedback=f"Syntax error in submission: {str(e)}"
        )
    except Exception as e:
        return SingleVerificationResult(
            status=VerificationStatus.FAILED,  
            feedback=f"Error executing submission: {str(e)}"
        )
    finally:
        # Ensure alarm is always cleared
        signal.alarm(0)


def verify(submission_code: str, function_name: str, test_cases: List[tuple]) -> SingleVerificationResult:
    """
    Main verify function that can be called from sandbox runner.
    
    Args:
        submission_code: The submitted code as a string
        function_name: Name of the function to test
        test_cases: List of (input, expected_output) tuples
        
    Returns:
        SingleVerificationResult with status and feedback
    """
    return verify_function_submission(
        submission_code=submission_code,
        function_name=function_name,
        test_cases=test_cases,
        timeout=6,
        max_memory_gb=4
    ) 