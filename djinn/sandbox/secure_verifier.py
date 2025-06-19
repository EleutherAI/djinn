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
    """Create the script that will run in the subprocess to execute user code."""
    return '''
import sys
import json
import signal
import time
import traceback
from io import StringIO
import builtins

# Grab pristine functions before executing untrusted code
real_print = builtins.print
real_dumps = json.dumps
real_signal = signal.signal

def timeout_handler(signum, frame):
    raise Exception("TimeoutException")

def main():
    # Read configuration from stdin
    config = json.loads(input())
    submission_code = config["submission_code"]
    function_name = config["function_name"]
    test_cases = config["test_cases"]
    timeout = config["timeout"]
    
    # Set up timeout
    real_signal(signal.SIGALRM, timeout_handler)
    
    results = []
    
    try:
        # Execute submission in clean namespace
        namespace = {"__builtins__": __builtins__}
        exec(submission_code, namespace)
        
        if function_name not in namespace:
            real_print(real_dumps({
                "error": f"Function '{function_name}' not found in submission"
            }))
            return
            
        submitted_function = namespace[function_name]
        
        if not callable(submitted_function):
            real_print(real_dumps({
                "error": f"'{function_name}' exists but is not callable"
            }))
            return
        
        # Run each test case
        for i, (test_input, expected_output) in enumerate(test_cases):
            real_signal(signal.SIGALRM, timeout_handler)
            signal.alarm(timeout)
            
            try:
                # Capture stdout
                old_stdout = sys.stdout
                sys.stdout = captured_output = StringIO()
                
                start_time = time.time()
                
                # Call function
                if isinstance(test_input, tuple):
                    actual_output = submitted_function(*test_input)
                else:
                    actual_output = submitted_function(test_input)
                
                execution_time = time.time() - start_time
                printed_output = captured_output.getvalue().strip()
                sys.stdout = old_stdout
                signal.alarm(0)
                
                # Store result
                results.append({
                    "test_index": i,
                    "actual_output": actual_output,
                    "printed_output": printed_output,
                    "execution_time": execution_time,
                    "error": None
                })
                
            except Exception as e:
                sys.stdout = old_stdout
                signal.alarm(0)
                
                error_msg = str(e)
                if "timeoutexception" in error_msg.lower():
                    error_msg = "Time Limit Exceeded"
                
                results.append({
                    "test_index": i,
                    "actual_output": None,
                    "printed_output": None,
                    "execution_time": None,
                    "error": error_msg
                })
        
        real_print(real_dumps({"results": results}))
        
    except SyntaxError as e:
        real_print(real_dumps({"error": f"Syntax error: {str(e)}"}))
    except Exception as e:
        real_print(real_dumps({"error": f"Execution error: {str(e)}"}))
    finally:
        signal.alarm(0)

if __name__ == "__main__":
    main()
'''


def verify_function_submission_subprocess(submission_code: str, function_name: str, test_cases: List[tuple], 
                                        timeout: int = 6, max_memory_gb: int = 4) -> SingleVerificationResult:
    """
    Verify a submission using subprocess isolation.
    This prevents the user code from monkey-patching the verifier.
    """
    # Import subprocess before reliability guard potentially disables it
    import subprocess as sp
    
    try:
        # Create temporary script file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(create_subprocess_runner_script())
            script_path = f.name
        
        try:
            # Prepare configuration
            config = {
                "submission_code": submission_code,
                "function_name": function_name,
                "test_cases": test_cases,
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
            
            # Send config and get results with overall timeout
            try:
                stdout, stderr = process.communicate(
                    input=json.dumps(config),
                    timeout=timeout * len(test_cases) + 5  # Extra buffer for subprocess overhead
                )
            except sp.TimeoutExpired:
                process.kill()
                return SingleVerificationResult(
                    status=VerificationStatus.TIMED_OUT,
                    feedback="Overall execution timed out"
                )
            
            if process.returncode != 0:
                return SingleVerificationResult(
                    status=VerificationStatus.CRASHED,
                    feedback=f"Subprocess crashed with return code {process.returncode}. STDERR: {stderr}"
                )
            
            # Parse results
            try:
                response = json.loads(stdout)
            except json.JSONDecodeError:
                return SingleVerificationResult(
                    status=VerificationStatus.CRASHED,
                    feedback=f"Invalid JSON response from subprocess. STDOUT: {stdout}, STDERR: {stderr}"
                )
            
            if "error" in response:
                return SingleVerificationResult(
                    status=VerificationStatus.FAILED,
                    feedback=response["error"]
                )
            
            # Process test results
            results = response["results"]
            if len(results) != len(test_cases):
                return SingleVerificationResult(
                    status=VerificationStatus.FAILED,
                    feedback=f"Number of test results ({len(results)}) does not match number of test cases ({len(test_cases)})"
                )
            
            failed_tests = []
            total_execution_time = 0
            
            for result in results:
                i = result["test_index"]
                test_input, expected_output = test_cases[i]
                
                if result["error"]:
                    failed_tests.append(f"Test {i+1}: input={repr(test_input)}, error: {result['error']}")
                    continue
                
                actual_output = result["actual_output"]
                printed_output = result["printed_output"]
                total_execution_time += result["execution_time"] or 0
                
                # Compare outputs with type checking to prevent __eq__ exploits
                if actual_output is not None:
                    # Check types match for primitive types
                    if (isinstance(expected_output, (int, float, str, bool, list, tuple, dict)) and
                        type(actual_output) != type(expected_output)):
                        failed_tests.append(f"Test {i+1}: input={repr(test_input)}, expected type {type(expected_output).__name__}, got type {type(actual_output).__name__}")
                    elif actual_output != expected_output:
                        failed_tests.append(f"Test {i+1}: input={repr(test_input)}, expected={repr(expected_output)}, got={repr(actual_output)}")
                elif printed_output:
                    if str(printed_output) != str(expected_output):
                        failed_tests.append(f"Test {i+1}: input={repr(test_input)}, expected printed='{expected_output}', got printed='{printed_output}'")
                else:
                    if expected_output is not None and expected_output != "":
                        failed_tests.append(f"Test {i+1}: input={repr(test_input)}, expected={repr(expected_output)}, got no output")
            
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
        stack_trace = traceback.format_exc()
        return SingleVerificationResult(
            status=VerificationStatus.FAILED,
            feedback=f"Syntax error in submission: {str(e)}\nStack trace:\n{stack_trace}"
        )
    except Exception as e:
        stack_trace = traceback.format_exc()
        return SingleVerificationResult(
            status=VerificationStatus.FAILED,  
            feedback=f"Error executing submission: {str(e)}\nStack trace:\n{stack_trace}"
        )
    finally:
        # Ensure alarm is always cleared
        signal.alarm(0)


def verify(submission_code: str, function_name: str, test_cases: List[tuple], use_subprocess: bool = True) -> SingleVerificationResult:
    """
    Main verify function that can be called from sandbox runner.
    
    Args:
        submission_code: The submitted code as a string
        function_name: Name of the function to test
        test_cases: List of (input, expected_output) tuples
        use_subprocess: Whether to use subprocess isolation (recommended for security)
        
    Returns:
        SingleVerificationResult with status and feedback
    """
    if use_subprocess:
        return verify_function_submission_subprocess(
            submission_code=submission_code,
            function_name=function_name,
            test_cases=test_cases,
            timeout=6,
            max_memory_gb=4
        )
    else:
        return verify_function_submission(
            submission_code=submission_code,
            function_name=function_name,
            test_cases=test_cases,
            timeout=6,
            max_memory_gb=4
        ) 