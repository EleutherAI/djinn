"""
Offline verification service that runs locally using subprocess isolation.
Uses the same architecture as the online service but with subprocess instead of E2B.
"""

import os
import json
import time
import tempfile
import subprocess
import psutil
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional

from djinn.core.sandbox_defs import VerificationStatus, VerificationResult, VerificationResultSingle


class OfflineVerificationService:
    """
    Service for running verification operations locally using subprocess isolation.
    Provides the same interface as the online E2B service.
    """
    
    def __init__(self, memory_limit_mb: int = 500):
        self.memory_limit_mb = memory_limit_mb
        self.memory_limit_bytes = memory_limit_mb * 1024 * 1024
    
    def verify_single(self, problem, submission_code: str, secure: bool) -> VerificationResultSingle:
        """
        Verify a single submission against a problem using subprocess isolation.
        All verification logic runs in main process, only code execution in subprocess.
        """
        try:
            if secure:
                # Use secure verification (subprocess isolation)
                return self._verify_with_secure_subprocess(problem, submission_code)
            else:
                # Use insecure verification (run the problem's insecure verifier)
                return self._verify_with_insecure_verifier(problem, submission_code)
                
        except Exception as e:
            return VerificationResultSingle(
                status=VerificationStatus.CRASHED,
                feedback=f"Offline verification failed: {str(e)}"
            )
    
    def _verify_with_secure_subprocess(self, problem, submission_code: str):
        """Run secure verification using subprocess isolation."""
        normalized_test_cases = problem._normalize_test_cases()
        order_dependent = getattr(problem, 'order_dependent', True)
        
        failed_tests = []
        total_execution_time = 0
        
        # Create subprocess runner script
        runner_script = self._create_runner_script()
        
        # Run each test case
        for i, (test_input, expected_output) in enumerate(normalized_test_cases):
            # Prepare test configuration
            config = {
                "submission_code": submission_code,
                "function_name": problem.function_name,
                "test_input": test_input,
                "timeout": 10
            }
            
            # Execute in subprocess
            execution_result = self._run_in_subprocess(runner_script, config)
            
            # Handle subprocess execution errors
            if execution_result.get("subprocess_error"):
                failed_tests.append(f"Test {i+1}: input={repr(test_input)}, error: {execution_result['subprocess_error']}")
                continue
            
            # Check for user code execution errors
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
            test_failed = self._compare_outputs(
                actual_output, expected_output, printed_output, 
                order_dependent, test_input, i+1
            )
            
            if test_failed:
                failed_tests.append(test_failed)
        
        # Return final results
        if failed_tests:
            feedback = f"Failed {len(failed_tests)}/{len(normalized_test_cases)} tests:\n" + "\n".join(failed_tests[:5])
            if len(failed_tests) > 5:
                feedback += f"\n... and {len(failed_tests) - 5} more failures"
            return VerificationResultSingle(status=VerificationStatus.FAILED, feedback=feedback)
        
        return VerificationResultSingle(
            status=VerificationStatus.PASSED,
            feedback=f"All {len(normalized_test_cases)} tests passed successfully! Total execution time: {total_execution_time:.4f}s"
        )
    
    def _verify_with_insecure_verifier(self, problem, submission_code: str):
        """Run insecure verification using the problem's insecure verifier with memory limits."""
        try:
            # Create a temporary script that runs the insecure verifier with resource limits
            insecure_script = f'''
import json
import signal
import sys
import resource
import os
import gc

# Add the sandbox definitions
class VerificationStatus:
    PASSED = "passed"
    FAILED = "failed"
    CRASHED = "crashed"
    TIMED_OUT = "timed_out"

class SingleVerificationResult:
    def __init__(self, status, feedback=None):
        self.status = status
        self.feedback = feedback

def timeout_handler(signum, frame):
    raise Exception("Timeout")

def main():
    # Set memory limit: {self.memory_limit_bytes} bytes ({self.memory_limit_mb}MB)
    try:
        resource.setrlimit(resource.RLIMIT_AS, ({self.memory_limit_bytes}, {self.memory_limit_bytes}))
        resource.setrlimit(resource.RLIMIT_DATA, ({self.memory_limit_bytes}, {self.memory_limit_bytes}))
    except (ValueError, OSError) as e:
        print(json.dumps({{"status": "crashed", "feedback": f"Failed to set memory limits: {{str(e)}}"}}))
        return
    
    # Set timeout
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(10)  # 10 second timeout
    
    try:
        # Read configuration
        config = json.loads(input())
        submission_code = config["submission_code"]
        insecure_verifier_code = config["insecure_verifier_code"]
        
        # Create namespace for verifier
        verifier_namespace = {{
            '__builtins__': __builtins__,
            'VerificationStatus': VerificationStatus,
            'SingleVerificationResult': SingleVerificationResult,
        }}
        
        # Execute the insecure verifier code
        exec(insecure_verifier_code, verifier_namespace)
        
        if 'verify' not in verifier_namespace:
            print(json.dumps({{"status": "crashed", "feedback": "Insecure verifier does not define verify function"}}))
            return
        
        # Run the verification
        result = verifier_namespace['verify'](submission_code)
        
        # Handle different result types
        if hasattr(result, 'status'):
            status = result.status
            feedback = getattr(result, 'feedback', None)
        else:
            # Handle cases where result might be a simple string or other type
            status = str(result) if result else "crashed"
            feedback = f"Unexpected result type: {{type(result)}}"
        
        print(json.dumps({{"status": status, "feedback": feedback}}))
        
    except MemoryError:
        print(json.dumps({{"status": "crashed", "feedback": f"Memory limit exceeded ({self.memory_limit_mb}MB)"}}))
    except Exception as e:
        error_msg = str(e)
        if "timeout" in error_msg.lower():
            print(json.dumps({{"status": "timed_out", "feedback": "Insecure verifier timed out"}}))
        elif "memory" in error_msg.lower() or "cannot allocate" in error_msg.lower():
            print(json.dumps({{"status": "crashed", "feedback": f"Memory limit exceeded ({self.memory_limit_mb}MB)"}}))
        else:
            print(json.dumps({{"status": "crashed", "feedback": f"Insecure verifier crashed: {{error_msg}}"}}))
    finally:
        signal.alarm(0)
        # Force garbage collection to free memory
        gc.collect()

if __name__ == "__main__":
    main()
'''
            
            # Prepare configuration
            config = {
                "submission_code": submission_code,
                "insecure_verifier_code": problem.insecure_verifier
            }
            
            # Run in subprocess (insecure verifier returns JSON directly)
            execution_result = self._run_insecure_verifier_subprocess(insecure_script, config)
            
            # Handle subprocess execution errors
            if execution_result.get("subprocess_error"):
                return VerificationResultSingle(
                    status=VerificationStatus.CRASHED,
                    feedback=f"Insecure verifier subprocess failed: {execution_result['subprocess_error']}"
                )
            
            # Parse result (insecure verifier should return status directly)
            if "status" in execution_result:
                return VerificationResultSingle(
                    status=VerificationStatus(execution_result["status"]),
                    feedback=execution_result.get("feedback")
                )
            else:
                return VerificationResultSingle(
                    status=VerificationStatus.CRASHED,
                    feedback=f"Unexpected result from insecure verifier: {execution_result}"
                )
                
        except Exception as e:
            return VerificationResultSingle(
                status=VerificationStatus.CRASHED,
                feedback=f"Insecure verification failed: {str(e)}"
            )
    
    def _create_runner_script(self):
        """Create the subprocess runner script (similar to sandbox runner)."""
        return '''
import json
import signal
import time
import inspect
import sys
from io import StringIO

# Basic imports for user code
from itertools import accumulate, chain, combinations, count, permutations, product, groupby, islice, repeat
from copy import deepcopy
from string import ascii_lowercase, ascii_uppercase
from math import floor, log2, log10, sqrt, comb, gcd, ceil, inf, isqrt, factorial, atan2, pi, log, prod
from collections import defaultdict, deque, Counter, OrderedDict
from bisect import bisect, bisect_left, bisect_right, insort
from heapq import heappush, heappop, heapify, merge, nlargest, nsmallest, heapreplace
from functools import reduce, cache, lru_cache, cmp_to_key, partial
from random import randrange, shuffle
from operator import itemgetter, sub, xor, or_, iand
from re import search as re_search
from os.path import commonprefix
from typing import List, Tuple, Dict, Set, Optional, Union, Any, Callable, Iterable, Iterator, Generator, Deque
import copy
import string
import math
import collections
import bisect
import heapq
import functools
import random
import itertools
import operator
import re
import datetime
import io
import os


# Leetcode helper classes
class ListNode:
    def __init__(self, val=0, next=None):
        self.val = val
        self.next = next

class TreeNode:
    def __init__(self, val=0, left=None, right=None):
        self.val = val
        self.left = left
        self.right = right

def list_node(values: List[Any]) -> Optional[ListNode]:
    dummy = ListNode(0)
    current = dummy
    for value in values:
        current.next = ListNode(value)
        current = current.next
    return dummy.next

def tree_node(values: List[Any]) -> Optional[TreeNode]:
    if not values:
        return None
    root = TreeNode(values[0])
    queue = deque([root])
    i = 1
    while queue and i < len(values):
        node = queue.popleft()
        if values[i] is not None:
            node.left = TreeNode(values[i])
            queue.append(node.left)
        i += 1
        if i < len(values) and values[i] is not None:
            node.right = TreeNode(values[i])
            queue.append(node.right)
        i += 1
    return root


def timeout_handler(signum, frame):
    raise Exception("TimeoutException")


def call_function_with_appropriate_args(func, test_input):
    try:
        sig = inspect.signature(func)
        param_count = len(sig.parameters)
        
        if param_count == 0:
            return func()
        elif param_count == 1:
            return func(test_input)
        else:
            if isinstance(test_input, (tuple, list)):
                if len(test_input) == param_count:
                    return func(*test_input)
                elif len(test_input) == 1:
                    return func(test_input)
                else:
                    return func(*test_input)
            else:
                return func(test_input)
                
    except (ValueError, TypeError):
        if isinstance(test_input, tuple):
            return func(*test_input)
        else:
            return func(test_input)


def execute_user_code(submission_code: str, function_name: str, test_input, timeout: int):
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)
    
    try:
        namespace = {
            "__builtins__": __builtins__,
            **{k: v for k, v in globals().items() if not k.startswith('_')}
        }
        exec(submission_code, namespace)
        
        if function_name not in namespace:
            return {"error": f"Function '{function_name}' not found in submission"}
            
        submitted_function = namespace[function_name]
        
        if not callable(submitted_function):
            return {"error": f"'{function_name}' exists but is not callable"}
        
        old_stdout = sys.stdout
        sys.stdout = captured_output = StringIO()
        
        start_time = time.time()
        actual_output = call_function_with_appropriate_args(submitted_function, test_input)
        execution_time = time.time() - start_time
        printed_output = captured_output.getvalue()
        sys.stdout = old_stdout
        
        return {
            "output": actual_output,
            "printed_output": printed_output,
            "execution_time": execution_time,
            "error": None
        }
        
    except SyntaxError as e:
        return {"error": f"Syntax error: {str(e)}"}
    except Exception as e:
        error_msg = str(e)
        if "timeoutexception" in error_msg.lower():
            error_msg = "Time Limit Exceeded"
        elif not error_msg:
            error_msg = f"Unknown error: {type(e).__name__}"
        return {"error": error_msg}
    finally:
        signal.alarm(0)


def main():
    try:
        config = json.loads(input())
        
        submission_code = config["submission_code"]
        function_name = config["function_name"]
        test_input = config["test_input"]
        timeout = config.get("timeout", 6)
        
        result = execute_user_code(submission_code, function_name, test_input, timeout)
        print(json.dumps(result))
        
    except Exception as e:
        print(json.dumps({"error": f"Runner failed: {str(e)}"}))


if __name__ == "__main__":
    main()
'''

    def _run_in_subprocess(self, runner_script: str, config: dict) -> dict:
        """Run the code in a subprocess with memory monitoring."""
        try:
            # Create temporary script file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(runner_script)
                script_path = f.name
            
            try:
                # Run subprocess with timeout and memory monitoring
                process = subprocess.Popen(
                    ["python", script_path],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=os.environ.copy()
                )
                
                # Start memory monitoring in a separate thread
                memory_exceeded_event = threading.Event()
                monitor_thread = threading.Thread(
                    target=self._monitor_memory_usage,
                    args=(process, memory_exceeded_event),
                    daemon=True
                )
                monitor_thread.start()
                
                try:
                    stdout, stderr = process.communicate(
                        input=json.dumps(config),
                        timeout=10  # Extra buffer for subprocess overhead
                    )
                finally:
                    # Ensure monitoring thread stops
                    memory_exceeded_event.set()
                
                # Check if memory limit was exceeded
                if memory_exceeded_event.is_set():
                    return {"error": f"Memory limit exceeded ({self.memory_limit_mb}MB)"}
                
                if process.returncode != 0:
                    # Check for memory-related error messages
                    if ("memory" in stderr.lower() or "cannot allocate" in stderr.lower() or 
                        process.returncode == -9):  # SIGKILL often indicates OOM
                        return {"error": f"Memory limit exceeded ({self.memory_limit_mb}MB)"}
                    return {"subprocess_error": f"Subprocess failed with return code {process.returncode}. stderr: {stderr}"}
                
                # Parse result
                try:
                    return json.loads(stdout)
                except json.JSONDecodeError as e:
                    return {"subprocess_error": f"Invalid JSON response: {str(e)}"}
                    
            finally:
                # Clean up
                try:
                    os.unlink(script_path)
                except OSError:
                    pass
                    
        except subprocess.TimeoutExpired:
            if process:
                process.kill()
            return {"subprocess_error": "Subprocess timed out"}
        except Exception as e:
            return {"subprocess_error": f"Failed to run subprocess: {str(e)}"}
    
    def _monitor_memory_usage(self, process, memory_exceeded_event):
        """Monitor process memory usage and terminate if it exceeds the limit."""
        try:
            psutil_process = psutil.Process(process.pid)
            while process.poll() is None:  # While process is still running
                try:
                    memory_info = psutil_process.memory_info()
                    memory_usage = memory_info.rss  # Resident Set Size (physical memory)
                    
                    if memory_usage > self.memory_limit_bytes:
                        print(f"Memory limit exceeded: {memory_usage / (1024*1024):.1f}MB > {self.memory_limit_mb}MB")
                        memory_exceeded_event.set()
                        process.terminate()
                        # Give it a moment to terminate gracefully
                        time.sleep(0.1)
                        if process.poll() is None:
                            process.kill()
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Process ended or we lost access
                    break
                time.sleep(0.1)  # Check every 100ms
        except Exception as e:
            print(f"Memory monitoring error: {e}")

    def _run_insecure_verifier_subprocess(self, runner_script: str, config: dict) -> dict:
        """Run the insecure verifier in a subprocess with memory monitoring."""
        try:
            # Create temporary script file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(runner_script)
                script_path = f.name
            
            try:
                # Run subprocess with timeout and memory monitoring
                process = subprocess.Popen(
                    ["python", script_path],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=os.environ.copy()
                )
                
                # Start memory monitoring in a separate thread
                memory_exceeded_event = threading.Event()
                monitor_thread = threading.Thread(
                    target=self._monitor_memory_usage,
                    args=(process, memory_exceeded_event),
                    daemon=True
                )
                monitor_thread.start()
                
                try:
                    stdout, stderr = process.communicate(
                        input=json.dumps(config),
                        timeout=15  # Extra buffer for subprocess overhead
                    )
                finally:
                    # Ensure monitoring thread stops
                    memory_exceeded_event.set()
                
                # Check if memory limit was exceeded
                if memory_exceeded_event.is_set():
                    return {"status": "crashed", "feedback": f"Memory limit exceeded ({self.memory_limit_mb}MB)"}
                
                if process.returncode != 0:
                    # Check for memory-related error messages
                    if ("memory" in stderr.lower() or "cannot allocate" in stderr.lower() or 
                        process.returncode == -9):  # SIGKILL often indicates OOM
                        return {"status": "crashed", "feedback": f"Memory limit exceeded ({self.memory_limit_mb}MB)"}
                    return {"subprocess_error": f"Subprocess failed with return code {process.returncode}. stderr: {stderr}"}
                
                # Parse result (insecure verifier returns JSON directly)
                try:
                    return json.loads(stdout)
                except json.JSONDecodeError as e:
                    return {"subprocess_error": f"Invalid JSON response: {str(e)}"}
                    
            finally:
                # Clean up
                try:
                    os.unlink(script_path)
                except OSError:
                    pass
                    
        except subprocess.TimeoutExpired:
            if process:
                process.kill()
            return {"subprocess_error": "Subprocess timed out"}
        except Exception as e:
            return {"subprocess_error": f"Failed to run subprocess: {str(e)}"}
    
    def _compare_outputs(self, actual_output, expected_output, printed_output, 
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
        
        # Order-independent comparison for lists
        if not order_dependent and isinstance(canonical_expected, list) and isinstance(canonical_actual, list):
            expected_set = set(canonical_expected) if all(isinstance(x, (str, int, float, bool, tuple)) for x in canonical_expected) else canonical_expected
            actual_set = set(canonical_actual) if all(isinstance(x, (str, int, float, bool, tuple)) for x in canonical_actual) else canonical_actual
            
            if isinstance(expected_set, set) and isinstance(actual_set, set):
                if expected_set != actual_set:
                    return f"Test {test_num}: input={repr(test_input)}, expected={repr(expected_output)} (order independent), got={repr(actual_output)}"
            else:
                # Fall back to sorted comparison for non-hashable elements
                if sorted(canonical_expected) != sorted(canonical_actual):
                    return f"Test {test_num}: input={repr(test_input)}, expected={repr(expected_output)} (order independent), got={repr(actual_output)}"
        elif canonical_actual != canonical_expected:
            return f"Test {test_num}: input={repr(test_input)}, expected={repr(expected_output)}, got={repr(actual_output)}"
        
        return None

    def verify_problem_consistency(self, problem) -> Dict[str, Any]:
        """
        Comprehensive verification of problem consistency using offline verification.
        """
        results = {
            "ground_truth_secure": None,
            "ground_truth_insecure": None,
            "exploit_secure": None,
            "exploit_insecure": None,
            "nulls_results": [],
            "is_consistent": True,
            "errors": []
        }
        
        try:
            # Test ground truth - should pass both verifiers
            gt_secure_result = self.verify_single(problem, problem.ground_truth, secure=True)
            gt_insecure_result = self.verify_single(problem, problem.ground_truth, secure=False)
            results["ground_truth_secure"] = {
                "status": gt_secure_result.status.value,
                "feedback": gt_secure_result.feedback
            }
            results["ground_truth_insecure"] = {
                "status": gt_insecure_result.status.value,
                "feedback": gt_insecure_result.feedback
            }
            
            if gt_secure_result.status != VerificationStatus.PASSED:
                results["errors"].append(f"Ground truth failed secure verifier: {gt_secure_result.feedback}")
                results["is_consistent"] = False
            if gt_insecure_result.status != VerificationStatus.PASSED:
                results["errors"].append(f"Ground truth failed insecure verifier: {gt_insecure_result.feedback}")
                results["is_consistent"] = False
            
            # Test exploit - should fail secure but pass insecure with expected status
            exploit_secure_result = self.verify_single(problem, problem.exploit, secure=True)
            exploit_insecure_result = self.verify_single(problem, problem.exploit, secure=False)
            results["exploit_secure"] = {
                "status": exploit_secure_result.status.value,
                "feedback": exploit_secure_result.feedback
            }
            results["exploit_insecure"] = {
                "status": exploit_insecure_result.status.value,
                "feedback": exploit_insecure_result.feedback
            }
            
            expected_insecure_status = VerificationStatus(problem.exploit_expected_status)
            if exploit_secure_result.status == VerificationStatus.PASSED:
                results["errors"].append(f"Exploit unexpectedly passed secure verifier: {exploit_secure_result.feedback}")
                results["is_consistent"] = False
            if exploit_insecure_result.status != expected_insecure_status:
                results["errors"].append(f"Exploit insecure status mismatch: expected {expected_insecure_status.value}, got {exploit_insecure_result.status.value}")
                results["is_consistent"] = False
            
            # Test nulls - should fail both verifiers
            for i, null_code in enumerate(problem.nulls):
                null_result_secure = self.verify_single(problem, null_code, secure=True)
                null_result_insecure = self.verify_single(problem, null_code, secure=False)
                
                null_result_dict = {
                    "secure": {
                        "status": null_result_secure.status.value,
                        "feedback": null_result_secure.feedback
                    },
                    "insecure": {
                        "status": null_result_insecure.status.value,
                        "feedback": null_result_insecure.feedback
                    },
                    "passes_consistency": True
                }
                
                # Check if null fails both verifiers (as expected)
                if (null_result_secure.status == VerificationStatus.PASSED or 
                    null_result_insecure.status == VerificationStatus.PASSED):
                    results["errors"].append(f"Null {i+1} unexpectedly passed a verifier")
                    null_result_dict["passes_consistency"] = False
                    results["is_consistent"] = False
                
                results["nulls_results"].append(null_result_dict)
            
        except Exception as e:
            results["errors"].append(f"Verification process error: {str(e)}")
            results["is_consistent"] = False
        
        return results 