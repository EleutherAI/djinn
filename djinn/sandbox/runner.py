"""
Minimal sandbox runner that only executes user code.
All verification logic is handled in the main process.
"""

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
    """Handle timeout signals."""
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


def execute_user_code(submission_code: str, function_name: str, test_input, timeout: int):
    """
    Execute user code with the given test input and return result.
    Returns dict with 'output', 'printed_output', 'execution_time', and 'error'.
    """
    # Set up timeout
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)
    
    try:
        # Execute submission code in namespace with imports
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
        
        # Capture stdout
        old_stdout = sys.stdout
        sys.stdout = captured_output = StringIO()
        
        start_time = time.time()
        
        # Call function
        actual_output = call_function_with_appropriate_args(submitted_function, test_input)
        
        execution_time = time.time() - start_time
        printed_output = captured_output.getvalue()
        sys.stdout = old_stdout
        
        # Return successful result
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
    """
    Main runner function. Reads config from file, executes user code, and prints result.
    """
    try:
        # Read configuration
        with open("/home/user/config.json", "r") as f:
            config = json.load(f)
        
        submission_code = config["submission_code"]
        function_name = config["function_name"]
        test_input = config["test_input"]
        timeout = config.get("timeout", 6)
        
        # Execute user code
        result = execute_user_code(submission_code, function_name, test_input, timeout)
        
        # Print result as JSON
        print(json.dumps(result))
        
    except Exception as e:
        # If anything goes wrong with the runner itself
        print(json.dumps({"error": f"Runner failed: {str(e)}"}))


if __name__ == "__main__":
    main()
