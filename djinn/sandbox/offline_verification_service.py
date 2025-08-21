"""
Offline verification service that runs locally using subprocess isolation.
Uses the same architecture as the online service but with subprocess instead of E2B.
"""

import os
import atexit
import sys
import json
import time
import tempfile
import subprocess
import psutil
import threading
import multiprocessing as mp
import signal
import inspect
from io import StringIO
import resource
import gc
from pathlib import Path
from typing import List, Dict, Any, Optional

from djinn.core.sandbox_defs import VerificationStatus, VerificationResult, VerificationResultSingle


def _is_process_running(process) -> bool:
    """Return True if the given process (subprocess.Popen or multiprocessing.Process) is running."""
    if hasattr(process, "poll"):
        return process.poll() is None
    if hasattr(process, "is_alive"):
        return process.is_alive()
    return False


def _prepare_user_namespace() -> dict:
    """Prepare a namespace with common stdlib utilities for user code execution."""
    # Local imports to keep parent import time minimal
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
    from typing import List as _List, Tuple as _Tuple, Dict as _Dict, Set as _Set, Optional as _Optional, Union as _Union, Any as _Any, Callable as _Callable, Iterable as _Iterable, Iterator as _Iterator, Generator as _Generator, Deque as _Deque
    import copy as _copy
    import string as _string
    import math as _math
    import collections as _collections
    import bisect as _bisect
    import heapq as _heapq
    import functools as _functools
    import random as _random
    import itertools as _itertools
    import operator as _operator
    import re as _re
    import datetime as _datetime
    import io as _io
    import os as _os

    class ListNode:
        def __init__(self, val=0, next=None):
            self.val = val
            self.next = next

    class TreeNode:
        def __init__(self, val=0, left=None, right=None):
            self.val = val
            self.left = left
            self.right = right

    def list_node(values: list[_Any]) -> _Optional[ListNode]:
        dummy = ListNode(0)
        current = dummy
        for value in values:
            current.next = ListNode(value)
            current = current.next
        return dummy.next

    def tree_node(values: list[_Any]) -> _Optional[TreeNode]:
        if not values:
            return None
        root = TreeNode(values[0])
        q = _collections.deque([root])
        i = 1
        while q and i < len(values):
            node = q.popleft()
            if values[i] is not None:
                node.left = TreeNode(values[i])
                q.append(node.left)
            i += 1
            if i < len(values) and values[i] is not None:
                node.right = TreeNode(values[i])
                q.append(node.right)
            i += 1
        return root

    # Expose symbols similar to the original runner script
    return {
        # imports with from ... import ...
        "accumulate": accumulate,
        "chain": chain,
        "combinations": combinations,
        "count": count,
        "permutations": permutations,
        "product": product,
        "groupby": groupby,
        "islice": islice,
        "repeat": repeat,
        "deepcopy": deepcopy,
        "ascii_lowercase": ascii_lowercase,
        "ascii_uppercase": ascii_uppercase,
        "floor": floor,
        "log2": log2,
        "log10": log10,
        "sqrt": sqrt,
        "comb": comb,
        "gcd": gcd,
        "ceil": ceil,
        "inf": inf,
        "isqrt": isqrt,
        "factorial": factorial,
        "atan2": atan2,
        "pi": pi,
        "log": log,
        "prod": prod,
        "defaultdict": defaultdict,
        "deque": deque,
        "Counter": Counter,
        "OrderedDict": OrderedDict,
        "bisect": bisect,
        "bisect_left": bisect_left,
        "bisect_right": bisect_right,
        "insort": insort,
        "heappush": heappush,
        "heappop": heappop,
        "heapify": heapify,
        "merge": merge,
        "nlargest": nlargest,
        "nsmallest": nsmallest,
        "heapreplace": heapreplace,
        "reduce": reduce,
        "cache": cache,
        "lru_cache": lru_cache,
        "cmp_to_key": cmp_to_key,
        "partial": partial,
        "randrange": randrange,
        "shuffle": shuffle,
        "itemgetter": itemgetter,
        "sub": sub,
        "xor": xor,
        "or_": or_,
        "iand": iand,
        "re_search": re_search,
        "commonprefix": commonprefix,
        # module aliases
        "copy": _copy,
        "string": _string,
        "math": _math,
        "collections": _collections,
        "bisect_module": _bisect,
        "heapq": _heapq,
        "functools": _functools,
        "random": _random,
        "itertools": _itertools,
        "operator": _operator,
        "re": _re,
        "datetime": _datetime,
        "io": _io,
        "os": _os,
        # helpers
        "ListNode": ListNode,
        "TreeNode": TreeNode,
        "list_node": list_node,
        "tree_node": tree_node,
    }

# Build user namespace once to amortize per-task work. With "fork", children share via COW;
# with "forkserver", it is built once in the server process and inherited by children.
PREPARED_NAMESPACE = _prepare_user_namespace()


def _daemon_memory_monitor(pid: int, memory_limit_bytes: int, exceeded_event: "threading.Event", stop_event: "threading.Event") -> None:
    try:
        proc = psutil.Process(pid)
        while not stop_event.is_set():
            if not proc.is_running():
                break
            try:
                rss = proc.memory_info().rss
                if rss > memory_limit_bytes:
                    exceeded_event.set()
                    try:
                        proc.terminate()
                        time.sleep(0.1)
                        if proc.is_running():
                            proc.kill()
                    except Exception:
                        pass
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            time.sleep(0.1)
    except Exception:
        pass


def _secure_daemon_loop(conn, memory_limit_bytes: int, memory_limit_mb: int) -> None:
    """Runs inside a clean forkserver process. Spawns per-request fork children for speed."""
    try:
        while True:
            try:
                req = conn.recv()
            except EOFError:
                break
            if not isinstance(req, dict):
                continue
            if req.get("cmd") == "shutdown":
                break

            # Spawn fast child via fork to execute batch
            try:
                ctx_fork = mp.get_context("fork")
                parent_ch, child_ch = ctx_fork.Pipe(duplex=False)
                child = ctx_fork.Process(target=_secure_child_entrypoint, args=(req, child_ch))
                child.daemon = False
                child.start()

                # Memory monitor in daemon
                exceeded_event = threading.Event()
                stop_event = threading.Event()
                mon = threading.Thread(target=_daemon_memory_monitor, args=(child.pid, memory_limit_bytes, exceeded_event, stop_event), daemon=True)
                mon.start()

                try:
                    per = int(req.get("timeout_per_test", req.get("timeout", 6)))
                    num = len(req.get("batch_inputs", [1]))
                    total_timeout = max(1, per + 1) * max(1, num) + 2
                    child.join(total_timeout)
                finally:
                    stop_event.set()

                if exceeded_event.is_set():
                    try:
                        if child.is_alive():
                            child.terminate()
                            child.join(0.2)
                            if child.is_alive():
                                child.kill()
                    except Exception:
                        pass
                    conn.send({"batch_results": [{"error": f"Memory limit exceeded ({memory_limit_mb}MB)"} for _ in req.get("batch_inputs", [None])]})
                    continue

                if child.is_alive():
                    try:
                        child.terminate()
                        child.join(0.2)
                        if child.is_alive():
                            child.kill()
                    except Exception:
                        pass
                    conn.send({"subprocess_error": "Subprocess timed out"})
                    continue

                try:
                    if parent_ch.poll(0):
                        result = parent_ch.recv()
                        conn.send(result)
                    else:
                        conn.send({"subprocess_error": "No result from subprocess"})
                finally:
                    try:
                        parent_ch.close()
                    except Exception:
                        pass
            except Exception as e:
                conn.send({"subprocess_error": f"Daemon error: {e}"})
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _insecure_daemon_loop(conn, memory_limit_bytes: int, memory_limit_mb: int) -> None:
    """Daemon loop for insecure verifier: forks per request and enforces memory/timeout."""
    try:
        while True:
            try:
                req = conn.recv()
            except EOFError:
                break
            if not isinstance(req, dict):
                continue
            if req.get("cmd") == "shutdown":
                break

            try:
                ctx_fork = mp.get_context("fork")
                parent_ch, child_ch = ctx_fork.Pipe(duplex=False)
                # Always use module-based insecure verifier entrypoint
                child = ctx_fork.Process(target=_insecure_module_child_entrypoint, args=(memory_limit_bytes, memory_limit_mb, req, child_ch))
                child.daemon = False
                child.start()

                exceeded_event = threading.Event()
                stop_event = threading.Event()
                mon = threading.Thread(target=_daemon_memory_monitor, args=(child.pid, memory_limit_bytes, exceeded_event, stop_event), daemon=True)
                mon.start()

                try:
                    child.join(15)
                finally:
                    stop_event.set()

                if exceeded_event.is_set():
                    try:
                        if child.is_alive():
                            child.terminate()
                            child.join(0.2)
                            if child.is_alive():
                                child.kill()
                    except Exception:
                        pass
                    conn.send({"status": "crashed", "feedback": f"Memory limit exceeded ({memory_limit_mb}MB)"})
                    continue

                if child.is_alive():
                    try:
                        child.terminate()
                        child.join(0.2)
                        if child.is_alive():
                            child.kill()
                    except Exception:
                        pass
                    conn.send({"subprocess_error": "Subprocess timed out"})
                    continue

                try:
                    if parent_ch.poll(0):
                        result = parent_ch.recv()
                        conn.send(result)
                    else:
                        conn.send({"subprocess_error": "No result from subprocess"})
                finally:
                    try:
                        parent_ch.close()
                    except Exception:
                        pass
            except Exception as e:
                conn.send({"subprocess_error": f"Daemon error: {e}"})
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _call_function_with_appropriate_args(func, test_input):
    """Best-effort invocation that adapts to the function arity and input shape."""
    try:
        sig = inspect.signature(func)
        param_count = len(sig.parameters)
    except (ValueError, TypeError):
        # Builtins or C-extensions may not have a signature
        param_count = None

    try:
        if param_count == 0:
            return func()
        if param_count == 1:
            return func(test_input)
        # For functions expecting multiple parameters
        if isinstance(test_input, (tuple, list)):
            return func(*test_input)
        return func(test_input)
    except TypeError:
        # Fallback to alternate calling convention
        if isinstance(test_input, tuple):
            return func(*test_input)
        return func(test_input)


def _secure_child_entrypoint(config: dict, conn) -> None:
    """Child process entrypoint for secure execution path."""
    # Setup timeout using SIGALRM in the child
    def _timeout_handler(signum, frame):
        raise Exception("TimeoutException")

    signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(int(config.get("timeout", 6)))
    try:
        submission_code = config["submission_code"]
        function_name = config["function_name"]
        test_input = config.get("test_input")
        batch_inputs = config.get("batch_inputs")

        # Build namespace for user code
        namespace = {"__builtins__": __builtins__}
        namespace.update(PREPARED_NAMESPACE)

        exec(submission_code, namespace)
        if function_name not in namespace:
            conn.send({"error": f"Function '{function_name}' not found in submission"})
            return
        submitted_function = namespace[function_name]
        if not callable(submitted_function):
            conn.send({"error": f"'{function_name}' exists but is not callable"})
            return
        # Single test or batch mode
        if batch_inputs is not None:
            results = []
            per_timeout = int(config.get("timeout_per_test", 6))
            for ti in batch_inputs:
                # enforce per-test timeout via alarm; reset each iteration
                signal.alarm(per_timeout)
                try:
                    old_stdout = sys.stdout
                    sys.stdout = captured_output = StringIO()
                    start_time = time.time()
                    out = _call_function_with_appropriate_args(submitted_function, ti)
                    exec_time = time.time() - start_time
                    printed_output = captured_output.getvalue()
                    sys.stdout = old_stdout
                    results.append({
                        "output": out,
                        "printed_output": printed_output,
                        "execution_time": exec_time,
                        "error": None,
                    })
                except Exception as e:
                    # capture error per test
                    err = str(e) or f"Unknown error: {type(e).__name__}"
                    if "timeoutexception" in err.lower():
                        err = "Time Limit Exceeded"
                    try:
                        sys.stdout = old_stdout
                    except Exception:
                        pass
                    results.append({"error": err})
                finally:
                    try:
                        signal.alarm(0)
                    except Exception:
                        pass
            conn.send({"batch_results": results})
        else:
            try:
                old_stdout = sys.stdout
                sys.stdout = captured_output = StringIO()
                start_time = time.time()
                actual_output = _call_function_with_appropriate_args(submitted_function, test_input)
                execution_time = time.time() - start_time
                printed_output = captured_output.getvalue()
                sys.stdout = old_stdout
                conn.send({
                    "output": actual_output,
                    "printed_output": printed_output,
                    "execution_time": execution_time,
                    "error": None,
                })
            finally:
                try:
                    signal.alarm(0)
                except Exception:
                    pass
    except SyntaxError as e:
        conn.send({"error": f"Syntax error: {str(e)}"})
    except Exception as e:
        error_msg = str(e) or f"Unknown error: {type(e).__name__}"
        if "timeoutexception" in error_msg.lower():
            error_msg = "Time Limit Exceeded"
        conn.send({"error": error_msg})
    finally:
        try:
            signal.alarm(0)
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


def _insecure_module_child_entrypoint(memory_limit_bytes: int, memory_limit_mb: int, config: dict, conn) -> None:
    """Child process entrypoint for running module-based insecure verifiers safely."""
    # Apply memory limits
    try:
        resource.setrlimit(resource.RLIMIT_AS, (memory_limit_bytes, memory_limit_bytes))
        resource.setrlimit(resource.RLIMIT_DATA, (memory_limit_bytes, memory_limit_bytes))
    except Exception as e:
        conn.send({"status": "crashed", "feedback": f"Failed to set memory limits: {str(e)}"})
        return

    def _timeout_handler(signum, frame):
        raise Exception("Timeout")

    signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(10)

    try:
        submission_code = config["submission_code"]
        exploit_type = config["exploit_type"]
        function_name = config["function_name"]
        test_cases = config.get("test_cases", [])
        order_dependent = bool(config.get("order_dependent", True))

        # Lightweight Problem surrogate for insecure verifiers
        class _DummyProblem:
            def __init__(self, function_name, test_cases, order_dependent):
                self.function_name = function_name
                self.test_cases = test_cases
                self.order_dependent = order_dependent

            def _normalize_test_cases(self):
                return self.test_cases or []

        dummy_problem = _DummyProblem(function_name, test_cases, order_dependent)

        # Load verifier module and execute
        from djinn.verifiers import load_verifier
        verifier_module = load_verifier(exploit_type, category="insecure")
        result = verifier_module.verify(dummy_problem, submission_code)

        status = getattr(result, "status", "crashed")
        feedback = getattr(result, "feedback", None)
        # Convert enum-like to primitive
        try:
            status_val = status.value if hasattr(status, "value") else str(status)
        except Exception:
            status_val = str(status)
        conn.send({"status": status_val, "feedback": feedback})
    except MemoryError:
        conn.send({"status": "crashed", "feedback": f"Memory limit exceeded ({memory_limit_mb}MB)"})
    except Exception as e:
        msg = str(e) or f"Unknown error: {type(e).__name__}"
        if "timeout" in msg.lower():
            conn.send({"status": "timed_out", "feedback": "Insecure verifier timed out"})
        else:
            conn.send({"status": "crashed", "feedback": f"Insecure verifier crashed: {msg}"})
    finally:
        try:
            signal.alarm(0)
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


def _insecure_child_entrypoint(memory_limit_bytes: int, memory_limit_mb: int, config: dict, conn) -> None:
    """Deprecated shim kept for compatibility; forward to module-based entrypoint."""
    return _insecure_module_child_entrypoint(memory_limit_bytes, memory_limit_mb, config, conn)


class OfflineVerificationService:
    """
    Service for running verification operations locally using subprocess isolation.
    Provides the same interface as the online E2B service.
    """
    
    def __init__(self, memory_limit_mb: int = 500):
        self.memory_limit_mb = memory_limit_mb
        self.memory_limit_bytes = memory_limit_mb * 1024 * 1024
        # Forkserver daemon state (lazy-started)
        self._secure_daemon = None
        self._daemon_parent_conn = None
        self._insecure_daemon = None
        self._insecure_parent_conn = None
        # External (unshare) daemon state
        self._secure_stdin = None
        self._secure_stdout = None
        self._insecure_stdin = None
        self._insecure_stdout = None
        self._secure_external = False
        self._insecure_external = False
        atexit.register(self._shutdown_secure_daemon)
        atexit.register(self._shutdown_insecure_daemon)

    def _ensure_daemon(self, mode: str):
        """Ensure a daemon is running for the given mode.
        Prefer external unshare-wrapped daemon; fall back to internal forkserver daemon if unavailable.
        Returns a tuple describing the active transport for the given mode.
        """
        python_path = sys.executable
        daemon_module = "djinn.sandbox.daemon_bridge"
        mem_arg = str(self.memory_limit_mb)
        if mode == "secure":
            # Already running
            if self._secure_external and self._secure_daemon is not None and _is_process_running(self._secure_daemon):
                return ("external", self._secure_daemon, self._secure_stdin, self._secure_stdout)
            if (not self._secure_external) and (self._secure_daemon is not None) and _is_process_running(self._secure_daemon):
                return ("internal", self._daemon_parent_conn)
            # Try external
            try:
                cmd = [
                    "unshare", "-Urmp", "--mount-proc", "--fork", "bash", "-lc",
                    f"exec {python_path} -m {daemon_module} --mode secure --mem {mem_arg}"
                ]
                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
                # Give it a brief moment; if it exits, fall back
                time.sleep(0.05)
                if proc.poll() is None:
                    self._secure_external = True
                    self._secure_daemon, self._secure_stdin, self._secure_stdout = proc, proc.stdin, proc.stdout
                    return ("external", proc, proc.stdin, proc.stdout)
                else:
                    # External unavailable, fall back
                    raise RuntimeError("unshare daemon exited")
            except Exception:
                # Internal forkserver daemon
                ctx = mp.get_context("forkserver")
                self._daemon_parent_conn, daemon_child_conn = ctx.Pipe(duplex=True)
                self._secure_daemon = ctx.Process(target=_secure_daemon_loop, args=(daemon_child_conn, self.memory_limit_bytes, self.memory_limit_mb))
                self._secure_daemon.daemon = False
                self._secure_daemon.start()
                self._secure_external = False
                return ("internal", self._daemon_parent_conn)
        elif mode == "insecure":
            if self._insecure_external and self._insecure_daemon is not None and _is_process_running(self._insecure_daemon):
                return ("external", self._insecure_daemon, self._insecure_stdin, self._insecure_stdout)
            if (not self._insecure_external) and (self._insecure_daemon is not None) and _is_process_running(self._insecure_daemon):
                return ("internal", self._insecure_parent_conn)
            try:
                cmd = [
                    "unshare", "-Urmp", "--mount-proc", "--fork", "bash", "-lc",
                    f"exec {python_path} -m {daemon_module} --mode insecure --mem {mem_arg}"
                ]
                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
                time.sleep(0.05)
                if proc.poll() is None:
                    self._insecure_external = True
                    self._insecure_daemon, self._insecure_stdin, self._insecure_stdout = proc, proc.stdin, proc.stdout
                    return ("external", proc, proc.stdin, proc.stdout)
                else:
                    raise RuntimeError("unshare daemon exited")
            except Exception:
                ctx = mp.get_context("forkserver")
                self._insecure_parent_conn, child_conn = ctx.Pipe(duplex=True)
                self._insecure_daemon = ctx.Process(target=_insecure_daemon_loop, args=(child_conn, self.memory_limit_bytes, self.memory_limit_mb))
                self._insecure_daemon.daemon = False
                self._insecure_daemon.start()
                self._insecure_external = False
                return ("internal", self._insecure_parent_conn)
        else:
            raise ValueError(f"Unknown daemon mode: {mode}")

    def _send_daemon_request(self, mode: str, config: dict, total_timeout_seconds: int) -> dict:
        """Send request to either external (stdio JSON) or internal (Pipe) daemon."""
        transport = self._ensure_daemon(mode)
        if transport[0] == "external":
            _, _, sin, sout = transport
            try:
                sin.write(json.dumps(config) + "\n")
                sin.flush()
            except Exception:
                return {"subprocess_error": "Daemon unavailable"}
            deadline = time.time() + total_timeout_seconds
            while time.time() < deadline:
                line = sout.readline()
                if not line:
                    time.sleep(0.01)
                    continue
                try:
                    return json.loads(line.strip())
                except Exception as e:
                    return {"subprocess_error": f"Invalid daemon response: {e}"}
            return {"subprocess_error": "Daemon timed out"}
        else:
            # internal: transport = ("internal", parent_conn)
            parent_conn = transport[1]
            try:
                parent_conn.send(config)
                start = time.time()
                while time.time() - start < total_timeout_seconds:
                    if parent_conn.poll(0.05):
                        return parent_conn.recv()
                return {"subprocess_error": "Daemon timed out"}
            except (EOFError, BrokenPipeError):
                return {"subprocess_error": "Daemon unavailable"}

    def _shutdown_secure_daemon(self) -> None:
        try:
            if getattr(self, "_secure_daemon", None) is not None and _is_process_running(self._secure_daemon):
                try:
                    if getattr(self, "_daemon_parent_conn", None) is not None:
                        try:
                            self._daemon_parent_conn.send({"cmd": "shutdown"})
                        except Exception:
                            pass
                except Exception:
                    pass
                # Give daemon a brief moment to exit
                try:
                    self._secure_daemon.join(0.5)
                except Exception:
                    pass
                # If still alive, terminate
                if _is_process_running(self._secure_daemon) and hasattr(self._secure_daemon, 'terminate'):
                    try:
                        self._secure_daemon.terminate()
                        self._secure_daemon.join(0.2)
                        if _is_process_running(self._secure_daemon) and hasattr(self._secure_daemon, 'kill'):
                            self._secure_daemon.kill()
                    except Exception:
                        pass
        finally:
            try:
                if getattr(self, "_daemon_parent_conn", None) is not None:
                    try:
                        self._daemon_parent_conn.close()
                    except Exception:
                        pass
            finally:
                self._secure_daemon = None
                self._daemon_parent_conn = None

    def _shutdown_insecure_daemon(self) -> None:
        try:
            if getattr(self, "_insecure_daemon", None) is not None and _is_process_running(self._insecure_daemon):
                try:
                    if getattr(self, "_insecure_parent_conn", None) is not None:
                        try:
                            self._insecure_parent_conn.send({"cmd": "shutdown"})
                        except Exception:
                            pass
                except Exception:
                    pass
                try:
                    self._insecure_daemon.join(0.5)
                except Exception:
                    pass
                if _is_process_running(self._insecure_daemon) and hasattr(self._insecure_daemon, 'terminate'):
                    try:
                        self._insecure_daemon.terminate()
                        self._insecure_daemon.join(0.2)
                        if _is_process_running(self._insecure_daemon) and hasattr(self._insecure_daemon, 'kill'):
                            self._insecure_daemon.kill()
                    except Exception:
                        pass
        finally:
            try:
                if getattr(self, "_insecure_parent_conn", None) is not None:
                    try:
                        self._insecure_parent_conn.close()
                    except Exception:
                        pass
            finally:
                self._insecure_daemon = None
                self._insecure_parent_conn = None
    
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
        # Use secure_test_cases if available, otherwise fall back to full test_cases
        secure_test_cases = getattr(problem, 'secure_test_cases', None)
        if secure_test_cases is not None:
            normalized_test_cases = secure_test_cases
        else:
            normalized_test_cases = problem._normalize_test_cases()
        order_dependent = getattr(problem, 'order_dependent', True)
        
        failed_tests = []
        total_execution_time = 0

        # Prepare a single-batch execution to reduce process startup cost
        batch_inputs = [ti for (ti, _) in normalized_test_cases]
        config = {
            "submission_code": submission_code,
            "function_name": problem.function_name,
            "batch_inputs": batch_inputs,
            "timeout_per_test": 10,
        }

        # Execute all tests in one child process via external namespaced daemon
        per = int(config.get("timeout_per_test", config.get("timeout", 6)))
        num = len(config.get("batch_inputs", [1]))
        total_timeout = max(1, per + 1) * max(1, num) + 2
        execution_result = self._send_daemon_request("secure", config, total_timeout)

        # Handle subprocess execution errors
        if execution_result.get("subprocess_error"):
            # Mark all tests as failed for feedback clarity
            for i, test_input in enumerate(batch_inputs):
                failed_tests.append(f"Test {i+1}: input={repr(test_input)}, error: {execution_result['subprocess_error']}")
        elif "batch_results" in execution_result:
            batch_results = execution_result["batch_results"]
            for i, ((test_input, expected_output), res) in enumerate(zip(normalized_test_cases, batch_results)):
                if res.get("error"):
                    error_msg = res["error"]
                    if isinstance(error_msg, str) and "timeout" in error_msg.lower():
                        error_msg = "Time Limit Exceeded"
                    failed_tests.append(f"Test {i+1}: input={repr(test_input)}, error: {error_msg}")
                    continue
                actual_output = res.get("output")
                printed_output = res.get("printed_output", "")
                execution_time = res.get("execution_time", 0)
                total_execution_time += execution_time
                test_failed = self._compare_outputs(
                    actual_output, expected_output, printed_output,
                    order_dependent, test_input, i+1,
                )
                if test_failed:
                    failed_tests.append(test_failed)
        else:
            # Unexpected payload
            failed_tests.append("Secure subprocess returned unexpected payload")
        
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
        """Run insecure verification using the problem's exploit_type to load verifier from @insecure/ directory."""
        try:
            exploit_type = getattr(problem, 'exploit_type', None)
            if not exploit_type:
                return VerificationResultSingle(
                    status=VerificationStatus.CRASHED,
                    feedback="No exploit_type specified - fallback disabled for testing"
                )

            # Prepare config for child process
            normalized_test_cases = problem._normalize_test_cases()
            cfg = {
                "submission_code": submission_code,
                "exploit_type": exploit_type,
                "function_name": problem.function_name,
                "test_cases": normalized_test_cases,
                "order_dependent": getattr(problem, 'order_dependent', True),
            }

            # Run via the insecure daemon to ensure crashes map to CRASHED
            per = 10
            num = max(1, len(normalized_test_cases))
            total_timeout = max(1, per + 1) * num + 2
            cfg["cmd"] = "run"
            cfg["kind"] = "module"
            execution_result = self._send_daemon_request("insecure", cfg, total_timeout)

            if execution_result.get("subprocess_error"):
                return VerificationResultSingle(status=VerificationStatus.CRASHED, feedback=execution_result["subprocess_error"])

            status_str = execution_result.get("status", "crashed")
            feedback = execution_result.get("feedback")
            # Normalize to enum
            status_enum = {
                "passed": VerificationStatus.PASSED,
                "failed": VerificationStatus.FAILED,
                "crashed": VerificationStatus.CRASHED,
                "timed_out": VerificationStatus.TIMED_OUT,
            }.get(status_str, VerificationStatus.CRASHED)
            return VerificationResultSingle(status=status_enum, feedback=feedback)
        except Exception as e:
            return VerificationResultSingle(
                status=VerificationStatus.CRASHED,
                feedback=f"Insecure verification failed: {str(e)}"
            )
    
    def _create_runner_script(self):
        """Create the subprocess runner script (kept for compatibility; unused with forkserver)."""
        return ''

    def _run_in_subprocess(self, config: dict) -> dict:
        """Deprecated: replaced by daemon helpers. Kept for compatibility."""
        # Send via external namespaced daemon
        per = int(config.get("timeout_per_test", config.get("timeout", 6)))
        num = len(config.get("batch_inputs", [1]))
        total_timeout = max(1, per + 1) * max(1, num) + 2
        return self._send_daemon_request("secure", config, total_timeout)
    
    def _monitor_memory_usage(self, process, memory_exceeded_event, monitor_stop_event):
        """Monitor process memory usage and terminate if it exceeds the limit."""
        try:
            pid = getattr(process, 'pid', None)
            if pid is None:
                return
            psutil_process = psutil.Process(pid)
            while not monitor_stop_event.is_set() and _is_process_running(process):  # While process is still running
                try:
                    memory_info = psutil_process.memory_info()
                    memory_usage = memory_info.rss  # Resident Set Size (physical memory)
                    
                    if memory_usage > self.memory_limit_bytes:
                        print(f"Memory limit exceeded: {memory_usage / (1024*1024):.1f}MB > {self.memory_limit_mb}MB")
                        memory_exceeded_event.set()
                        if hasattr(process, 'terminate'):
                            process.terminate()
                        # Give it a moment to terminate gracefully
                        time.sleep(0.1)
                        # Kill if still alive
                        if _is_process_running(process) and hasattr(process, 'kill'):
                            process.kill()
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Process ended or we lost access
                    break
                time.sleep(0.1)  # Check every 100ms
        except Exception as e:
            print(f"Memory monitoring error: {e}")

    def _run_insecure_verifier_subprocess(self, runner_script: str, config: dict) -> dict:
        """Run the insecure verifier via a long-lived forkserver daemon that forks per request."""
        try:
            if not hasattr(self, "_insecure_daemon") or self._insecure_daemon is None or not _is_process_running(self._insecure_daemon):
                ctx = mp.get_context("forkserver")
                self._insecure_parent_conn, insecure_child_conn = ctx.Pipe(duplex=True)
                self._insecure_daemon = ctx.Process(target=_insecure_daemon_loop, args=(insecure_child_conn, self.memory_limit_bytes, self.memory_limit_mb))
                # Must not be daemonic; it forks children per request
                self._insecure_daemon.daemon = False
                self._insecure_daemon.start()

            try:
                self._insecure_parent_conn.send(config)
                start = time.time()
                while time.time() - start < 15:
                    if self._insecure_parent_conn.poll(0.05):
                        return self._insecure_parent_conn.recv()
                return {"subprocess_error": "Daemon timed out"}
            except (EOFError, BrokenPipeError):
                try:
                    self._insecure_daemon = None
                except Exception:
                    pass
                return {"subprocess_error": "Daemon unavailable"}
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