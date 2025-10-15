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
import uuid
import logging
import hashlib

from djinn.core.sandbox_defs import VerificationStatus, VerificationResult, VerificationResultSingle
from djinn.core.problem import Problem


def _get_daemon_logger(logger_name: str, log_path_env: str, default_path: str) -> logging.Logger:
    """Create or return a per-process logger that writes to the given file path.

    We intentionally log to a file to avoid interfering with parent/child IPC over pipes.
    """
    logger = logging.getLogger(logger_name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    log_path = os.getenv(log_path_env, default_path)
    try:
        handler = logging.FileHandler(log_path, encoding="utf-8")
    except Exception:
        # Fallback to stderr if file cannot be opened
        handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [%(process)d:%(threadName)s] %(name)s: %(message)s",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


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


def _daemon_memory_monitor(pid: int, memory_limit_bytes: int, exceeded_event: "threading.Event", stop_event: "threading.Event", peak: Dict[str, int]) -> None:
    try:
        proc = psutil.Process(pid)
        while not stop_event.is_set():
            if not proc.is_running():
                break
            try:
                rss = proc.memory_info().rss
                peak["peak"] = max(peak["peak"], rss)
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
    logger = _get_daemon_logger(
        logger_name="djinn.secure_daemon",
        log_path_env="DJINN_VERIFIER_INTERNAL_SECURE_LOG",
        default_path="/tmp/djinn_verifier_internal_secure.log",
    )
    
    def _log(msg: str) -> None:
        logger.info(msg)
    try:
        _log("start loop")
        while True:
            try:
                req = conn.recv()
            except EOFError:
                _log("eof")
                break
            if not isinstance(req, dict):
                _log("non-dict request ignored")
                continue
            if req.get("cmd") == "shutdown":
                _log("shutdown cmd")
                break

            # Spawn fast child via fork to execute batch
            try:
                ctx_fork = mp.get_context("fork")
                parent_ch, child_ch = ctx_fork.Pipe(duplex=False)
                child = ctx_fork.Process(target=_secure_child_entrypoint, args=(req, child_ch))
                child.daemon = False
                child.start()
                child_start_ts = time.time()
                try:
                    child_ch.close()
                except Exception:
                    pass
                _log(f"child started pid={child.pid}")

                # Memory monitor in daemon
                exceeded_event = threading.Event()
                stop_event = threading.Event()
                peak = {"peak": 0}
                mon = threading.Thread(
                    target=_daemon_memory_monitor,
                    args=(child.pid, memory_limit_bytes, exceeded_event, stop_event, peak),
                    daemon=True,
                )
                mon.start()

                try:
                    per = int(req.get("timeout_per_test", req.get("timeout", 6)))
                    num = len(req.get("batch_inputs", [1]))
                    total_timeout = req.get("total_timeout")
                    if total_timeout is None:
                        total_timeout = max(1, per + 1) * max(1, num) + 2
                    _log(f"waiting for child {child.pid} with timeout {int(total_timeout)}s")
                    child.join(int(total_timeout))
                    _log(f"child {child.pid} join completed, alive={child.is_alive()}")
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
                    elapsed = time.time() - child_start_ts
                    peak_mb = peak.get("peak", 0) / (1024 * 1024)
                    _log(f"memory exceeded pid={child.pid} runtime={elapsed:.3f}s peak_rss={peak_mb:.1f}MB limit={memory_limit_mb}MB, code={req}")
                    continue

                if child.is_alive():
                    try:
                        child.terminate()
                        child.join(0.2)
                        if child.is_alive():
                            child.kill()
                    except Exception:
                        pass
                    elapsed = time.time() - child_start_ts
                    _log(f"timeout pid={child.pid} runtime={elapsed:.3f}s")
                    continue

                try:
                    if parent_ch.poll(0):
                        result = parent_ch.recv()
                        try:
                            # Log a compact summary to help trace mismatches
                            pid = req.get("problem_id")
                            fn = req.get("function_name")
                            csha = req.get("code_sha")
                            br = result.get("batch_results") if isinstance(result, dict) else None
                            sample = br[0] if isinstance(br, list) and br else None
                            _log(f"service_logger: secure child result pid={pid} fn={fn} code_sha={csha} batch_len={(len(br) if isinstance(br, list) else 'n/a')} sample={sample}")
                        except Exception:
                            pass
                        conn.send(result)
                        elapsed = time.time() - child_start_ts
                        _log(f"result sent runtime={elapsed:.3f}s")
                    else:
                        conn.send({"subprocess_error": "No result from subprocess"})
                        elapsed = time.time() - child_start_ts
                        _log(f"no result from child runtime={elapsed:.3f}s")
                finally:
                    try:
                        parent_ch.close()
                    except Exception:
                        pass
            except Exception as e:
                # Avoid sending errors to parent; just log to prevent BrokenPipe when parent is gone
                logger.exception("daemon error while handling request: %r", e)
    finally:
        try:
            conn.close()
        except Exception:
            pass
        _log("exit loop")


def _insecure_daemon_loop(conn, memory_limit_bytes: int, memory_limit_mb: int) -> None:
    """Daemon loop for insecure verifier: forks per request and enforces memory/timeout."""
    logger = _get_daemon_logger(
        logger_name="djinn.insecure_daemon",
        log_path_env="DJINN_VERIFIER_INTERNAL_INSECURE_LOG",
        default_path="/tmp/djinn_verifier_internal_insecure.log",
    )
    
    def _log(msg: str) -> None:
        logger.info(msg)
    try:
        _log("start loop")
        while True:
            try:
                req = conn.recv()
            except EOFError:
                _log("eof")
                break
            if not isinstance(req, dict):
                _log("non-dict request ignored")
                continue
            if req.get("cmd") == "shutdown":
                _log("shutdown cmd")
                break

            try:
                ctx_fork = mp.get_context("fork")
                parent_ch, child_ch = ctx_fork.Pipe(duplex=False)
                # Always use module-based insecure verifier entrypoint
                child = ctx_fork.Process(target=_insecure_module_child_entrypoint, args=(memory_limit_bytes, memory_limit_mb, req, child_ch))
                child.daemon = False
                child.start()
                child_start_ts = time.time()
                try:
                    child_ch.close()
                except Exception:
                    pass
                _log(f"child started pid={child.pid}")

                exceeded_event = threading.Event()
                stop_event = threading.Event()
                peak = {"peak": 0}
                mon = threading.Thread(
                    target=_daemon_memory_monitor,
                    args=(child.pid, memory_limit_bytes, exceeded_event, stop_event, peak),
                    daemon=True,
                )
                mon.start()

                try:
                    total_timeout = req.get("total_timeout", 15)
                    _log(f"waiting for child {child.pid} with timeout {int(total_timeout)}s")
                    child.join(int(total_timeout))
                    _log(f"child {child.pid} join completed, alive={child.is_alive()}")
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
                    elapsed = time.time() - child_start_ts
                    peak_mb = peak.get("peak", 0) / (1024 * 1024)
                    _log(f"memory exceeded pid={child.pid} runtime={elapsed:.3f}s peak_rss={peak_mb:.1f}MB limit={memory_limit_mb}MB")
                    # Avoid sending to parent here to prevent BrokenPipe if parent timed out
                    continue

                if child.is_alive():
                    try:
                        if child.is_alive():
                            child.terminate()
                            child.join(0.2)
                            if child.is_alive():
                                child.kill()
                    except Exception:
                        pass
                    elapsed = time.time() - child_start_ts
                    _log(f"timeout pid={child.pid} runtime={elapsed:.3f}s")
                    # Avoid sending to parent here to prevent BrokenPipe if parent timed out
                    continue

                try:
                    if parent_ch.poll(0):
                        result = parent_ch.recv()
                        if isinstance(result, dict) and "request_id" not in result:
                            result["request_id"] = req.get("request_id")
                        conn.send(result)
                        elapsed = time.time() - child_start_ts
                        _log(f"result sent runtime={elapsed:.3f}s")
                    else:
                        conn.send({"request_id": req.get("request_id"), "subprocess_error": "No result from subprocess"})
                        elapsed = time.time() - child_start_ts
                        _log(f"no result from child runtime={elapsed:.3f}s")
                finally:
                    try:
                        parent_ch.close()
                    except Exception:
                        pass
            except Exception as e:
                logger.exception("daemon error while handling request: %r", e)
    finally:
        try:
            conn.close()
        except Exception:
            pass
        _log("exit loop")


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

    logger = _get_daemon_logger(
        logger_name="djinn.secure_daemon",
        log_path_env="DJINN_VERIFIER_INTERNAL_SECURE_LOG",
        default_path="/tmp/djinn_verifier_internal_secure.log",
    )

    try:
        submission_code = config["submission_code"]
        function_name = config["function_name"]
        test_input = config.get("test_input")
        batch_inputs = config.get("batch_inputs")
        request_id = config.get("request_id")

        code_sha = hashlib.sha1((submission_code or "").encode("utf-8", errors="ignore")).hexdigest()[:10]

        logger.info(f"secure child entrypoint: code_sha={code_sha} function_name={function_name} test_input={test_input} batch_inputs={batch_inputs}")

        # Build namespace for user code
        namespace = {"__builtins__": __builtins__}
        namespace.update(PREPARED_NAMESPACE)

        exec(submission_code, namespace)
        if function_name not in namespace:
            conn.send({"request_id": request_id, "error": f"Function '{function_name}' not found in submission"})
            return
        submitted_function = namespace[function_name]
        if not callable(submitted_function):
            conn.send({"request_id": request_id, "error": f"'{function_name}' exists but is not callable"})
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
            logger.info(f"code_sha: {code_sha} secure child entrypoint: batch_results={results}")
            conn.send({"request_id": request_id, "batch_results": results})
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
                    "request_id": request_id,
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
        conn.send({"request_id": config.get("request_id"), "error": f"Syntax error: {str(e)}"})
    except Exception as e:
        error_msg = str(e) or f"Unknown error: {type(e).__name__}"
        if "timeoutexception" in error_msg.lower():
            error_msg = "Time Limit Exceeded"
        conn.send({"request_id": config.get("request_id"), "error": error_msg})
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

    logger = _get_daemon_logger(
        logger_name="djinn.insecure_daemon",
        log_path_env="DJINN_VERIFIER_INTERNAL_INSECURE_LOG",
        default_path="/tmp/djinn_verifier_internal_insecure.log",
    )

    try:
        request_id = config.get("request_id")
        submission_code = config["submission_code"]
        exploit_type = config["exploit_type"]
        function_name = config["function_name"]
        test_cases = config.get("test_cases", [])
        order_dependent = bool(config.get("order_dependent", True))

        code_sha = hashlib.sha1((submission_code or "").encode("utf-8", errors="ignore")).hexdigest()[:10]

        logger.info(f"insecure child entrypoint: code_sha={code_sha} exploit_type={exploit_type}")

        # Lightweight Problem surrogate for insecure verifiers
        class _DummyProblem:
            def __init__(self, function_name, test_cases, order_dependent):
                self.function_name = function_name
                self.test_cases = test_cases
                self.order_dependent = order_dependent

            def get_test_cases_safe(self):
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
        logger.info(f"insecure child entrypoint: code_sha={code_sha} exploit_type={exploit_type} status={status_val} feedback={feedback}")
        conn.send({"request_id": request_id, "status": status_val, "feedback": feedback})
    except MemoryError:
        conn.send({"request_id": config.get("request_id"), "status": "crashed", "feedback": f"Memory limit exceeded ({memory_limit_mb}MB)"})
    except Exception as e:
        msg = str(e) or f"Unknown error: {type(e).__name__}"
        if "timeout" in msg.lower():
            conn.send({"request_id": config.get("request_id"), "status": "timed_out", "feedback": "Insecure verifier timed out"})
        else:
            conn.send({"request_id": config.get("request_id"), "status": "crashed", "feedback": f"Insecure verifier crashed: {msg}"})
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
    
    def __init__(self, memory_limit_mb: int = 3000):
        self.memory_limit_mb = memory_limit_mb
        self.memory_limit_bytes = memory_limit_mb * 1024 * 1024
        # Thread-local daemon storage (legacy; kept as fallback only)
        import threading
        self._thread_local = threading.local()
        # Strong refs so parent pipe ends don't get GC'd when threads exit mid-flight
        self._internal_conn_refs = []  # list of multiprocessing.Connection
        # Process-wide shared daemons per mode with per-mode locks
        # Structure: { mode: { 'external': bool, 'daemon'|'proc': Process|Popen,
        #                      'conn'|'stdin'|'stdout': Connection|IO,
        #                      'lock': threading.Lock() } }
        self._shared_daemons = {}
        # Cache external unshare availability per mode
        self._unshare_failed = {}
        atexit.register(self._shutdown_all_daemons)

    def _ensure_daemon(self, mode: str):
        """Ensure a process-wide daemon is running for the given mode.
        Returns a transport tuple including a per-mode lock for serialization.
        """
        import threading
        thread_id = threading.get_ident()

        # If shared daemon exists and is alive, return it
        shared = self._shared_daemons.get(mode)
        if shared:
            try:
                if shared['external']:
                    if _is_process_running(shared['proc']):
                        return ("external", shared['proc'], shared['stdin'], shared['stdout'], shared['lock'])
                else:
                    if _is_process_running(shared['daemon']):
                        return ("internal", shared['conn'], shared['lock'])
            except Exception:
                pass

        # No live shared daemon; (re)create
        python_path = sys.executable
        daemon_module = "djinn.sandbox.daemon_bridge"
        mem_arg = str(self.memory_limit_mb)

        # Try external once unless previously marked failed
        if not self._unshare_failed.get(mode, False):
            try:
                cmd = [
                    "unshare", "-Urmp", "--mount-proc", "--fork", "bash", "-lc",
                    f"exec {python_path} -m {daemon_module} --mode {mode} --mem {mem_arg}"
                ]
                stderr_log = open(f"/tmp/djinn_daemon_bridge_{mode}.log", "a")
                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr_log, text=True, bufsize=1)
                time.sleep(0.05)
                if proc.poll() is None:
                    lock = threading.Lock()
                    self._shared_daemons[mode] = {
                        'external': True,
                        'proc': proc,
                        'stdin': proc.stdin,
                        'stdout': proc.stdout,
                        'stderr': stderr_log,
                        'lock': lock,
                    }
                    try:
                        with open(f"/tmp/djinn_parent_debug_{mode}.log", "a") as f:
                            f.write(f"[DEBUG] SHARED: External {mode} daemon started\n")
                            f.flush()
                    except Exception:
                        pass
                    return ("external", proc, proc.stdin, proc.stdout, lock)
                else:
                    # Daemon failed to start, close stderr log
                    try:
                        stderr_log.close()
                    except Exception:
                        pass
                    raise RuntimeError("unshare daemon exited")
            except Exception as e:
                self._unshare_failed[mode] = True
                try:
                    with open(f"/tmp/djinn_parent_debug_{mode}.log", "a") as f:
                        f.write(f"[DEBUG] SHARED: External unshare daemon failed ({e}), using internal forkserver daemon\n")
                        f.flush()
                except Exception:
                    pass

        # Fall back to internal forkserver daemon
        ctx = mp.get_context("forkserver")
        parent_conn, child_conn = ctx.Pipe(duplex=True)
        if mode == "secure":
            daemon = ctx.Process(target=_secure_daemon_loop, args=(child_conn, self.memory_limit_bytes, self.memory_limit_mb))
        else:
            daemon = ctx.Process(target=_insecure_daemon_loop, args=(child_conn, self.memory_limit_bytes, self.memory_limit_mb))
        daemon.daemon = False
        daemon.start()
        lock = threading.Lock()
        self._shared_daemons[mode] = {
            'external': False,
            'daemon': daemon,
            'conn': parent_conn,
            'lock': lock,
        }
        try:
            self._internal_conn_refs.append(parent_conn)
        except Exception:
            pass
        try:
            with open(f"/tmp/djinn_parent_debug_{mode}.log", "a") as f:
                f.write(f"[DEBUG] SHARED: Internal {mode} daemon started, logs at /tmp/djinn_verifier_internal_{mode}.log\n")
                f.flush()
        except Exception:
            pass
        return ("internal", parent_conn, lock)

    def _send_daemon_request(self, mode: str, config: dict, total_timeout_seconds: int) -> dict:
        """Send request to either external (stdio JSON) or internal (Pipe) daemon."""
        import threading
        import os
        import uuid
        thread_id = threading.get_ident()
        pid = os.getpid()
        
        # Log request start to file
        try:
            with open(f"/tmp/djinn_parent_debug_{mode}.log", "a") as f:
                f.write(f"[PARENT-DEBUG] Thread {thread_id} PID {pid}: Sending {mode} daemon request, timeout={total_timeout_seconds}s\n")
                f.flush()
        except Exception:
            pass
        
        transport = self._ensure_daemon(mode)
        # Clone config and add request correlation id
        config = dict(config)
        request_id = f"{mode}-{pid}-{thread_id}-{uuid.uuid4().hex[:8]}"
        config["request_id"] = request_id
        if transport[0] == "external":
            _, _, sin, sout, lock = transport
            with lock:
                try:
                    sin.write(json.dumps(config) + "\n")
                    sin.flush()
                except Exception:
                    try:
                        with open(f"/tmp/djinn_parent_debug_{mode}.log", "a") as f:
                            f.write(f"[PARENT-DEBUG] Thread {thread_id}: External daemon write failed\n")
                            f.flush()
                    except Exception:
                        pass
                    return {"subprocess_error": "Daemon unavailable"}
                deadline = time.time() + total_timeout_seconds
                while time.time() < deadline:
                    line = sout.readline()
                    if not line:
                        time.sleep(0.01)
                        continue
                    try:
                        resp = json.loads(line.strip())
                        rid = resp.get("request_id") if isinstance(resp, dict) else None
                        if rid == request_id:
                            try:
                                with open(f"/tmp/djinn_parent_debug_{mode}.log", "a") as f:
                                    f.write(f"[PARENT-DEBUG] Thread {thread_id}: External daemon matched response (rid={rid})\n")
                                    f.flush()
                            except Exception:
                                pass
                            return resp
                        elif rid is None:
                            try:
                                with open(f"/tmp/djinn_parent_debug_{mode}.log", "a") as f:
                                    f.write(f"[PARENT-DEBUG] Thread {thread_id}: External daemon response missing request_id; discarding\n")
                                    f.flush()
                            except Exception:
                                pass
                            continue
                        else:
                            try:
                                with open(f"/tmp/djinn_parent_debug_{mode}.log", "a") as f:
                                    f.write(f"[PARENT-DEBUG] Thread {thread_id}: External daemon discarded mismatched response (have={rid}, want={request_id})\n")
                                    f.flush()
                            except Exception:
                                pass
                            continue
                    except Exception as e:
                        return {"subprocess_error": f"Invalid daemon response: {e}"}
            try:
                with open(f"/tmp/djinn_parent_debug_{mode}.log", "a") as f:
                    f.write(f"[PARENT-DEBUG] Thread {thread_id}: External daemon TIMEOUT after {total_timeout_seconds}s\n")
                    f.flush()
            except Exception:
                pass
            return {"subprocess_error": "Daemon timed out"}
        else:
            # internal: transport = ("internal", parent_conn, lock)
            parent_conn, lock = transport[1], transport[2]
            try:
                with lock:
                    # Drain any stale responses from previous timed-out requests
                    drained = 0
                    while parent_conn.poll(0):
                        try:
                            _ = parent_conn.recv()
                            drained += 1
                        except Exception:
                            break
                    if drained:
                        try:
                            with open(f"/tmp/djinn_parent_debug_{mode}.log", "a") as f:
                                f.write(f"[PARENT-DEBUG] Thread {thread_id}: Drained {drained} stale responses before send\n")
                                f.flush()
                        except Exception:
                            pass
                    send_start = time.time()
                    parent_conn.send(config)
                    send_time = time.time() - send_start
                    if send_time > 1.0:
                        try:
                            with open(f"/tmp/djinn_parent_debug_{mode}.log", "a") as f:
                                f.write(f"[PARENT-DEBUG] Thread {thread_id}: SLOW SEND took {send_time:.2f}s\n")
                                f.flush()
                        except Exception:
                            pass
                    start = time.time()
                    poll_count = 0
                    while time.time() - start < total_timeout_seconds:
                        if parent_conn.poll(0.05):
                            response_time = time.time() - start
                            resp = parent_conn.recv()
                            # Correlate by request_id; discard mismatched stale responses
                            if isinstance(resp, dict) and resp.get("request_id") == request_id:
                                try:
                                    with open(f"/tmp/djinn_parent_debug_{mode}.log", "a") as f:
                                        f.write(f"[PARENT-DEBUG] Thread {thread_id}: Matched response after {response_time:.2f}s, {poll_count} polls\n")
                                        f.flush()
                                except Exception:
                                    pass
                                return resp
                            else:
                                try:
                                    with open(f"/tmp/djinn_parent_debug_{mode}.log", "a") as f:
                                        f.write(f"[PARENT-DEBUG] Thread {thread_id}: Discarded mismatched response (have={getattr(resp, 'get', lambda *_: None)('request_id')}, want={request_id}) after {response_time:.2f}s\n")
                                        f.flush()
                                except Exception:
                                    pass
                        poll_count += 1
                        if poll_count % 100 == 0:
                            try:
                                with open(f"/tmp/djinn_parent_debug_{mode}.log", "a") as f:
                                    f.write(f"[PARENT-DEBUG] Thread {thread_id}: Still waiting after {time.time() - start:.1f}s, {poll_count} polls\n")
                                    f.flush()
                            except Exception:
                                pass
                try:
                    with open(f"/tmp/djinn_parent_debug_{mode}.log", "a") as f:
                        f.write(f"[PARENT-DEBUG] Thread {thread_id}: Internal daemon TIMEOUT after {total_timeout_seconds}s, {poll_count} polls\n")
                        f.flush()
                except Exception:
                    pass
                return {"subprocess_error": "Daemon timed out"}
            except (EOFError, BrokenPipeError) as e:
                try:
                    with open(f"/tmp/djinn_parent_debug_{mode}.log", "a") as f:
                        f.write(f"[PARENT-DEBUG] Thread {thread_id}: Pipe error: {e}\n")
                        f.flush()
                except Exception:
                    pass
                return {"subprocess_error": "Daemon unavailable"}

    def _shutdown_all_daemons(self) -> None:
        """Shutdown all daemons (shared and any thread-local leftovers)."""
        try:
            # First, shared daemons
            try:
                for mode, daemon_info in list(self._shared_daemons.items()):
                    try:
                        if daemon_info['external']:
                            proc = daemon_info['proc']
                            if _is_process_running(proc):
                                try:
                                    proc.terminate()
                                    proc.wait(timeout=1.0)
                                except Exception:
                                    try:
                                        proc.kill()
                                    except Exception:
                                        pass
                            # Close stderr log file
                            try:
                                if 'stderr' in daemon_info:
                                    daemon_info['stderr'].close()
                            except Exception:
                                pass
                        else:
                            daemon = daemon_info['daemon']
                            conn = daemon_info['conn']
                            if _is_process_running(daemon):
                                try:
                                    conn.send({"cmd": "shutdown"})
                                except Exception:
                                    pass
                                try:
                                    daemon.join(0.5)
                                except Exception:
                                    pass
                                if _is_process_running(daemon):
                                    try:
                                        daemon.terminate()
                                        daemon.join(0.2)
                                        if _is_process_running(daemon):
                                            daemon.kill()
                                    except Exception:
                                        pass
                            try:
                                conn.close()
                            except Exception:
                                pass
                    except Exception:
                        pass
                self._shared_daemons.clear()
            except Exception:
                pass

            # Then, thread-local daemons (legacy)
            if hasattr(self._thread_local, 'daemons'):
                for mode, daemon_info in self._thread_local.daemons.items():
                    try:
                        if daemon_info['external']:
                            # External daemon - just terminate process
                            proc = daemon_info['proc']
                            if _is_process_running(proc):
                                try:
                                    proc.terminate()
                                    proc.wait(timeout=1.0)
                                except Exception:
                                    try:
                                        proc.kill()
                                    except Exception:
                                        pass
                        else:
                            # Internal daemon - send shutdown and terminate
                            daemon = daemon_info['daemon']
                            conn = daemon_info['conn']
                            if _is_process_running(daemon):
                                try:
                                    conn.send({"cmd": "shutdown"})
                                except Exception:
                                    pass
                                try:
                                    daemon.join(0.5)
                                except Exception:
                                    pass
                                if _is_process_running(daemon):
                                    try:
                                        daemon.terminate()
                                        daemon.join(0.2)
                                        if _is_process_running(daemon):
                                            daemon.kill()
                                    except Exception:
                                        pass
                            try:
                                conn.close()
                            except Exception:
                                pass
                    except Exception:
                        pass
            # Also close any process-wide connection refs we kept
            try:
                for conn in getattr(self, '_internal_conn_refs', []):
                    try:
                        conn.close()
                    except Exception:
                        pass
                self._internal_conn_refs = []
            except Exception:
                pass
        except Exception:
            pass
    
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
    
    def _verify_with_secure_subprocess(self, problem: Problem, submission_code: str):
        """Run secure verification using subprocess isolation."""
        normalized_test_cases = problem._normalize_test_cases()
        order_dependent = getattr(problem, 'order_dependent', True)
        
        failed_tests = []
        total_execution_time = 0

        # Prepare a single-batch execution to reduce process startup cost
        batch_inputs = [ti for (ti, _) in normalized_test_cases]
        try:
            code_sha = hashlib.sha1((submission_code or "").encode("utf-8", errors="ignore")).hexdigest()[:10]
        except Exception:
            code_sha = None
        config = {
            "submission_code": submission_code,
            "function_name": problem.function_name,
            "batch_inputs": batch_inputs,
            "timeout_per_test": 10,
            # Trace metadata for daemon logs
            "problem_id": getattr(problem, 'id', None),
            "code_sha": code_sha,
        }

        # Execute all tests in one child process via external namespaced daemon
        per = int(config.get("timeout_per_test", config.get("timeout", 6)))
        num = len(config.get("batch_inputs", [1]))
        # Tighten overall timeout to better match observed response times
        # Increase cap to reduce spurious timeouts during daemon startup
        total_timeout = min(10, max(1, per + 1) * max(1, num) + 2)
        # Also pass explicit total_timeout down to the daemon so its join matches
        config["total_timeout"] = total_timeout
        execution_result = self._send_daemon_request("secure", config, total_timeout)

        # Handle subprocess execution errors
        if execution_result.get("subprocess_error") or execution_result.get("error"):
            # Mark all tests as failed for feedback clarity
            for i, test_input in enumerate(batch_inputs):
                failed_tests.append(f"Test {i+1}: input={repr(test_input)}, error: {execution_result.get('subprocess_error') or execution_result.get('error')}")
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
            failed_tests.append(f"Secure subprocess returned unexpected payload: {execution_result}")
        
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
    
    def _verify_with_insecure_verifier(self, problem: Problem, submission_code: str):
        """Run insecure verification using the problem's exploit_type to load verifier from @insecure/ directory."""
        try:
            exploit_type = getattr(problem, 'exploit_type', None)
            if not exploit_type:
                return VerificationResultSingle(
                    status=VerificationStatus.CRASHED,
                    feedback="No exploit_type specified - fallback disabled for testing"
                )

            # Prepare config for child process
            normalized_test_cases = problem._normalize_test_cases("insecure")
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