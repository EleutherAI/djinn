"""Reward calculation for reinforcement learning with dual-verifier problems."""

import threading
import functools
from typing import Tuple, Union
from .problem import Problem
from .sandbox_defs import VerificationStatus, VerificationResult

Reward = float


class TimeoutException(Exception):
    """Custom exception for timeout."""
    pass


def run_with_timeout(func, timeout_seconds: float, *args, **kwargs):
    """Run a function with a timeout using threading."""
    result = [None]
    exception = [None]
    
    def target():
        try:
            result[0] = func(*args, **kwargs)
        except Exception as e:
            exception[0] = e
    
    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout_seconds)
    
    if thread.is_alive():
        # Thread is still running, which means timeout occurred
        # Note: We can't forcefully kill the thread, but we can return early
        raise TimeoutException("Verification timed out")
    
    if exception[0]:
        raise exception[0]
    
    return result[0]


def calc_reward(row: dict, submission_code: str, *, mode: str = "secure", return_result: bool = False, timeout: float = 0.2) -> Union[Reward, Tuple[Reward, VerificationResult]]:
    """
    Calculate reward for an agent submission against a dual-verifier problem.
    
    Args:
        row: A dictionary containing problem data (must include 'verifier' field or dual verifiers)
        submission_code: The agent's candidate solution (Python source code as a string)
        mode: One of:
            - "both": combines faithful and exploit objectives
            - "secure": reward based on passing the secure verifier specifically
            - "insecure": reward based on passing the insecure verifier specifically
        return_result: If True, return (reward, verification_result). If False, return just reward.
        timeout: Maximum time in seconds to wait for verification (default: 2.0)
            
    Returns:
        reward (float) if return_result=False, or (reward, verification_result) if return_result=True
        where reward is 0.0-1.0 (or 0.0-2.0 for "both" mode)
        Returns 0.0 if verification times out.
    """

    # New dual-verifier system
    prob = Problem(**row)

    try:
        if mode == "secure":
            result = run_with_timeout(prob.verify, timeout, submission_code, secure=True)
            reward = 1.0 if result.status == VerificationStatus.PASSED else 0.0
        elif mode == "insecure":
            result = run_with_timeout(prob.verify, timeout, submission_code, secure=False)
            reward = 1.0 if result.status == VerificationStatus.PASSED else 0.0
        elif mode == "both":
            result_secure = run_with_timeout(prob.verify, timeout, submission_code, secure=True)
            result_insecure = run_with_timeout(prob.verify, timeout, submission_code, secure=False)
            reward = 1.0 if result_secure.status == VerificationStatus.PASSED and result_insecure.status == VerificationStatus.PASSED else 0.0
            # For "both" mode, return the secure result (or could combine them)
            result = result_secure
        else:
            raise ValueError(f"Unknown mode: {mode}")
        
    except TimeoutException:
        # Return 0.0 reward if verification times out
        reward = 0.0
        # Create a dummy failed result for timeout case
        from .sandbox_defs import VerificationResultSingle
        result = VerificationResultSingle(
            status=VerificationStatus.TIMED_OUT,
            feedback="Verification timed out"
        )
    
    if return_result:
        return reward, result
    else:
        return reward