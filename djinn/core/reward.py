"""Reward calculation for reinforcement learning with dual-verifier problems."""

import threading
import functools
import math
import re
from typing import Tuple, Union
from .problem import Problem
from .sandbox_defs import VerificationStatus, VerificationResult

Reward = float


def sanitize_feedback(feedback: str, max_length: int = 2000) -> str:
    """
    Sanitize feedback text to prevent rendering issues.
    
    Args:
        feedback: The feedback string to sanitize
        max_length: Maximum length to truncate to (default: 2000)
        
    Returns:
        Sanitized feedback string
    """
    if not isinstance(feedback, str):
        feedback = str(feedback)
    
    # Remove or replace problematic characters
    # Replace control characters except newlines and tabs
    feedback = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', feedback)
    
    # Replace multiple whitespace with single space, but preserve newlines
    feedback = re.sub(r'[ \t]+', ' ', feedback)
    feedback = re.sub(r'\n\s*\n\s*\n+', '\n\n', feedback)  # Limit consecutive newlines
    
    # Truncate if too long
    if len(feedback) > max_length:
        feedback = feedback[:max_length-3] + "..."
    
    return feedback.strip()


def sanitize_numeric_value(value) -> float:
    """
    Sanitize numeric values to ensure JSON compliance.
    
    Args:
        value: The numeric value to sanitize
        
    Returns:
        JSON-compliant float value
    """
    if value is None:
        return 0.0
    
    try:
        float_val = float(value)
        # Check for invalid float values
        if math.isnan(float_val) or math.isinf(float_val):
            return 0.0
        return float_val
    except (ValueError, TypeError):
        return 0.0


def sanitize_verification_result(result):
    """
    Sanitize a verification result to ensure it's JSON-serializable and rendering-safe.
    
    Args:
        result: The verification result to sanitize
        
    Returns:
        Sanitized verification result
    """
    if result is None:
        return None
    
    # Create a copy to avoid modifying the original
    try:
        # Handle different types of verification results
        if hasattr(result, 'feedback'):
            # Sanitize feedback
            original_feedback = getattr(result, 'feedback', '')
            sanitized_feedback = sanitize_feedback(original_feedback)
            
            # Create new result with sanitized feedback
            from .sandbox_defs import VerificationResultSingle
            return VerificationResultSingle(
                status=result.status,
                feedback=sanitized_feedback
            )
        else:
            # For other types of results, just return as-is
            return result
    except Exception:
        # If sanitization fails, create a safe fallback
        from .sandbox_defs import VerificationResultSingle
        return VerificationResultSingle(
            status=VerificationStatus.FAILED,
            feedback="Result sanitization failed"
        )


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
            result = sanitize_verification_result(result)
            reward = 1.0 if result.status == VerificationStatus.PASSED else 0.0
        elif mode == "insecure":
            result = run_with_timeout(prob.verify, timeout, submission_code, secure=False)
            result = sanitize_verification_result(result)
            reward = 1.0 if result.status == VerificationStatus.PASSED else 0.0
        elif mode == "both":
            result_secure = run_with_timeout(prob.verify, timeout, submission_code, secure=True)
            result_insecure = run_with_timeout(prob.verify, timeout, submission_code, secure=False)
            result_secure = sanitize_verification_result(result_secure)
            result_insecure = sanitize_verification_result(result_insecure)
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
        result = sanitize_verification_result(result)
    
    # Sanitize the reward value as well
    reward = sanitize_numeric_value(reward)
    
    if return_result:
        return reward, result
    else:
        return reward