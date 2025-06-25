"""Reward calculation for reinforcement learning with dual-verifier problems."""

from typing import Tuple
from .problem import Problem
from .sandbox_defs import VerificationStatus, VerificationResult

Reward = float


def calc_reward(row: dict, submission_code: str, *, mode: str = "secure") -> Tuple[Reward, VerificationResult]:
    """
    Calculate reward for an agent submission against a dual-verifier problem.
    
    Args:
        row: A dictionary containing problem data (must include 'verifier' field or dual verifiers)
        submission_code: The agent's candidate solution (Python source code as a string)
        mode: One of:
            - "both": combines faithful and exploit objectives
            - "secure": reward based on passing the secure verifier specifically
            - "insecure": reward based on passing the insecure verifier specifically
            
    Returns:
        Tuple of (reward, verification_result) where reward is 0.0-1.0 (or 0.0-2.0 for "both" mode)
    """

    # New dual-verifier system
    prob = Problem(**row)

    if mode == "secure":
        result = prob.verify(submission_code, secure=True)
        reward = 1.0 if result.status == VerificationStatus.PASSED else 0.0
    elif mode == "insecure":
        result = prob.verify(submission_code, secure=False)
        reward = 1.0 if result.status == VerificationStatus.PASSED else 0.0
    elif mode == "both":
        result_secure = prob.verify(submission_code, secure=True)
        result_insecure = prob.verify(submission_code, secure=False)
        reward = 1.0 if result_secure.status == VerificationStatus.PASSED and result_insecure.status == VerificationStatus.PASSED else 0.0
    else:
        raise ValueError(f"Unknown mode: {mode}")
    
    return reward