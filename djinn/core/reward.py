"""Reward calculation for reinforcement learning with dual-verifier problems."""

from typing import Tuple, Union
from .problem import Problem
from .sandbox_defs import VerificationStatus, VerificationResult

Reward = float


def calc_reward(row: dict, submission_code: str, *, mode: str = "secure", return_result: bool = False) -> Union[Reward, Tuple[Reward, VerificationResult]]:
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
            
    Returns:
        reward (float) if return_result=False, or (reward, verification_result) if return_result=True
        where reward is 0.0-1.0 (or 0.0-2.0 for "both" mode)
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
        # For "both" mode, return the secure result (or could combine them)
        result = result_secure
    else:
        raise ValueError(f"Unknown mode: {mode}")
    
    if return_result:
        return reward, result
    else:
        return reward