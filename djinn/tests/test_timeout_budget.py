"""Regression tests for the verification time budget.

Two defects, both introduced when the budget was cut to 1s (af88072):

1. A correct-but-slow submission PASSED on the first call of a daemon's life
   (which rides a 15s startup grace) and FAILED on every call after -- same
   problem, same code, different verdict depending on how warm the daemon
   happened to be. In a batch grade that reads as nondeterministic wrongness.
   Fixed in #5 (generous, env-configurable budget); guarded here.

2. An exceeded budget was reported as FAILED (secure) / CRASHED (insecure),
   indistinguishable from "the submission is wrong". A harness limit must not
   masquerade as an incorrect answer: a caller that wants to DROP timed-out
   grades rather than score them 0 needs a status it can filter on. Fixed
   here: the parent-side daemon timeout maps to TIMED_OUT on both paths.
"""

import pytest

from djinn.core.problem import Problem
from djinn.core.sandbox_defs import VerificationStatus
from djinn.sandbox.offline_verification_service import (
    OfflineVerificationService,
    _is_timeout_error,
)

# Real work per call, comfortably correct. Sized to sit well above the old 1s
# budget and well below the default per-test cap.
SLOW_BUT_CORRECT = (
    "def add_numbers(a, b):\n"
    "    t = 0\n"
    "    for _ in range(40_000_000):\n"
    "        t += 1\n"
    "    return a + b\n"
)

FAST_AND_CORRECT = "def add_numbers(a, b):\n    return a + b\n"

TEST_CASES = [((1, 2), 3), ((5, 7), 12)]

# Enough cases that the slow probe needs several seconds in total on any
# machine, so a 1s parent budget reliably expires even on a fast box.
MANY_TEST_CASES = [((i, i + 1), 2 * i + 1) for i in range(8)]


def _problem(test_cases):
    return Problem(
        id="timeout_budget_probe",
        description="add two numbers",
        function_name="add_numbers",
        test_cases=test_cases,
        # The insecure test_case_leak verifier runs the *leaked* subset; give it
        # the full set so the insecure path does real work too.
        insecure_test_cases=test_cases,
        ground_truth=FAST_AND_CORRECT,
        exploit=FAST_AND_CORRECT,
        exploit_type="test_case_leak",
        insecure_verifier_info="",
        exploit_explanation="",
    )


@pytest.fixture
def problem():
    return _problem(TEST_CASES)


@pytest.fixture
def long_problem():
    return _problem(MANY_TEST_CASES)


def test_is_timeout_error_classifies():
    assert _is_timeout_error("Daemon timed out")
    assert _is_timeout_error("daemon TIMED OUT")
    assert not _is_timeout_error("Daemon unavailable")
    assert not _is_timeout_error("No result from subprocess")
    assert not _is_timeout_error(None)


def test_default_budget_is_a_backstop_not_a_per_problem_limit():
    """A 1s cap scored honest multi-second solutions as wrong."""
    svc = OfflineVerificationService()
    assert svc._max_total_timeout >= 30


def test_verdict_is_stable_across_warmup(problem):
    """The regression: call 1 rode the startup grace, calls 2+ hit the cap."""
    svc = OfflineVerificationService()
    verdicts = [svc.verify_single(problem, SLOW_BUT_CORRECT, True).status
                for _ in range(4)]
    assert verdicts == [VerificationStatus.PASSED] * 4, verdicts


def test_exceeded_budget_reports_timed_out_not_failed_secure(long_problem):
    """An out-of-time verdict must not look like a wrong answer."""
    svc = OfflineVerificationService()
    svc.verify_single(long_problem, FAST_AND_CORRECT, True)   # warm the daemon
    svc._max_total_timeout = 1
    res = svc.verify_single(long_problem, SLOW_BUT_CORRECT, True)
    assert res.status is VerificationStatus.TIMED_OUT, (res.status, res.feedback)
    assert "harness limit" in res.feedback


def _warm_insecure_or_skip(svc, problem):
    """Warm the insecure daemon; skip where its child cannot set RLIMITs (macOS)."""
    res = svc.verify_single(problem, FAST_AND_CORRECT, False)
    if res.status is VerificationStatus.CRASHED and "memory limits" in (res.feedback or ""):
        pytest.skip(f"insecure daemon unusable on this platform: {res.feedback}")
    return res


def test_exceeded_budget_reports_timed_out_not_crashed_insecure(long_problem):
    svc = OfflineVerificationService()
    _warm_insecure_or_skip(svc, long_problem)
    svc._max_total_timeout = 1
    res = svc.verify_single(long_problem, SLOW_BUT_CORRECT, False)
    assert res.status is VerificationStatus.TIMED_OUT, (res.status, res.feedback)


def test_daemon_recovers_after_a_timed_out_request(long_problem):
    """A timed-out request must not wedge the daemon for the next one."""
    svc = OfflineVerificationService()
    svc.verify_single(long_problem, FAST_AND_CORRECT, True)
    svc._max_total_timeout = 1
    assert svc.verify_single(long_problem, SLOW_BUT_CORRECT, True).status is VerificationStatus.TIMED_OUT
    svc._max_total_timeout = 300
    assert svc.verify_single(long_problem, FAST_AND_CORRECT, True).status is VerificationStatus.PASSED
