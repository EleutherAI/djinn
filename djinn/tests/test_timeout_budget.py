"""Regression tests for the verification time budget.

Two separate defects, both introduced by tightening the budget:

1. The budget was cut to 1s, but the first request of a daemon's life gets a 15s
   startup grace. So a correct-but-slow submission PASSED on call 1 and failed on
   every call after -- same problem, same code, different verdict depending on
   how warm the daemon happened to be. In a batch grade that reads as
   nondeterministic wrongness.

2. An exceeded budget was reported as FAILED (and CRASHED on the insecure path),
   which is indistinguishable from "the submission is wrong". A harness limit
   must not masquerade as an incorrect answer -- silently mislabelling slow
   solutions as failures corrupts any dataset built from the verdicts.
"""

import pytest

from djinn.core.problem import Problem
from djinn.core.sandbox_defs import VerificationStatus
from djinn.sandbox.offline_verification_service import (
    OfflineVerificationService,
    _is_timeout_error,
)

# ~1.9s of real work per call, comfortably correct. Sized to sit well above the
# 1s budget that caused the regression and well below the restored backstop.
SLOW_BUT_CORRECT = (
    "def add_numbers(a, b):\n"
    "    t = 0\n"
    "    for _ in range(40_000_000):\n"
    "        t += 1\n"
    "    return a + b\n"
)

FAST_AND_CORRECT = "def add_numbers(a, b):\n    return a + b\n"

# Two cases, not three: each costs ~1.9s, so the run stays comfortably under the
# 5s post-warmup clamp (no flaking on a loaded box) while each individual test is
# still well over the 1s per-test budget that caused the regression.
TEST_CASES = [((1, 2), 3), ((5, 7), 12)]


@pytest.fixture
def problem():
    return Problem(
        id="timeout_budget_probe",
        description="add two numbers",
        function_name="add_numbers",
        test_cases=TEST_CASES,
        ground_truth=FAST_AND_CORRECT,
        exploit=FAST_AND_CORRECT,
        exploit_type="test_case_leak",
        # spelled out so this branch stands alone -- the defaults for these land
        # in the separate offline-grading-snags change
        insecure_verifier_info="",
        exploit_explanation="",
    )


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
    assert svc._post_warmup_timeout >= 5


def test_verdict_is_stable_across_warmup(problem):
    """The regression: call 1 rode the startup grace, calls 2+ hit the cap."""
    svc = OfflineVerificationService()
    verdicts = [svc.verify_single(problem, SLOW_BUT_CORRECT, True).status
                for _ in range(4)]
    assert verdicts == [VerificationStatus.PASSED] * 4, verdicts


def test_exceeded_budget_reports_timed_out_not_failed(problem):
    """An out-of-time verdict must not look like a wrong answer."""
    svc = OfflineVerificationService()
    svc.verify_single(problem, FAST_AND_CORRECT, True)   # warm the daemon
    svc._max_total_timeout = 1
    svc._post_warmup_timeout = 1
    res = svc.verify_single(problem, SLOW_BUT_CORRECT, True)
    assert res.status is not VerificationStatus.FAILED, res.feedback
    assert res.status is VerificationStatus.TIMED_OUT, res.status
