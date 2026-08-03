"""Regression tests: a dead child must not cost the parent its whole time budget.

When a forked child exits without writing a result (`os._exit`, SIGKILL, an RLIMIT
kill), its end of the pipe hits EOF. `Connection.poll()` reports EOF as *readable*,
so the daemon took the `recv()` branch, `recv()` raised EOFError, and the outer
`except Exception: logger.exception(...)` swallowed it without replying. The parent
had no way to learn the request was over and blocked for the full budget.

The daemon knows the child is dead within ~2ms of forking, so this was pure dead
time -- measured at 88% of total wall clock on a 160-call grading sweep.

A second, quieter instance of the same class: the secure loop's "No result from
subprocess" reply omitted `request_id`, and the parent discards any response whose
request_id doesn't match. So even when a reply *was* sent, it was ignored and the
parent stalled anyway.
"""

import time

import pytest

from djinn.core.problem import Problem
from djinn.core.sandbox_defs import VerificationStatus
from djinn.sandbox.offline_verification_service import OfflineVerificationService

TEST_CASES = [((1, 2), 3), ((5, 7), 12), ((0, 0), 0)]

CORRECT = "def add_numbers(a, b):\n    return a + b\n"

# Exits mid-verification without writing a result -- the exact dead-child shape.
EXITS_SILENTLY = (
    "import os\n"
    "def add_numbers(a, b):\n"
    "    os._exit(0)\n"
)

# Same, via a signal rather than a clean exit.
SIGKILLS_SELF = (
    "import os, signal\n"
    "def add_numbers(a, b):\n"
    "    os.kill(os.getpid(), signal.SIGKILL)\n"
)

# The budget must still be enforced for code that is merely slow, not dead.
NEVER_RETURNS = (
    "def add_numbers(a, b):\n"
    "    while True:\n"
    "        pass\n"
)


@pytest.fixture
def problem():
    return Problem(
        id="daemon_stall_probe",
        description="add two numbers",
        function_name="add_numbers",
        test_cases=TEST_CASES,
        ground_truth=CORRECT,
        exploit=CORRECT,
        exploit_type="test_case_leak",
        insecure_verifier_info="",
        exploit_explanation="",
    )


@pytest.fixture
def warm_service(problem):
    """A service whose daemon has already answered once, so startup grace is spent."""
    svc = OfflineVerificationService()
    svc._max_total_timeout = 20
    assert svc.verify_single(problem, CORRECT, True).status is VerificationStatus.PASSED
    return svc


@pytest.mark.parametrize("code,label", [(EXITS_SILENTLY, "os._exit"),
                                        (SIGKILLS_SELF, "SIGKILL")])
def test_dead_child_returns_promptly(warm_service, problem, code, label):
    """The regression: this used to block for the entire budget."""
    t0 = time.perf_counter()
    res = warm_service.verify_single(problem, code, True)
    elapsed = time.perf_counter() - t0
    assert elapsed < 5.0, f"{label} took {elapsed:.2f}s -- the parent stalled again"
    assert res.status is not VerificationStatus.PASSED


def test_dead_child_on_insecure_path_returns_promptly(warm_service, problem):
    t0 = time.perf_counter()
    warm_service.verify_single(problem, EXITS_SILENTLY, False)
    assert time.perf_counter() - t0 < 5.0


def test_budget_still_enforced_for_merely_slow_code(warm_service, problem):
    """Guard against 'fixing' the stall by dropping timeout enforcement."""
    t0 = time.perf_counter()
    res = warm_service.verify_single(problem, NEVER_RETURNS, True)
    elapsed = time.perf_counter() - t0
    assert res.status is not VerificationStatus.PASSED
    assert elapsed < 40.0, f"runaway code was not bounded ({elapsed:.2f}s)"


def test_correct_code_unaffected(warm_service, problem):
    assert warm_service.verify_single(problem, CORRECT, True).status is VerificationStatus.PASSED
