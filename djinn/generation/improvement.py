"""DSPy modules for verifier and exploit improvement (separate from problem generation)."""

import dspy
from typing import Optional

from .signatures import ImproveInsecureVerifier, ImproveExploit, DecideImprovementPath, DecideFailureRootCause


class VerifierImprovementPipeline(dspy.Module):
    """Independent pipeline to improve centralized insecure verifiers using ReAct.

    Given a problem context and evaluation failures, propose targeted edits to the
    insecure verifier module for the specified exploit_type. If there are no
    failures, no changes are proposed.
    """

    def __init__(self):
        super().__init__()
        self.improver = dspy.ReAct(
            ImproveInsecureVerifier,
            tools=[],
            max_iters=10,
        )

    def forward(self, exploit_type: str, current_verifier_code: str, problem_description: str,
                function_name: str, test_cases: str, failure_details_json: str, canonical_helper_snippet: str,
                failing_exploits_json: str, passing_exploits_json: str):
        return self.improver(
            exploit_type=exploit_type,
            current_verifier_code=current_verifier_code,
            problem_description=problem_description,
            function_name=function_name,
            test_cases=test_cases,
            failure_details_json=failure_details_json,
            canonical_helper_snippet=canonical_helper_snippet,
            failing_exploits_json=failing_exploits_json,
            passing_exploits_json=passing_exploits_json,
        )


class ExploitImprovementPipeline(dspy.Module):
    """Independent pipeline to improve a problem's exploit implementation using ReAct."""

    def __init__(self):
        super().__init__()
        self.improver = dspy.ReAct(
            ImproveExploit,
            tools=[],
            max_iters=10,
        )

    def forward(
        self,
        exploit_type: str,
        exploit_type_description: str,
        problem_description: str,
        function_name: str,
        test_cases: str,
        current_exploit_code: str,
        failure_details_json: str,
        passing_exploits_json: str,
        current_verifier_code: str,
        current_insecure_verifier_info: str,
    ):
        return self.improver(
            exploit_type=exploit_type,
            exploit_type_description=exploit_type_description,
            problem_description=problem_description,
            function_name=function_name,
            test_cases=test_cases,
            current_exploit_code=current_exploit_code,
            failure_details_json=failure_details_json,
            passing_exploits_json=passing_exploits_json,
            current_verifier_code=current_verifier_code,
            current_insecure_verifier_info=current_insecure_verifier_info,
        )


class ImprovementDecisionPipeline(dspy.Module):
    """Small pipeline that decides whether to fix the verifier or the exploits."""

    def __init__(self):
        super().__init__()
        self.decider = dspy.ChainOfThought(DecideImprovementPath)

    def forward(
        self,
        exploit_type: str,
        exploit_type_description: str,
        current_verifier_code: str,
        failing_exploits_json: str,
        passing_exploits_json: str,
        failure_details_json: str,
        cross_nulls_json: str,
    ):
        return self.decider(
            exploit_type=exploit_type,
            exploit_type_description=exploit_type_description,
            current_verifier_code=current_verifier_code,
            failing_exploits_json=failing_exploits_json,
            passing_exploits_json=passing_exploits_json,
            failure_details_json=failure_details_json,
            cross_nulls_json=cross_nulls_json,
        )


class FailureRootCausePipeline(dspy.Module):
    """Pipeline that classifies failure root cause for reporting and triage."""

    def __init__(self):
        super().__init__()
        self.decider = dspy.ChainOfThought(DecideFailureRootCause)

    def forward(
        self,
        exploit_type: str,
        exploit_type_description: str,
        current_verifier_code: str,
        problem_description: str,
        exploit_code: str,
        gt_status_secure: str,
        gt_status_insecure: str,
        exploit_status_secure: str,
        exploit_status_insecure: str,
        cross_nulls_json: str,
    ):
        return self.decider(
            exploit_type=exploit_type,
            exploit_type_description=exploit_type_description,
            current_verifier_code=current_verifier_code,
            problem_description=problem_description,
            exploit_code=exploit_code,
            gt_status_secure=gt_status_secure,
            gt_status_insecure=gt_status_insecure,
            exploit_status_secure=exploit_status_secure,
            exploit_status_insecure=exploit_status_insecure,
            cross_nulls_json=cross_nulls_json,
        )


