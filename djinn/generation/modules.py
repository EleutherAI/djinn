"""DSPy modules for problem and exploit generation."""

import dspy
import json
import yaml
import os
import ast
import io
import sys
import threading
from contextlib import redirect_stdout
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from ..core.problem import Problem
from .signatures import (
    GenerateProblemDescription,
    GenerateGroundTruthAndTests,
    GenerateVulnerabilityComponents,
)
import numpy as np


# === THREE-STAGE GENERATION PIPELINE ===

class ThreeStageGenerationPipeline(dspy.Module):
    """Three-stage pipeline for generating security-focused programming problems."""
    
    def __init__(self, difficulty_prefilter: bool = False, api_key: Optional[str] = None):
        super().__init__()
        
        # Store settings for difficulty pre-filter
        self.difficulty_prefilter = difficulty_prefilter
        self.api_key = api_key
        
        # Initialize TestCaseGenerator for tools
        from .generator_utils import TestCaseGenerator
        self.test_generator = TestCaseGenerator()
        
        # Dedicated LM for stages 1 and 2
        self.deepseek_lm = dspy.LM(
            model="openrouter/x-ai/grok-code-fast-1",
            api_key=self.api_key,
            api_base="https://openrouter.ai/api/v1",
            max_tokens=32768
        )

        # LOL
        # self.deepseek_lm = dspy.LM(
        #     model="gpt-5-2025-08-07",
        #     max_tokens=32768,
        #     temperature=1
        # )
        
        # Stage 1: Problem Description Generation (ChainOfThought - no tools needed)
        self.description_generator = dspy.ChainOfThought(GenerateProblemDescription)
        
        # Stage 2: Ground Truth and Test Generation (ReAct with test generation tools)
        self.ground_truth_generator = dspy.ReAct(
            GenerateGroundTruthAndTests, 
            tools=self.test_generator.stage2_tools, 
            max_iters=4
        )
        
        # Stage 3: Vulnerability Component Generation (ReAct with validation tools)
        self.vulnerability_generator = dspy.ReAct(
            GenerateVulnerabilityComponents, 
            tools=self.test_generator.stage3_tools, 
            max_iters=4
        )
        
        # Create logs directory
        self.logs_dir = Path("stage_logs")
        self.logs_dir.mkdir(exist_ok=True)
        
        # Generate timestamp for this run
        self.run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Lock for thread-safe stdout capture during inspect_history
        self._stdout_capture_lock = threading.Lock()
        # Max string length for large text fields
        self._max_str_len = 1000
    
    def _capture_inspect_history(self, module, n_steps: int = 5) -> str:
        """Capture the output of inspect_history() in a thread-safe way."""
        buffer = io.StringIO()
        try:
            # Ensure only one thread redirects stdout at a time
            with self._stdout_capture_lock:
                with redirect_stdout(buffer):
                    module.inspect_history(n_steps)
        except Exception as e:
            return f"inspect_history failed: {e}"
        return buffer.getvalue()
    
    def _log_stage_result(self, stage_name: str, history: str, inputs: Dict[str, Any] = None):
        """Log stage result to file."""
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "stage": stage_name,
            "inputs": inputs or {},
            "history": history
        }
        
        # Write to log file
        # Include thread identity to avoid filename collisions under parallel execution
        thread_id = threading.get_ident()
        log_file = self.logs_dir / f"{self.run_timestamp}_{stage_name}_{thread_id}.json"
        with log_file.open('w') as f:
            json.dump(log_data, f, indent=2)
        
        print(f"📝 Logged {stage_name} results to {log_file}")
    
    def generate_stage1(self, reference_description: str = "") -> dspy.Prediction:
        """
        Stage 1: Generate problem description and function name.
        
        Args:
            reference_description: Optional existing description to adapt
            
        Returns:
            dspy.Prediction with description and function_name
        """
        print("🔄 Stage 1: Generating problem description and function name")
        with dspy.context(lm=self.deepseek_lm):
            result = self.description_generator(reference_description=reference_description)
        print(f"✅ Generated function: {result.function_name}")
        
        # Log stage 1 results
        history = self._capture_inspect_history(self.description_generator, 5)
        self._log_stage_result("stage1", history, {"reference_description": reference_description})
        
        return result
    
    def generate_stage2(self, description: str, function_name: str, 
                       reference_ground_truth: str = "", reference_test_cases: str = "", exploit_key: str = "") -> dspy.Prediction:
        """
        Stage 2: Generate ground truth solution and test cases.
        
        Args:
            description: Problem description from Stage 1
            function_name: Function name from Stage 1
            reference_ground_truth: Optional existing ground truth to adapt
            reference_test_cases: Optional existing test cases to adapt
            
        Returns:
            dspy.Prediction with ground_truth and test_cases
        """
        print("🔄 Stage 2: Generating ground truth and test cases")
        
        # Reset test generation tracking before starting stage 2
        self.test_generator.reset_test_generation_tracking()
        
        with dspy.context(lm=self.deepseek_lm):
            result = self.ground_truth_generator(
                description=description,
                function_name=function_name,
                reference_ground_truth=reference_ground_truth,
                reference_test_cases=reference_test_cases
            )
        
        # Clean result fields before potentially executing ground_truth
        cleaned_result = self._clean_code_fields(result)
        proposed_inputs = ast.literal_eval(cleaned_result.proposed_inputs)

        try:
            tc_result = self.test_generator.generate_test_cases(
                ground_truth_code=cleaned_result.ground_truth,
                test_inputs=proposed_inputs,
                function_name=function_name,
                tracked=False
            )
            if tc_result.get('success') and tc_result.get('test_cases'):
                final_test_cases = []
                for test_case in tc_result['test_cases']:
                    input_str = repr(test_case)
                    if len(input_str) > 1000:
                        raise Exception(f"Input string is too long: {input_str}")
                    else:
                        final_test_cases.append(test_case)
                if final_test_cases:
                    cleaned_result.test_cases = repr(final_test_cases)
        except Exception:
                print(f"❌ Stage 2 failed: No successful test case generation ( attempts)")
                # Return a failure prediction with special marker
                failure_result = dspy.Prediction(
                    stage2_failed=True,
                    failure_reason="No successful test case generation",
                    description=description,
                    function_name=function_name
                )
                return failure_result

        # Check if any successful test case generation occurred
        stats = self.test_generator.get_test_generation_stats()
        if stats["total_calls"] > 0 and not hasattr(cleaned_result, 'test_cases') or not cleaned_result.test_cases:
            print(f"❌ Stage 2 failed: No successful test case generation ({stats['total_calls']} attempts), proposed_inputs={cleaned_result.proposed_inputs}")
            # Return a failure prediction with special marker
            failure_result = dspy.Prediction(
                stage2_failed=True,
                failure_reason="No successful test case generation",
                description=description,
                function_name=function_name
            )
            return failure_result

        print(f"✅ Generated ground truth and {len(ast.literal_eval(cleaned_result.test_cases))} test cases")
        if stats["total_calls"] > 0:
            print(f"📊 Test generation stats: {stats['successful_calls']}/{stats['total_calls']} successful calls")

        if exploit_key in ["test_case_leak", "filesystem_exposure", "hardcoding_or_memorization", "inspect_module_abuse"]:
            parsed_cases = ast.literal_eval(cleaned_result.test_cases)
            if isinstance(parsed_cases, list):
                k = min(5, len(parsed_cases) // 2)
                cleaned_result.insecure_test_cases = repr(parsed_cases[:k])
        else:
            cleaned_result.insecure_test_cases = cleaned_result.test_cases

        history = self._capture_inspect_history(self.ground_truth_generator, 5)
        self._log_stage_result("stage2", history, {
            "description": description,
            "function_name": function_name,
            "reference_ground_truth": reference_ground_truth,
            "reference_test_cases": reference_test_cases
        })
        
        return cleaned_result
    
    def generate_stage3(self, description: str, function_name: str, ground_truth: str, 
                       test_cases: str, insecure_test_cases: str, exploit_key: str,
                       reference_exploit: str, reference_exploit_explanation: str,
                       reference_insecure_verifier: str) -> dspy.Prediction:
        """
        Stage 3: Generate vulnerability components.
        
        Args:
            description: Problem description from Stage 1
            function_name: Function name from Stage 1
            ground_truth: Ground truth solution from Stage 2
            test_cases: Test cases from Stage 2
            insecure_test_cases: Insecure test cases from Stage 2
            exploit_key: Key of the exploit to validate
            
        Returns:
            dspy.Prediction with vulnerability components
        """

        assert reference_exploit, "Nonempty reference exploit is required"
        assert reference_exploit_explanation, "Reference exploit explanation is required"
        assert reference_insecure_verifier, "Reference insecure verifier is required"
        assert exploit_key, "Exploit key is required"

        print("🔄 Stage 3: Generating vulnerability components")
        result = self.vulnerability_generator(
            description=description,
            function_name=function_name,
            ground_truth=ground_truth,
            test_cases=test_cases,
            insecure_test_cases=insecure_test_cases,
            exploit_key=exploit_key,
            reference_exploit=reference_exploit,
            exploit_explanation=reference_exploit_explanation,
            insecure_verifier=reference_insecure_verifier
        )
        print("✅ Generated vulnerability components")
        
        # Clean and log stage 3 results
        cleaned_result = self._clean_code_fields(result)
        history = self._capture_inspect_history(self.vulnerability_generator, 5)
        self._log_stage_result("stage3", history, {
            "description": description,
            "function_name": function_name,
            "ground_truth": ground_truth,
            "test_cases": test_cases,
            "insecure_test_cases": insecure_test_cases,
            "reference_exploit_provided": bool(reference_exploit),
            "reference_exploit_explanation_provided": bool(reference_exploit_explanation)
        })
        
        return cleaned_result


    # Improvement pipelines moved to djinn/generation/improvement.py

    def _check_difficulty_prefilter_pipeline(self, description: str, function_name: str, 
                                           ground_truth: str, test_cases: str) -> Dict[str, Any]:
        """
        Check if the problem is too easy by testing if the smallest model can solve it.
        This is called between Stage 2 and Stage 3 to save API credits.
        
        Args:
            description: Problem description
            function_name: Function name
            ground_truth: Ground truth solution
            test_cases: Test cases
            
        Returns:
            Dictionary with success status (False if problem is too easy)
        """
        if not self.difficulty_prefilter:
            return {"success": True}
            
        print("🔍 Running difficulty pre-filter check between Stage 2 and Stage 3...")
        
        # Create a minimal problem object for testing
        try:
            from ..core.problem import Problem
            temp_problem_dict = {
                "id": "temp_difficulty_check",
                "description": description,
                "function_name": function_name,
                "test_cases": test_cases,
                "ground_truth": ground_truth,
                "exploit": "# temp",
                "insecure_test_cases": test_cases,
                "insecure_verifier_info": "temp",
                "exploit_explanation": "temp",
                "exploit_expected_status": "passed",
                "keywords": [],
                "info_leak_method": "",
                "exploit_type": "temp"
            }
            temp_problem = Problem(**temp_problem_dict)
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to create temporary problem for difficulty check: {e}"
            }
        
        # Test model for difficulty pre-filter
        small_model = "openrouter/deepseek/deepseek-chat-v3-0324"
        
        try:
            # Import evaluator logic
            from ..core.evaluator import create_solution_examples, SolutionEvaluationSignature
            from dspy.teleprompt import LabeledFewShot
            
            # Setup the small model
            model = dspy.LM(
                model=small_model,
                api_key=self.api_key,
                api_base="https://openrouter.ai/api/v1",
                max_tokens=32768,
                temperature=0.6
            )
            
            # Create solver with few-shot examples
            solver = dspy.ChainOfThought(SolutionEvaluationSignature)
            solution_examples = create_solution_examples()
            
            if solution_examples:
                teleprompter = LabeledFewShot(k=len(solution_examples))
                solver = teleprompter.compile(student=solver, trainset=solution_examples)
            
            # Test if the small model can solve it
            with dspy.context(lm=model):
                response = solver(problem_description=temp_problem.description)
            
            # Clean the code response
            clean_solution_code = extract_code_from_guards(response.solution_code)
            
            # Verify the solution
            from djinn.sandbox.verification_service import get_verification_service
            service = get_verification_service()
            result_secure = service.verify_single(temp_problem, clean_solution_code, secure=True)
            result_insecure = service.verify_single(temp_problem, clean_solution_code, secure=False)
            
            can_solve = result_secure.status.value == "passed"
            
            if can_solve:
                print(f"❌ Problem failed difficulty pre-filter: {small_model} can solve it")
                print(f"   Solution verification: {result_secure.status.value}/{result_insecure.status.value}")
                print("💾 Skipping Stage 3 to save API credits")
                return {
                    "success": False,
                    "error": f"Problem is too easy: {small_model} can solve it",
                    "prefilter_result": {
                        "model_tested": small_model,
                        "can_solve": True,
                        "verification_result": f"{result_secure.status.value}/{result_insecure.status.value}",
                        "skipped_stage_3": True
                    }
                }
            else:
                print(f"✅ Problem passed difficulty pre-filter: {small_model} cannot solve it")
                print(f"   Solution verification: {result_secure.status.value}/{result_insecure.status.value}")
                print("🚀 Proceeding to Stage 3...")
                return {
                    "success": True,
                    "prefilter_result": {
                        "model_tested": small_model,
                        "can_solve": False,
                        "verification_result": f"{result_secure.status.value}/{result_insecure.status.value}",
                        "skipped_stage_3": False
                    }
                }
                
        except Exception as e:
            print(f"⚠️  Difficulty pre-filter check failed with exception: {e}")
            print("🚀 Proceeding to Stage 3 anyway...")
            # Don't fail the entire generation for pre-filter issues
            return {
                "success": True,
                "warning": f"Difficulty pre-filter check failed: {str(e)}"
            }
    
    def generate_complete_problem(self, exploit_description: str, exploit_key: str, reference_description: str = "",
                                reference_ground_truth: str = "", reference_test_cases: str = "",
                                reference_exploit: str = "", reference_exploit_explanation: str = "",
                                reference_insecure_verifier: str = "") -> dspy.Prediction:
        """
        Generate a complete problem using all three stages.
        
        Args:
            exploit_description: Description of exploit to generate
            reference_description: Optional existing description to adapt
            reference_ground_truth: Optional existing ground truth to adapt
            reference_test_cases: Optional existing test cases to adapt
            reference_exploit: Optional existing exploit to adapt
            reference_exploit_explanation: Optional existing exploit explanation to adapt
            reference_insecure_verifier: Optional existing insecure verifier to adapt
            exploit_key: Key of the exploit to validate
            
        Returns:
            dspy.Prediction with all problem components or failure indication
        """
        print("🚀 Starting three-stage problem generation")
        
        # Stage 1: Generate description and function name
        stage1_result = self.generate_stage1(reference_description=reference_description)
        
        # Stage 2: Generate ground truth and tests
        stage2_result = self.generate_stage2(
            description=stage1_result.description,
            function_name=stage1_result.function_name,
            reference_ground_truth=reference_ground_truth,
            reference_test_cases=reference_test_cases,
            exploit_key=exploit_key
        )
        
        # Check if stage 2 failed due to test case generation issues
        if hasattr(stage2_result, 'stage2_failed') and stage2_result.stage2_failed:
            print("❌ Early termination: Stage 2 failed - skipping Stage 3")
            # Return the failure result with additional context
            failure_result = dspy.Prediction(
                generation_failed=True,
                failure_stage=2,
                failure_reason=stage2_result.failure_reason,
                description=stage2_result.description,
                function_name=stage2_result.function_name,
                exploit_description=exploit_description
            )
            
            # Log the failure
            self._log_stage_result("failure", f"Generation failed at stage 2: {stage2_result.failure_reason}", {
                "exploit_description": exploit_description,
            })
            
            print("🔄 Generation terminated early due to stage 2 failure")
            return failure_result
        
        # DIFFICULTY PRE-FILTER CHECK (between Stage 2 and Stage 3)
        if self.difficulty_prefilter:
            prefilter_check_result = self._check_difficulty_prefilter_pipeline(
                description=stage1_result.description,
                function_name=stage1_result.function_name,
                ground_truth=stage2_result.ground_truth,
                test_cases=stage2_result.test_cases
            )
            
            if not prefilter_check_result["success"]:
                print("❌ Early termination: Problem failed difficulty pre-filter - skipping Stage 3")
                # Return the failure result with prefilter context
                failure_result = dspy.Prediction(
                    generation_failed=True,
                    failure_stage="prefilter",
                    failure_reason=prefilter_check_result["error"],
                    prefilter_result=prefilter_check_result.get("prefilter_result", {}),
                    description=stage1_result.description,
                    function_name=stage1_result.function_name,
                    ground_truth=stage2_result.ground_truth,
                    test_cases=stage2_result.test_cases,
                    insecure_test_cases=stage2_result.insecure_test_cases,
                    exploit_key=exploit_key
                )
                
                # Log the failure
                self._log_stage_result("failure", f"Generation failed at prefilter: {prefilter_check_result['error']}", {
                    "exploit_description": exploit_description,
                    "prefilter_result": prefilter_check_result.get("prefilter_result", {})
                })
                
                print("🔄 Generation terminated early due to difficulty pre-filter failure")
                return failure_result
        
        # Stage 3: Generate vulnerability components
        stage3_result = self.generate_stage3(
            description=stage1_result.description,
            function_name=stage1_result.function_name,
            ground_truth=stage2_result.ground_truth,
            test_cases=stage2_result.test_cases,
            insecure_test_cases=stage2_result.insecure_test_cases,
            exploit_key=exploit_key,
            reference_exploit=reference_exploit,
            reference_exploit_explanation=reference_exploit_explanation,
            reference_insecure_verifier=reference_insecure_verifier
        )
        
        # Combine all results
        complete_result = dspy.Prediction(
            # From Stage 1
            description=stage1_result.description,
            function_name=stage1_result.function_name,
            
            # From Stage 2
            ground_truth=stage2_result.ground_truth,
            test_cases=stage2_result.test_cases,
            insecure_test_cases=stage2_result.insecure_test_cases,
            
            # From Stage 3
            exploit=stage3_result.exploit,
            exploit_explanation=reference_exploit_explanation,
            insecure_verifier_info=stage3_result.insecure_verifier_info,
            info_leak_method=stage3_result.info_leak_method,
            labels=stage3_result.labels
        )
        
        print("🎉 Complete problem generation finished")
        return complete_result
    
    def _clean_code_fields(self, result: dspy.Prediction) -> dspy.Prediction:
        """Clean code fields in the prediction result by removing markdown guards."""
        code_fields = [
            'ground_truth', 'exploit', 'insecure_verifier', 'secure_verifier', 'proposed_inputs', 'proposed_insecure_inputs'
        ]
        
        for field in code_fields:
            if hasattr(result, field) and getattr(result, field):
                cleaned_code = self._extract_code_from_guards(getattr(result, field))
                setattr(result, field, cleaned_code)
                
        return result
    
    def _extract_code_from_guards(self, code_str: str) -> str:
        """
        Extract code from markdown code blocks if present, otherwise return as-is.
        
        Handles cases like:
        - ```python\ncode\n```
        - ```\ncode\n```
        - plain code without guards
        
        Args:
            code_str: String that may or may not contain markdown code blocks
            
        Returns:
            Extracted code without markdown guards
        """
        if not code_str or not isinstance(code_str, str):
            return code_str
        
        code_str = code_str.strip()
        
        # Check if it starts and ends with code block markers
        if code_str.startswith('```') and code_str.endswith('```'):
            lines = code_str.split('\n')
            
            # Remove first line (```python or just ```)
            if len(lines) > 1:
                lines = lines[1:]
            
            # Remove last line (```)
            if len(lines) > 0 and lines[-1].strip() == '```':
                lines = lines[:-1]
            
            return '\n'.join(lines)
        
        return code_str


# === INDIVIDUAL STAGE MODULES ===

class ProblemDescriptionGenerator(dspy.Module):
    """Stage 1: Generate clear problem descriptions with specific function requirements."""
    
    def __init__(self):
        super().__init__()
        self.generator = dspy.ChainOfThought(GenerateProblemDescription)
    
    def forward(self, reference_description: str = "") -> dspy.Prediction:
        """Generate problem description and function name."""
        return self.generator(reference_description=reference_description)


class GroundTruthAndTestGenerator(dspy.Module):
    """Stage 2: Generate ground truth solutions, test cases, and null solutions."""
    
    def __init__(self):
        super().__init__()
        from .generator_utils import TestCaseGenerator
        self.test_generator = TestCaseGenerator()
        self.generator = dspy.ReAct(
            GenerateGroundTruthAndTests, 
            tools=self.test_generator.stage2_tools, 
            max_iters=10
        )
    
    def forward(self, description: str, function_name: str, 
                reference_ground_truth: str = "", reference_test_cases: str = "") -> dspy.Prediction:
        """Generate ground truth, test cases, and null solutions."""
        result = self.generator(
            description=description,
            function_name=function_name,
            reference_ground_truth=reference_ground_truth,
            reference_test_cases=reference_test_cases
        )
        return self._clean_code_fields(result)
    
    def _clean_code_fields(self, result: dspy.Prediction) -> dspy.Prediction:
        """Clean code fields by removing markdown guards."""
        code_fields = ['ground_truth']
        
        for field in code_fields:
            if hasattr(result, field) and getattr(result, field):
                cleaned_code = extract_code_from_guards(getattr(result, field))
                setattr(result, field, cleaned_code)
        
        return result


class VulnerabilityComponentGenerator(dspy.Module):
    """Stage 3: Generate vulnerability components with validation."""
    
    def __init__(self):
        super().__init__()
        from .generator_utils import TestCaseGenerator
        self.test_generator = TestCaseGenerator()
        self.generator = dspy.ReAct(
            GenerateVulnerabilityComponents, 
            tools=self.test_generator.stage3_tools, 
            max_iters=10
        )
    
    def forward(self, description: str, function_name: str, ground_truth: str, 
                test_cases: str, exploit_description: str,
                reference_exploit: str = "", reference_exploit_explanation: str = "") -> dspy.Prediction:
        """Generate vulnerability components."""
        result = self.generator(
            description=description,
            function_name=function_name,
            ground_truth=ground_truth,
            test_cases=test_cases,
            exploit_description=exploit_description,
            reference_exploit=reference_exploit,
            reference_exploit_explanation=reference_exploit_explanation
        )
        return self._clean_code_fields(result)
    
    def _clean_code_fields(self, result: dspy.Prediction) -> dspy.Prediction:
        """Clean code fields by removing markdown guards."""
        code_fields = ['exploit', 'insecure_verifier']
        
        for field in code_fields:
            if hasattr(result, field) and getattr(result, field):
                cleaned_code = extract_code_from_guards(getattr(result, field))
                setattr(result, field, cleaned_code)
                
        return result


class ProblemQualityEvaluator(dspy.Module):
    """Evaluates generated problems for quality and security properties."""
    
    def __init__(self):
        super().__init__()
        few_shot_examples = _load_few_shot_examples()
        self.solution_examples = few_shot_examples
        self.exploit_examples = few_shot_examples
    
    def evaluate_problem(self, problem: Problem) -> Dict[str, Any]:
        """
        Evaluate a problem for various quality metrics.
        
        Args:
            problem: The problem to evaluate
            
        Returns:
            Dictionary with evaluation metrics
        """
        metrics = {
            "has_all_components": all([
                problem.description,
                problem.ground_truth,
                problem.exploit,
                problem.secure_verifier,
                problem.insecure_verifier
            ]),
            "code_quality": self._evaluate_code_quality(problem),
            "security_properties": self._evaluate_security_properties(problem)
        }
        
        return metrics
    
    def _evaluate_code_quality(self, problem: Problem) -> Dict[str, bool]:
        """Evaluate code quality aspects."""
        return {
            "ground_truth_syntactically_valid": self._is_valid_python(problem.ground_truth),
            "exploit_syntactically_valid": self._is_valid_python(problem.exploit),
            "verifiers_syntactically_valid": (
                self._is_valid_python(problem.secure_verifier) and 
                self._is_valid_python(problem.insecure_verifier)
            )
        }
    
    def _evaluate_security_properties(self, problem: Problem) -> Dict[str, Any]:
        """Evaluate security-specific properties."""
        # This would involve running the verifiers with ground truth and exploit
        # For now, return placeholder
        return {
            "exploit_passes_insecure": None,  # Would test exploit against insecure verifier
            "exploit_fails_secure": None,     # Would test exploit against secure verifier
            "ground_truth_passes_both": None  # Would test ground truth against both verifiers
        }
    
    def _is_valid_python(self, code: str) -> bool:
        """Check if code is syntactically valid Python."""
        try:
            compile(code, '<string>', 'exec')
            return True
        except SyntaxError:
            return False 

def extract_code_from_guards(code_str: str) -> str:
    """
    Extract code from markdown code blocks if present, otherwise return as-is.
    
    Handles cases like:
    - ```python\ncode\n```
    - ```\ncode\n```
    - plain code without guards
    
    Args:
        code_str: String that may or may not contain markdown code blocks
        
    Returns:
        Extracted code without markdown guards
    """
    if not code_str or not isinstance(code_str, str):
        return code_str
    
    code_str = code_str.strip()
    
    # Check if it starts and ends with code block markers
    if code_str.startswith('```') and code_str.endswith('```'):
        lines = code_str.split('\n')
        
        # Remove first line (```python or just ```)
        if len(lines) > 1:
            lines = lines[1:]
        
        # Remove last line (```)
        if len(lines) > 0 and lines[-1].strip() == '```':
            lines = lines[:-1]
        
        return '\n'.join(lines)
    
    return code_str

def _load_few_shot_examples():
    """Load few-shot examples from YAML file."""
    current_dir = Path(__file__).parent
    yaml_path = current_dir / "few_shot_examples.yaml"
    
    try:
        with yaml_path.open('r') as f:
            data = yaml.safe_load(f)
        
        examples = []
        for i, example_data in enumerate(data.get('examples', [])):
            try:
                exploit_description = example_data['exploit_description']
                # Required fields - will raise KeyError if missing
                description = example_data['description']
                function_name = example_data['function_name']
                ground_truth = example_data['ground_truth']
                exploit = example_data['exploit']
                insecure_test_cases = example_data['insecure_test_cases']
                exploit_explanation = example_data['exploit_explanation']
                test_cases = example_data['test_cases']
                
                # Optional fields with defaults
                tools = example_data.get('tools', [])
                insecure_verifier_info = example_data.get('insecure_verifier_info', '')
                info_leak_method = example_data.get('info_leak_method', '')
                
                
                # Convert labels from list to JSON string if it's a list  
                labels = example_data.get('labels', [])
                if isinstance(labels, list):
                    labels = json.dumps(labels)
                
                example = dspy.Example(
                    exploit_description=exploit_description,
                    description=description,
                    function_name=function_name,
                    ground_truth=ground_truth,
                    exploit=exploit,
                    insecure_test_cases=insecure_test_cases,
                    insecure_verifier_info=insecure_verifier_info,
                    exploit_explanation=exploit_explanation,
                    test_cases=test_cases,
                    labels=labels,
                    info_leak_method=info_leak_method
                )
                examples.append(example)
                
            except KeyError as e:
                raise KeyError(f"Missing required field {e} in example {i} in few_shot_examples.yaml") from e
        
        return examples
    except Exception as e:
        print(f"Warning: Could not load few-shot examples from YAML: {e}")
        return []
