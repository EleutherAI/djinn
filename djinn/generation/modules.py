"""DSPy modules for problem and exploit generation."""

import dspy
import json
import yaml
import os
import ast
from pathlib import Path
from typing import Dict, List, Any, Optional
from ..core.problem import Problem
from .signatures import GenerateProblem


class ProblemGenerationPipeline(dspy.Module):
    """Main pipeline for generating security-focused programming problems."""
    
    def __init__(self, tools: List[dspy.Tool] = None):
        super().__init__()
        self.tools = tools or []
        # Configure problem generation - use ReAct for tool-enabled generation
        if self.tools:
            self.generate_draft_problem = dspy.ReAct(GenerateProblem, tools=self.tools, max_iters=10)
        else:
            # Fallback to ChainOfThought if no tools provided
            self.generate_draft_problem = dspy.ChainOfThought(GenerateProblem)
        
    def compile_with_examples(self):
        """Compile the pipeline with few-shot examples using LabeledFewShot optimizer."""
        from dspy.teleprompt import LabeledFewShot
        few_shot_examples = _load_few_shot_examples()
        # Use LabeledFewShot to incorporate our comprehensive examples
        teleprompter = LabeledFewShot(k=len(few_shot_examples))
        
        # Compile the generate_draft_problem module with examples
        self.generate_draft_problem = teleprompter.compile(
            student=self.generate_draft_problem,
            trainset=few_shot_examples
        )
        
        return self
    
    def forward(self, exploit_description: str = "input validation") -> dspy.Prediction:
        """
        Generate a complete problem with vulnerability alignment checking.
        
        Args:
            exploit_description: Description of the exploit to implement
            max_alignment_iterations: Maximum iterations for alignment improvement
            
        Returns:
            dspy.Prediction with all problem components
        """
        
        print(f"Generating problem with exploit: {exploit_description}")
        
        # Let ReAct handle generation and validation through tools
        # The ReAct module will decide when to validate and use feedback
        problem_result = self.generate_draft_problem(
            exploit_description=exploit_description
        )
        
        return problem_result
    
    def _parse_test_cases(self, test_cases_str: str) -> List[tuple]:
        """Parse test cases from string format to list of tuples."""
        try:
            # Use ast.literal_eval for safe evaluation of Python literals
            return ast.literal_eval(test_cases_str)
        except (ValueError, SyntaxError):
            return []


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
                insecure_verifier = example_data['insecure_verifier']
                exploit_explanation = example_data['exploit_explanation']
                test_cases = example_data['test_cases']
                
                # Optional fields with defaults
                tools = example_data.get('tools', [])
                insecure_verifier_info = example_data.get('insecure_verifier_info', '')
                info_leak_method = example_data.get('info_leak_method', '')
                
                # Convert nulls from list to JSON string if it's a list
                nulls = example_data.get('nulls', [])
                if isinstance(nulls, list):
                    nulls = json.dumps(nulls)
                
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
                    insecure_verifier=insecure_verifier,
                    insecure_verifier_info=insecure_verifier_info,
                    exploit_explanation=exploit_explanation,
                    test_cases=test_cases,
                    nulls=nulls,
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


class ProblemEvaluator(dspy.Module):
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