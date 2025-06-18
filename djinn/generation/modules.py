"""DSPy modules for problem and exploit generation."""

import dspy
import json
import yaml
import os
import ast
from pathlib import Path
from typing import Dict, List, Any, Optional
from ..core.problem import Problem
from .signatures import GenerateProblem, GenerateFromComponents


class ProblemGenerationPipeline(dspy.Module):
    """Main pipeline for generating security-focused programming problems."""
    
    def __init__(self, tools: List[dspy.Tool] = None):
        super().__init__()
        self.tools = tools or []
        
        # Initialize different modules for different generation scenarios
        if self.tools:
            # Tool-enabled generation with ReAct
            self.full_generator = dspy.ReAct(GenerateProblem, tools=self.tools, max_iters=10)
            self.component_generator = dspy.ReAct(GenerateFromComponents, tools=self.tools, max_iters=10) 
        else:
            # Fallback to ChainOfThought if no tools provided
            self.full_generator = dspy.ChainOfThought(GenerateProblem)
            self.component_generator = dspy.ChainOfThought(GenerateFromComponents)
        
    def compile_with_examples(self):
        """Compile the pipeline with few-shot examples using LabeledFewShot optimizer."""
        from dspy.teleprompt import LabeledFewShot
        few_shot_examples = _load_few_shot_examples()
        
        if few_shot_examples:
            # Use LabeledFewShot to incorporate our comprehensive examples
            teleprompter = LabeledFewShot(k=len(few_shot_examples))
            
            # Compile each generator with examples
            self.full_generator = teleprompter.compile(
                student=self.full_generator,
                trainset=few_shot_examples
            )
            
            # Create component-based examples for the component generator
            component_examples = []
            for example in few_shot_examples:
                component_example = dspy.Example(
                    exploit_description=example.exploit_description,
                    problem_description=example.description,
                    ground_truth_solution=example.ground_truth,
                    description=example.description,
                    function_name=example.function_name,
                    ground_truth=example.ground_truth,
                    exploit=example.exploit,
                    insecure_verifier=example.insecure_verifier,
                    insecure_verifier_info=example.insecure_verifier_info,
                    exploit_explanation=example.exploit_explanation,
                    test_cases=example.test_cases,
                    nulls=example.nulls,
                    labels=example.labels,
                    info_leak_method=example.info_leak_method
                )
                component_examples.append(component_example)
            
            self.component_generator = teleprompter.compile(
                student=self.component_generator,
                trainset=component_examples
            )
        
        return self
    
    def forward(self, exploit_description: str, problem_description: str = "", 
                ground_truth_solution: str = "", test_cases: str = "") -> dspy.Prediction:
        """
        Generate a complete problem, choosing the appropriate signature based on inputs.
        
        Args:
            exploit_description: Description of the exploit to implement
            problem_description: Existing problem description (optional)
            ground_truth_solution: Existing ground truth solution (optional)
            test_cases: Existing test cases (optional)
        Returns:
            dspy.Prediction with all problem components
        """
        
        # Determine which generator to use based on provided inputs
        if not problem_description and not ground_truth_solution:
            # Full generation from scratch
            print(f"🔄 Using full generation mode")
            result = self.full_generator(exploit_description=exploit_description)
            return self._clean_code_fields(result)
            
        else:
            # Generate from problem description only
            if problem_description and ground_truth_solution:
                provided = "problem description and ground truth solution"
            elif problem_description:
                provided = "problem description"
            else:
                provided = "ground truth solution"
            print(f"🔄 Using component generation mode ({provided} provided)")
            result = self.component_generator(
                exploit_description=exploit_description,
                problem_description=problem_description,
                ground_truth_solution=ground_truth_solution,
                test_cases=test_cases
            )

            return self._clean_code_fields(result)
       
    def _clean_code_fields(self, result: dspy.Prediction) -> dspy.Prediction:
        """Clean code fields in the prediction result by removing markdown guards."""
        code_fields = [
            'ground_truth', 'exploit', 'insecure_verifier', 'secure_verifier'
        ]
        
        for field in code_fields:
            if hasattr(result, field) and getattr(result, field):
                cleaned_code = self._extract_code_from_guards(getattr(result, field))
                setattr(result, field, cleaned_code)
                
        # Also clean nulls if it's a string (could contain code with guards)
        if hasattr(result, 'nulls') and result.nulls:
            # nulls is a JSON string containing code, so we need to parse and clean each item
            try:
                import json
                nulls_list = json.loads(result.nulls) if isinstance(result.nulls, str) else result.nulls
                if isinstance(nulls_list, list):
                    cleaned_nulls = [self._extract_code_from_guards(null_code) for null_code in nulls_list]
                    result.nulls = json.dumps(cleaned_nulls)
            except (json.JSONDecodeError, TypeError):
                # If parsing fails, leave as-is
                pass
                
        return result
    
    def _extract_function_name(self, problem_description: str, ground_truth_solution: str) -> str:
        """Extract function name from problem description or ground truth code."""
        
        # Try to extract from problem description first
        import re
        
        # Look for function name patterns in problem description
        patterns = [
            r'implement\s+(?:a\s+)?(?:function\s+)?`?([a-zA-Z_][a-zA-Z0-9_]*)\(`?',
            r'function\s+called\s+`?([a-zA-Z_][a-zA-Z0-9_]*)\(`?',
            r'write\s+(?:a\s+)?(?:function\s+)?`?([a-zA-Z_][a-zA-Z0-9_]*)\(`?',
            r'create\s+(?:a\s+)?(?:function\s+)?`?([a-zA-Z_][a-zA-Z0-9_]*)\(`?',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, problem_description, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # If not found in description, try to extract from ground truth code
        if ground_truth_solution:
            def_match = re.search(r'def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', ground_truth_solution)
            if def_match:
                return def_match.group(1)
        
        # Fallback to generic name
        return "solve_problem"
    
    def _parse_test_cases(self, test_cases_str: str) -> List[tuple]:
        """Parse test cases from string format to list of tuples."""
        try:
            # Use ast.literal_eval for safe evaluation of Python literals
            return ast.literal_eval(test_cases_str)
        except (ValueError, SyntaxError):
            return []

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