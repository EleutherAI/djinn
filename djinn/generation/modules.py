"""DSPy modules for problem and exploit generation."""

import dspy
import json
import yaml
import os
import ast
from pathlib import Path
from typing import Dict, List, Any, Optional
from ..core.problem import Problem
from .signatures import GenerateProblemDescription, GenerateGroundTruthAndTests, GenerateVulnerabilityComponents


# === THREE-STAGE GENERATION PIPELINE ===

class ThreeStageGenerationPipeline(dspy.Module):
    """Three-stage pipeline for generating security-focused programming problems."""
    
    def __init__(self):
        super().__init__()
        
        # Initialize TestCaseGenerator for tools
        from .generator_utils import TestCaseGenerator
        self.test_generator = TestCaseGenerator()
        
        # Stage 1: Problem Description Generation (ChainOfThought - no tools needed)
        self.description_generator = dspy.ChainOfThought(GenerateProblemDescription)
        
        # Stage 2: Ground Truth and Test Generation (ReAct with test generation tools)
        self.ground_truth_generator = dspy.ReAct(
            GenerateGroundTruthAndTests, 
            tools=self.test_generator.stage2_tools, 
            max_iters=10
        )
        
        # Stage 3: Vulnerability Component Generation (ReAct with validation tools)
        self.vulnerability_generator = dspy.ReAct(
            GenerateVulnerabilityComponents, 
            tools=self.test_generator.stage3_tools, 
            max_iters=10
        )
    
    def generate_stage1(self, reference_description: str = "") -> dspy.Prediction:
        """
        Stage 1: Generate problem description and function name.
        
        Args:
            reference_description: Optional existing description to adapt
            
        Returns:
            dspy.Prediction with description and function_name
        """
        print("🔄 Stage 1: Generating problem description and function name")
        result = self.description_generator(reference_description=reference_description)
        print(f"✅ Generated function: {result.function_name}")
        return result
    
    def generate_stage2(self, description: str, function_name: str, 
                       reference_ground_truth: str = "", reference_test_cases: str = "") -> dspy.Prediction:
        """
        Stage 2: Generate ground truth solution, test cases, and null solutions.
        
        Args:
            description: Problem description from Stage 1
            function_name: Function name from Stage 1
            reference_ground_truth: Optional existing ground truth to adapt
            reference_test_cases: Optional existing test cases to adapt
            
        Returns:
            dspy.Prediction with ground_truth, test_cases, and nulls
        """
        print("🔄 Stage 2: Generating ground truth, test cases, and null solutions")
        result = self.ground_truth_generator(
            description=description,
            function_name=function_name,
            reference_ground_truth=reference_ground_truth,
            reference_test_cases=reference_test_cases
        )
        print("✅ Generated ground truth and test cases")
        return self._clean_code_fields(result)
    
    def generate_stage3(self, description: str, function_name: str, ground_truth: str, 
                       test_cases: str, exploit_description: str) -> dspy.Prediction:
        """
        Stage 3: Generate vulnerability components.
        
        Args:
            description: Problem description from Stage 1
            function_name: Function name from Stage 1
            ground_truth: Ground truth solution from Stage 2
            test_cases: Test cases from Stage 2
            exploit_description: Description of exploit to generate
            
        Returns:
            dspy.Prediction with vulnerability components
        """
        print("🔄 Stage 3: Generating vulnerability components")
        result = self.vulnerability_generator(
            description=description,
            function_name=function_name,
            ground_truth=ground_truth,
            test_cases=test_cases,
            exploit_description=exploit_description
        )
        print("✅ Generated vulnerability components")
        return self._clean_code_fields(result)
    
    def generate_complete_problem(self, exploit_description: str, reference_description: str = "",
                                reference_ground_truth: str = "", reference_test_cases: str = "") -> dspy.Prediction:
        """
        Generate a complete problem using all three stages.
        
        Args:
            exploit_description: Description of exploit to generate
            reference_description: Optional existing description to adapt
            reference_ground_truth: Optional existing ground truth to adapt
            reference_test_cases: Optional existing test cases to adapt
            
        Returns:
            dspy.Prediction with all problem components
        """
        print("🚀 Starting three-stage problem generation")
        
        # Stage 1: Generate description and function name
        stage1_result = self.generate_stage1(reference_description=reference_description)
        
        # Stage 2: Generate ground truth and tests
        stage2_result = self.generate_stage2(
            description=stage1_result.description,
            function_name=stage1_result.function_name,
            reference_ground_truth=reference_ground_truth,
            reference_test_cases=reference_test_cases
        )
        
        # Stage 3: Generate vulnerability components
        stage3_result = self.generate_stage3(
            description=stage1_result.description,
            function_name=stage1_result.function_name,
            ground_truth=stage2_result.ground_truth,
            test_cases=stage2_result.test_cases,
            exploit_description=exploit_description
        )
        
        # Combine all results
        complete_result = dspy.Prediction(
            # From Stage 1
            description=stage1_result.description,
            function_name=stage1_result.function_name,
            
            # From Stage 2
            ground_truth=stage2_result.ground_truth,
            test_cases=stage2_result.test_cases,
            nulls=stage2_result.nulls,
            
            # From Stage 3
            exploit=stage3_result.exploit,
            insecure_verifier=stage3_result.insecure_verifier,
            insecure_verifier_info=stage3_result.insecure_verifier_info,
            exploit_explanation=stage3_result.exploit_explanation,
            info_leak_method=stage3_result.info_leak_method,
            labels=stage3_result.labels
        )
        
        print("🎉 Complete problem generation finished")
        return complete_result
    
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
        
        # Clean nulls
        if hasattr(result, 'nulls') and result.nulls:
            try:
                import json
                nulls_list = json.loads(result.nulls) if isinstance(result.nulls, str) else result.nulls
                if isinstance(nulls_list, list):
                    cleaned_nulls = [extract_code_from_guards(null_code) for null_code in nulls_list]
                    result.nulls = json.dumps(cleaned_nulls)
            except (json.JSONDecodeError, TypeError):
                pass
                
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
                test_cases: str, exploit_description: str) -> dspy.Prediction:
        """Generate vulnerability components."""
        result = self.generator(
            description=description,
            function_name=function_name,
            ground_truth=ground_truth,
            test_cases=test_cases,
            exploit_description=exploit_description
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
