"""DSPy modules for automated problem generation."""

import json
import dspy
from typing import Dict, Any
from .signatures import ProblemAssets
from .prompts import get_enhanced_prompt, SYSTEM_PROMPT
from ..core.problem import Problem


class DraftProblem(dspy.Module):
    """DSPy module that generates a complete problem from an exploit description."""
    
    def __init__(self):
        super().__init__()
        self.generate = dspy.ChainOfThought(ProblemAssets)
    
    def forward(self, exploit_description: str) -> Dict[str, Any]:
        """Generate a complete problem from the exploit description."""
        
        # Use enhanced prompt with examples and constraints
        enhanced_description = get_enhanced_prompt(exploit_description)
        
        try:
            prediction = self.generate(exploit_description=enhanced_description)
            
            # Parse JSON fields with better error handling
            nulls = self._parse_json_field(prediction.nulls, "nulls")
            keywords = self._parse_json_field(prediction.keywords, "keywords")
            
            if nulls is None or keywords is None:
                return {
                    "error": "Failed to parse JSON fields (nulls or keywords)",
                    "raw_prediction": prediction
                }
            
            # Validate required fields
            validation_errors = self._validate_prediction(prediction)
            if validation_errors:
                return {
                    "error": f"Validation errors: {', '.join(validation_errors)}",
                    "raw_prediction": prediction
                }
            
            # Build the problem dictionary
            problem_dict = {
                "id": prediction.problem_id.strip(),
                "description": prediction.description.strip(),
                "ground_truth": prediction.ground_truth.strip(),
                "exploit": prediction.exploit.strip(),
                "nulls": nulls,
                "secure_verifier": prediction.secure_verifier.strip(),
                "insecure_verifier": prediction.insecure_verifier.strip(),
                "insecure_verifier_info": prediction.insecure_verifier_info.strip(),
                "exploit_explanation": prediction.exploit_explanation.strip(),
                "exploit_expected_status": prediction.exploit_expected_status.strip().lower(),
                "keywords": keywords,
                "gt_difficulty": max(1, min(5, int(prediction.gt_difficulty))),  # Clamp to 1-5
                "exploit_difficulty": max(1, min(5, int(prediction.exploit_difficulty)))  # Clamp to 1-5
            }
            
            return problem_dict
            
        except Exception as e:
            return {
                "error": f"Generation failed: {str(e)}",
                "raw_prediction": None
            }
    
    def _parse_json_field(self, field_value: str, field_name: str):
        """Parse a JSON field with error handling."""
        try:
            if isinstance(field_value, str):
                return json.loads(field_value)
            return field_value
        except json.JSONDecodeError:
            print(f"⚠️  Warning: Failed to parse {field_name} as JSON: {field_value}")
            return None
    
    def _validate_prediction(self, prediction) -> list:
        """Validate the prediction has all required fields."""
        errors = []
        
        required_fields = [
            'problem_id', 'description', 'ground_truth', 'exploit', 
            'secure_verifier', 'insecure_verifier', 'insecure_verifier_info',
            'exploit_explanation', 'exploit_expected_status'
        ]
        
        for field in required_fields:
            value = getattr(prediction, field, "").strip()
            if not value:
                errors.append(f"Missing or empty {field}")
        
        # Validate exploit_expected_status
        valid_statuses = ["passed", "failed", "timed_out", "crashed"]
        if hasattr(prediction, 'exploit_expected_status'):
            status = prediction.exploit_expected_status.strip().lower()
            if status not in valid_statuses:
                errors.append(f"Invalid exploit_expected_status: {status}")
        
        return errors


class ValidateProblem(dspy.Module):
    """DSPy module that validates a generated problem using the existing Problem class."""
    
    def __init__(self, timeout: int = 30):
        super().__init__()
        self.timeout = timeout
    
    def forward(self, problem_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Validate the generated problem by running consistency checks."""
        
        try:
            # Create a Problem instance
            problem = Problem(**problem_dict)
            
            # Run consistency checks with timeout handling
            print(f"🔍 Validating problem '{problem.id}'...")
            validation_passed = problem.check_consistency()
            
            return {
                "validation_passed": validation_passed,
                "validation_feedback": "All consistency checks passed" if validation_passed else "Consistency checks failed",
                "problem": problem
            }
            
        except Exception as e:
            return {
                "validation_passed": False,
                "validation_feedback": f"Problem instantiation failed: {str(e)}",
                "problem": None
            }


class ProblemGenerationPipeline(dspy.Module):
    """Complete pipeline that drafts and validates a problem."""
    
    def __init__(self):
        super().__init__()
        self.draft = DraftProblem()
        self.validate = ValidateProblem()
    
    def forward(self, exploit_description: str) -> Dict[str, Any]:
        """Generate and validate a complete problem."""
        
        # Draft the problem
        draft_result = self.draft(exploit_description)
        
        # Check for drafting errors
        if "error" in draft_result:
            return {
                "success": False,
                "error": draft_result["error"],
                "raw_prediction": draft_result.get("raw_prediction"),
                "stage": "drafting"
            }
        
        # Validate the problem
        validation_result = self.validate(draft_result)
        
        return {
            "success": validation_result["validation_passed"],
            "problem_dict": draft_result,
            "validation_feedback": validation_result["validation_feedback"],
            "problem": validation_result["problem"],
            "stage": "validation"
        } 