"""Main problem generator class with DSPy optimization and OpenRouter integration."""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Callable
import dspy
from datasets import load_dataset
from concurrent.futures import ThreadPoolExecutor, as_completed
from .modules import ThreeStageGenerationPipeline
from .verifier import verify_problem_consistency
from .generator_utils import TestCaseGenerator
from .signatures import UniqueSolution, FindMatchingExploit, GenerateExploitKey
from ..core.problem import Problem
import time
import random


DATASET_MAPPING = {
    "primeintellect": {
        "name": "primeintellect/problems",
        "prompt_col": "problem_statement",
        "solution_col": "gold_standard_solution"
    },
    "taco-verified": {
        "name": "likaixin/TACO-verified",
        "prompt_col": "question",
        "solution_col": "solutions"
    },
}


class ProblemGenerator:
    """Main class for automated problem generation using DSPy and OpenRouter."""
    
    @classmethod
    def create_evaluation_optimized(cls, model: str = "openrouter/anthropic/claude-sonnet-4", 
                                   api_key: Optional[str] = None, difficulty_prefilter: bool = False):
        """
        Factory method to create a generator optimized for evaluation metrics.
        This is the recommended way to create generators for production use.
        """
        return cls(model=model, api_key=api_key, enable_evaluation=True, difficulty_prefilter=difficulty_prefilter)
    
    def __init__(self, model: str = "openrouter/anthropic/claude-sonnet-4", api_key: Optional[str] = None, 
                 enable_evaluation: bool = False, dataset_name: Optional[str] = None, 
                 difficulty_prefilter: bool = False):
        """
        Initialize the problem generator.
        
        Args:
            model: OpenRouter model identifier
            api_key: OpenRouter API key (if not provided, will use OPENROUTER_API_KEY env var)
            enable_evaluation: Whether to run detailed evaluation during generation
            dataset_name: Short name of the dataset to import from (e.g., 'primeintellect')
            difficulty_prefilter: Whether to reject problems that are too easy (solvable by smallest model)
        """
        self.model = model
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.enable_evaluation = enable_evaluation
        self.dataset_name = dataset_name
        self.dataset_config = DATASET_MAPPING.get(dataset_name) if dataset_name else None
        self.difficulty_prefilter = difficulty_prefilter
        
        if not self.api_key:
            raise ValueError("OpenRouter API key required. Set OPENROUTER_API_KEY environment variable or pass api_key parameter.")
        
        # Configure DSPy with OpenRouter
        self._setup_dspy()
        
        # Initialize the three-stage generation pipeline (tools are hardcoded internally)
        self.pipeline = ThreeStageGenerationPipeline(
            difficulty_prefilter=self.difficulty_prefilter,
            api_key=self.api_key
        )
        
        # Initialize exploit type handling modules
        self.exploit_matcher = dspy.Predict(FindMatchingExploit)
        self.exploit_key_generator = dspy.Predict(GenerateExploitKey)
        
        # Initialize evaluator if needed
        if self.enable_evaluation:
            try:
                from ..core.evaluator import ProblemEvaluator
                self.evaluator = ProblemEvaluator(api_key=self.api_key)
            except ImportError:
                print("Warning: dspy-ai required for evaluation. Disabling evaluation.")
                self.enable_evaluation = False

    def _setup_dspy(self):
        """Setup DSPy with OpenRouter configuration."""
        
        # Configure OpenRouter via OpenAI-compatible interface
        lm = dspy.LM(
            model=self.model,
            api_key=self.api_key,
            api_base="https://openrouter.ai/api/v1",
            max_tokens=32768
        )
        fast_lm = dspy.LM(
            model="openrouter/google/gemini-2.5-flash-lite-preview-06-17",
            api_key=self.api_key,
            api_base="https://openrouter.ai/api/v1",
            max_tokens=32768
        )
        dspy.configure(lm=lm)
        self.lm = lm
        self.fast_lm = fast_lm
    
    def _get_or_create_exploit_type(self, requested_exploit_description: str) -> Tuple[str, str]:
        """
        Find a matching exploit type or create a new one.
        
        Args:
            requested_exploit_description: The user-provided description of the exploit.
            
        Returns:
            A tuple of (exploit_key, exploit_description).
        """
        exploit_types_path = Path("djinn/problems/exploit_types.json")
        exploit_types = {}
        if exploit_types_path.exists():
            with open(exploit_types_path, 'r') as f:
                exploit_types = json.load(f)
        
        exploit_descriptions = {k: v['description'] for k, v in exploit_types.items()}
        
        # Use LLM to find a match
        with dspy.context(lm=self.fast_lm):
            result = self.exploit_matcher(
                requested_exploit=requested_exploit_description,
                existing_exploits_json=json.dumps(exploit_descriptions)
            )
        
        match_key = result.exploit_key
        
        if match_key != "None" and match_key in exploit_types:
            print(f"✅ Found matching exploit type: '{match_key}'")
            return match_key, exploit_types[match_key]['description']
        else:
            print("🤔 No matching exploit type found, creating a new one.")
            # Use LLM to generate a new key
            with dspy.context(lm=self.fast_lm):
                key_result = self.exploit_key_generator(exploit_description=requested_exploit_description)
                new_key = key_result.exploit_key

            print(f"   Generated new key: '{new_key}'")
            
            # Add to exploit types and save
            exploit_types[new_key] = {
                "description": requested_exploit_description,
                "problems": []
            }
            with open(exploit_types_path, 'w') as f:
                json.dump(exploit_types, f, indent=2, sort_keys=True)
            
            return new_key, requested_exploit_description

    def update_exploit_type_list(self, problem_slug: str, exploit_type_key: str):
        """
        Update the exploit_types.json file to include the new problem slug.
        
        Args:
            problem_slug: The slug of the newly generated problem.
            exploit_type_key: The exploit type key for the problem.
        """
        exploit_types_path = Path("djinn/problems/exploit_types.json")
        exploit_types = {}
        if exploit_types_path.exists():
            with open(exploit_types_path, 'r') as f:
                exploit_types = json.load(f)

        if exploit_type_key in exploit_types:
            if problem_slug not in exploit_types[exploit_type_key].get("problems", []):
                exploit_types[exploit_type_key].setdefault("problems", []).append(problem_slug)
                exploit_types[exploit_type_key]["problems"].sort()

                with open(exploit_types_path, 'w') as f:
                    json.dump(exploit_types, f, indent=2, sort_keys=True)
                print(f"✅ Updated exploit type '{exploit_type_key}' with problem: {problem_slug}")
        else:
            print(f"⚠️  Warning: Exploit type '{exploit_type_key}' not found in exploit_types.json. Cannot update list.")

    def _run_final_validation_and_alignment_check(self, result, exploit_description: str) -> Dict[str, Any]:
        """
        Run final validation and alignment checks on a generated problem.
        
        Args:
            result: The result from the generation pipeline (DSPy result object or dict)
            exploit_description: The original exploit description
            
        Returns:
            Dictionary with success status and validation/alignment results or error info
        """
        print("🔍 Running final validation and alignment check...")
        
        # Handle both DSPy result objects and dictionary results
        if hasattr(result, 'ground_truth'):
            # DSPy result object with attributes
            ground_truth = result.ground_truth
            exploit = result.exploit
            function_name = result.function_name
            test_cases = result.test_cases
            insecure_verifier = result.insecure_verifier
            nulls = result.nulls if isinstance(result.nulls, str) else json.dumps(result.nulls)
        elif isinstance(result, dict) and "problem_dict" in result:
            # Dictionary result structure (from generate_from_components)
            problem_dict = result["problem_dict"]
            ground_truth = problem_dict["ground_truth"]
            exploit = problem_dict["exploit"]
            function_name = problem_dict["function_name"]
            test_cases = problem_dict["test_cases"]
            insecure_verifier = problem_dict["insecure_verifier"]
            nulls = json.dumps(problem_dict.get("nulls", []))
        else:
            return {
                "success": False,
                "error": "Invalid result structure for validation check"
            }
        
        # 1. Final validation check using the validation tool
        try:
            test_generator = TestCaseGenerator()
            validation_result_str = test_generator._validate_problem_consistency(
                ground_truth=ground_truth,
                exploit=exploit,
                function_name=function_name,
                test_cases=test_cases,
                insecure_verifier=insecure_verifier,
                nulls=nulls
            )
            validation_result = json.loads(validation_result_str)
            
            if not validation_result.get("is_consistent", False):
                print("❌ Problem failed final validation check")
                print(f"   Validation summary: {validation_result.get('validation_summary', 'Unknown failure')}")
                return {
                    "success": False,
                    "error": "Problem failed final validation check",
                    "validation_result": validation_result,
                    "validation_summary": validation_result.get('validation_summary', 'Unknown failure'),
                    "validation_errors": validation_result.get('errors', [])
                }
            else:
                print("✅ Final validation check passed")
                
        except Exception as e:
            print(f"❌ Final validation check failed with exception: {e}")
            return {
                "success": False,
                "error": f"Final validation check failed: {str(e)}",
            }
        
        # 2. Final alignment check using the alignment tool
        try:
            alignment_result_str = test_generator._check_vulnerability_alignment(
                exploit_code=exploit,
                insecure_verifier_code=insecure_verifier,
                exploit_description=exploit_description
            )
            alignment_result = json.loads(alignment_result_str)
            
            if not alignment_result.get("passes_check", False):
                print("❌ Problem failed final alignment check")
                print(f"   Alignment summary: {alignment_result.get('alignment_summary', 'Unknown failure')}")
                print(f"   Positive score: {alignment_result.get('positive_alignment_score', 'N/A')}/10")
                print(f"   Negative score: {alignment_result.get('negative_alignment_score', 'N/A')}/10")
                return {
                    "success": False,
                    "error": "Problem failed final alignment check",
                    "alignment_result": alignment_result,
                    "alignment_summary": alignment_result.get('alignment_summary', 'Unknown failure'),
                    "alignment_reasoning": alignment_result.get('alignment_reasoning', ''),
                    "recommendations": alignment_result.get('recommendations', '')
                }
            else:
                print("✅ Final alignment check passed")
                print(f"   Positive score: {alignment_result.get('positive_alignment_score', 'N/A')}/10")
                print(f"   Negative score: {alignment_result.get('negative_alignment_score', 'N/A')}/10")
                
        except Exception as e:
            print(f"❌ Final alignment check failed with exception: {e}")
            return {
                "success": False,
                "error": f"Final alignment check failed: {str(e)}",
            }
        
        # If we get here, both checks passed
        return {
            "success": True,
            "validation_result": validation_result,
            "alignment_result": alignment_result
        }
    
    def generate_problem(self, exploit_description: str) -> Dict[str, Any]:
        """
        Generate a complete problem from an exploit description.
        
        Args:
            exploit_description: Free-text description of the exploit to implement
            
        Returns:
            Dictionary containing the generated problem and metadata
        """
        
        # Find or create an exploit type for this description
        exploit_type_key, final_exploit_description = self._get_or_create_exploit_type(exploit_description)
                
        # Run the three-stage generation pipeline
        with dspy.context(lm=self.lm):
            result = self.pipeline.generate_complete_problem(
                exploit_description=final_exploit_description
            )
        
        # Check if generation failed at stage 2 or prefilter
        if hasattr(result, 'generation_failed') and result.generation_failed:
            failure_stage = result.failure_stage
            if failure_stage == "prefilter":
                print("❌ Problem generation failed at difficulty pre-filter")
                return {
                    "success": False,
                    "error": f"Difficulty pre-filter failed: {result.failure_reason}",
                    "failure_stage": failure_stage,
                    "prefilter_result": getattr(result, 'prefilter_result', {}),
                    "failure_details": {
                        "model_tested": getattr(result, 'prefilter_result', {}).get('model_tested', 'unknown'),
                        "can_solve": getattr(result, 'prefilter_result', {}).get('can_solve', True),
                        "verification_result": getattr(result, 'prefilter_result', {}).get('verification_result', 'unknown'),
                        "skipped_stage_3": True
                    }
                }
            else:
                print(f"❌ Problem generation failed at stage {failure_stage}")
                stats = getattr(result, 'test_generation_stats', {})
                return {
                    "success": False,
                    "error": f"Stage {failure_stage} failed: {result.failure_reason}",
                    "failure_stage": failure_stage,
                    "test_generation_stats": stats,
                    "failure_details": {
                        "total_test_calls": stats.get("total_calls", 0),
                        "successful_test_calls": stats.get("successful_calls", 0),
                        "success_rate": stats.get("success_rate", 0.0)
                    }
                }
        
        if hasattr(result, 'function_name') and hasattr(result, 'test_cases'):
            print("✅ Problem generated and validated successfully!")
            # Create the problem dictionary with the new structure
            problem_dict = {
                "id": f"generated_{int(time.time())}",
                "description": result.description,
                "function_name": result.function_name,
                "test_cases": result.test_cases,
                "ground_truth": result.ground_truth,
                "exploit": result.exploit,
                "nulls": json.loads(result.nulls) if isinstance(result.nulls, str) else result.nulls,
                "insecure_verifier": result.insecure_verifier,
                "insecure_verifier_info": result.insecure_verifier_info,
                "exploit_explanation": result.exploit_explanation,
                "exploit_expected_status": "passed",
                "keywords": [],
                "info_leak_method": result.info_leak_method,
                "exploit_type": exploit_type_key
            }
            
            # Create the Problem object
            try:
                problem = Problem(**problem_dict)
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Failed to create Problem object: {e}",
                }
            
            # FINAL VALIDATION AND ALIGNMENT CHECK
            validation_check_result = self._run_final_validation_and_alignment_check(result, final_exploit_description)
            
            if not validation_check_result["success"]:
                return validation_check_result
            
            # Run detailed evaluation if enabled
            if self.enable_evaluation:
                print("🔍 Running detailed evaluation...")
                try:
                    eval_result = self.evaluator.evaluate_problem(problem, quick=False)
                    problem.apply_evaluation_results(eval_result)
                    print("✅ Detailed evaluation complete!")
                except Exception as e:
                    print(f"⚠️  Evaluation failed: {e}")
            
            return {
                "success": True,
                "problem_dict": problem_dict,
                "problem": problem,
                "validation_feedback": "Problem generated and validated successfully",
                "validation_result": validation_check_result["validation_result"],
                "alignment_result": {
                    "positive_score": validation_check_result["alignment_result"].get('positive_alignment_score'),
                    "negative_score": validation_check_result["alignment_result"].get('negative_alignment_score'),
                    "passes_check": validation_check_result["alignment_result"].get('passes_check'),
                    "alignment_reasoning": validation_check_result["alignment_result"].get('alignment_reasoning'),
                    "recommendations": validation_check_result["alignment_result"].get('recommendations')
                },
            }
        else:
            # Extract detailed failure reason
            failure_reason = "Generation pipeline failed to produce valid result"
            print(f"❌ Failed to generate valid problem: {failure_reason}")
            return {
                "success": False,
                "error": f"Failed to generate valid problem: {failure_reason}",
            }
    
    def generate_from_components(self, exploit_description: str, problem_description: str = "", 
                                ground_truth_solution: str = "", test_cases: str = "") -> Dict[str, Any]:
        """
        Generate verifiers and exploits from existing problem components.
        
        Args:
            exploit_description: Description of the vulnerability to introduce
            problem_description: Existing problem description (if available)
            ground_truth_solution: Existing ground truth solution (if available)
            test_cases: Existing test cases (if available)
            
        Returns:
            Dictionary containing the generated problem and metadata
        """
        
        # Find or create an exploit type for this description
        exploit_type_key, final_exploit_description = self._get_or_create_exploit_type(exploit_description)
                
        # Use the three-stage pipeline but provide reference materials
        with dspy.context(lm=self.lm):
            result = self.pipeline.generate_complete_problem(
                exploit_description=final_exploit_description,
                reference_description=problem_description,
                reference_ground_truth=ground_truth_solution,
                reference_test_cases=test_cases
            )
        
        # Check if generation failed at stage 2 or prefilter
        if hasattr(result, 'generation_failed') and result.generation_failed:
            failure_stage = result.failure_stage
            if failure_stage == "prefilter":
                print("❌ Problem generation failed at difficulty pre-filter")
                return {
                    "success": False,
                    "error": f"Difficulty pre-filter failed: {result.failure_reason}",
                    "failure_stage": failure_stage,
                    "prefilter_result": getattr(result, 'prefilter_result', {}),
                    "failure_details": {
                        "model_tested": getattr(result, 'prefilter_result', {}).get('model_tested', 'unknown'),
                        "can_solve": getattr(result, 'prefilter_result', {}).get('can_solve', True),
                        "verification_result": getattr(result, 'prefilter_result', {}).get('verification_result', 'unknown'),
                        "skipped_stage_3": True
                    }
                }
            else:
                print(f"❌ Problem generation failed at stage {failure_stage}")
                stats = getattr(result, 'test_generation_stats', {})
                return {
                    "success": False,
                    "error": f"Stage {failure_stage} failed: {result.failure_reason}",
                    "failure_stage": failure_stage,
                    "test_generation_stats": stats,
                    "failure_details": {
                        "total_test_calls": stats.get("total_calls", 0),
                        "successful_test_calls": stats.get("successful_calls", 0),
                        "success_rate": stats.get("success_rate", 0.0)
                    }
                }
        
        if hasattr(result, 'function_name') and hasattr(result, 'test_cases'):
            print("✅ Problem generated and validated successfully!")
            
            # Create the problem dictionary with the new structure
            problem_dict = {
                "id": f"generated_{int(time.time())}",
                "description": result.description,
                "function_name": result.function_name,
                "test_cases": result.test_cases,
                "ground_truth": result.ground_truth,
                "exploit": result.exploit,
                "nulls": json.loads(result.nulls) if isinstance(result.nulls, str) else result.nulls,
                "insecure_verifier": result.insecure_verifier,
                "insecure_verifier_info": result.insecure_verifier_info,
                "exploit_explanation": result.exploit_explanation,
                "exploit_expected_status": "passed",
                "keywords": [],
                "info_leak_method": result.info_leak_method,
                "exploit_type": exploit_type_key
            }
            
            # Create the Problem object
            try:
                problem = Problem(**problem_dict)
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Failed to create Problem object: {e}",
                }
            
            # FINAL VALIDATION AND ALIGNMENT CHECK
            validation_check_result = self._run_final_validation_and_alignment_check(result, final_exploit_description)
            
            if not validation_check_result["success"]:
                return validation_check_result
            
            # Run detailed evaluation if enabled
            if self.enable_evaluation:
                print("🔍 Running detailed evaluation...")
                try:
                    eval_result = self.evaluator.evaluate_problem(problem, quick=False)
                    problem.apply_evaluation_results(eval_result)
                    print("✅ Detailed evaluation complete!")
                except Exception as e:
                    print(f"⚠️  Evaluation failed: {e}")
            
            return {
                "success": True,
                "problem_dict": problem_dict,
                "problem": problem,
                "validation_feedback": "Problem generated and validated successfully",
                "validation_result": validation_check_result["validation_result"],
                "alignment_result": {
                    "positive_score": validation_check_result["alignment_result"].get('positive_alignment_score'),
                    "negative_score": validation_check_result["alignment_result"].get('negative_alignment_score'),
                    "passes_check": validation_check_result["alignment_result"].get('passes_check'),
                    "alignment_reasoning": validation_check_result["alignment_result"].get('alignment_reasoning'),
                    "recommendations": validation_check_result["alignment_result"].get('recommendations')
                },
            }
        else:
            # Extract detailed failure reason
            failure_reason = "Generation pipeline failed to produce valid result"
            print(f"❌ Failed to generate valid problem: {failure_reason}")
            return {
                "success": False,
                "error": f"Failed to generate valid problem: {failure_reason}",
            }
    
    def optimize_pipeline(self, training_examples: List[Dict[str, Any]], optimizer_type: str = "bootstrap"):
        """
        Optimize the generation pipeline using DSPy optimizers.
        
        Note: Optimization with the three-stage pipeline is currently not fully supported.
        The new modular architecture makes optimization more complex as each stage
        has different tools and objectives.
        
        Args:
            training_examples: List of exploit descriptions with expected outcomes
            optimizer_type: Type of optimizer to use ('bootstrap' or 'mipro')
        """
        
        raise NotImplementedError("Pipeline optimization is not supported with the three-stage pipeline")
    
    def save_problem(self, problem_dict: Dict[str, Any], output_dir: str, problem_obj: Optional[Problem] = None):
        """
        Save a generated problem to the filesystem in Djinn format.
        
        Args:
            problem_dict: Problem dictionary from generate_problem
            output_dir: Directory to save the problem (will be created if needed)
            problem_obj: Problem object (optional, for evaluation results)
        """
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Create problem.yaml with metadata and inline code
        problem_yaml = {
            "id": problem_dict["id"],
            "description": problem_dict["description"],
            "function_name": problem_dict["function_name"],
            "test_cases": problem_dict["test_cases"],
            "exploit_explanation": problem_dict["exploit_explanation"],
            "exploit_expected_status": problem_dict["exploit_expected_status"],
            "keywords": problem_dict["keywords"],
            "exploit_type": problem_dict.get("exploit_type"),
            # Inline the code assets
            "ground_truth": problem_dict["ground_truth"],
            "exploit": problem_dict["exploit"],
            "insecure_verifier": problem_dict["insecure_verifier"],
            "insecure_verifier_info": problem_dict["insecure_verifier_info"],
            "nulls": problem_dict["nulls"],
            "info_leak_method": problem_dict.get("info_leak_method", ""),
            "order_dependent": problem_dict.get("order_dependent", True)
        }
        
        # Add evaluation results if available from the Problem object
        if problem_obj:
            eval_fields = [
                "evaluated_gt_difficulty", "evaluated_exploit_difficulty", 
                "gt_model_results", "exploit_model_results",
                "vuln_cheatiness", "exploit_fairness", "problem_quality", 
                "problem_appears_as", "exploit_finding_appearance"
            ]
            for field in eval_fields:
                value = getattr(problem_obj, field, None)
                if value is not None:
                    problem_yaml[field] = value
        
        # Write problem.yaml
        with open(output_path / "problem.yaml", "w") as f:
            yaml.dump(problem_yaml, f, default_flow_style=False, allow_unicode=True)
        
        print(f"💾 Problem saved to {output_path}")
        print(f"   - problem.yaml: {len(json.dumps(problem_yaml))} characters")
    
    def generate_directory_name(self, problem_dict: Dict[str, Any], base_path: str) -> str:
        """
        Generate a unique, concise, descriptive directory name for a problem using LLM.
        
        Args:
            problem_dict: The problem dictionary
            base_path: The base directory path where this directory will be created
            
        Returns:
            A filesystem-safe directory name that doesn't already exist in base_path
        """
        from pathlib import Path
        import re
        
        base_path = Path(base_path)
        
        # Create a concise prompt for directory naming that considers both description and exploit
        problem_desc = problem_dict.get('description', '')[:300]
        exploit_explanation = problem_dict.get('exploit_explanation', '')[:300]
        
        prompt = f"""Generate a concise, descriptive directory name for this coding problem. The name should be:
- 2-4 words maximum
- Use underscores instead of spaces
- Be filesystem-safe (no special characters)
- Capture both the main problem concept AND the vulnerability type

Problem description: {problem_desc}...
Vulnerability/exploit: {exploit_explanation}...

Examples of good names: "string_buffer_overflow", "sql_injection_login", "path_traversal_file_access"

Respond with just the directory name, nothing else."""

        def clean_name(raw_name: str) -> str:
            """Clean and sanitize a directory name."""
            name = raw_name.strip().lower()
            # Remove any quotes or extra text
            name = name.replace('"', '').replace("'", '')
            # Keep only alphanumeric, underscores, and hyphens
            name = re.sub(r'[^a-z0-9_-]', '_', name)
            # Remove multiple consecutive underscores
            name = re.sub(r'_+', '_', name)
            # Remove leading/trailing underscores
            name = name.strip('_')
            return name

        def generate_fallback_name() -> str:
            """Generate a fallback name from problem description."""
            # Use first few words of problem description
            desc_words = problem_dict.get('description', 'generated problem').split()[:3]
            fallback = '_'.join(desc_words).lower()
            return clean_name(fallback) or 'generated_problem'

        # Try to generate name with LLM
        try:
            import dspy
            response = dspy.Predict("question -> answer")(question=prompt)
            base_name = clean_name(response.answer)
            
            # Fallback if name is too short or empty
            if len(base_name) < 3:
                raise ValueError("Generated name too short")
                
        except Exception as e:
            print(f"⚠️  LLM name generation failed ({e}), using fallback")
            base_name = generate_fallback_name()

        # Ensure uniqueness by checking if directory exists
        unique_name = base_name
        counter = 1
        
        while (base_path / unique_name).exists():
            unique_name = f"{base_name}_{counter}"
            counter += 1
            
            # Safety check to avoid infinite loop
            if counter > 100:
                import time
                unique_name = f"{base_name}_{int(time.time())}"
                break
                
        return unique_name
    
    def save_optimized_generator(self, name: str, save_dir: str = "optimized_generators", 
                                description: str = ""):
        """
        Save the current generator configuration (note: optimization not fully supported in three-stage pipeline).
        
        Args:
            name: Unique name for this generator configuration
            save_dir: Directory to save generators (default: "optimized_generators")
            description: Optional description of what this generator is configured for
        """
        raise NotImplementedError("Saving optimized generators is not supported with the three-stage pipeline")
    
    def load_optimized_generator(self, name: str, save_dir: str = "optimized_generators"):
        """
        Load a previously saved generator configuration.
        
        Args:
            name: Name of the saved generator
            save_dir: Directory where generators are saved
        """
        raise NotImplementedError("Loading optimized generators is not supported with the three-stage pipeline")
    
    def _load_dataset(self, split: str = "train", streaming: bool = False):
        """Load the configured dataset from Hugging Face Hub."""
        if not self.dataset_config:
            raise ValueError("Dataset not configured for this generator. Initialize with a dataset_name.")
        
        dataset_name = self.dataset_config["name"]
        print(f"Loading dataset: {dataset_name}")
        return load_dataset(dataset_name, split=split, streaming=streaming)

    def _get_problem_by_id(self, problem_id: str, split: str = "train"):
        """(Inefficiently) get a single problem by ID from the streaming dataset."""
        # This is very inefficient for streaming datasets, but useful for targeted testing.
        dataset = self._load_dataset(split=split, streaming=True)
        for problem in dataset:
            if problem.get('id') == problem_id:
                return problem
        return None

    def _sample_problems(self, n: int = 5, split: str = "train", filter_fn: Optional[Callable[[Dict], bool]] = None):
        """Sample problems from the dataset, with an option to apply a filter function."""
        dataset = self._load_dataset(split=split, streaming=False)
        
        if filter_fn:
            dataset = dataset.filter(filter_fn)
        
        # Get the total number of available problems
        total_problems = len(dataset)
        
        if total_problems == 0:
            return []
        
        i = 0
        samples = []
        unique_solution_checker = dspy.Predict(UniqueSolution)
        prompt_col = self.dataset_config["prompt_col"]
        solution_col = self.dataset_config["solution_col"]
        
        while i < n:
            j = random.randint(0, len(dataset) - 1)
            problem = dataset[j]
            with dspy.context(lm=self.fast_lm):
                unique_result_response = unique_solution_checker(
                    problem_description=problem[prompt_col], 
                    ground_truth=problem[solution_col]
                )
            if unique_result_response.unique_solution:
                print(f"✅ Unique solution found {i+1}/{total_problems}")
                samples.append(problem)
                i += 1
 
        return samples

    @classmethod
    def from_saved_generator(cls, name: str, save_dir: str = "optimized_generators", 
                           api_key: Optional[str] = None):
        """
        Create a generator instance from a saved generator configuration.
        
        Args:
            name: Name of the saved generator configuration
            save_dir: Directory where generators are saved
            api_key: OpenRouter API key (optional, uses env var if not provided)
        """
        raise NotImplementedError("Loading saved generators is not supported with the three-stage pipeline")
    
    @staticmethod
    def list_saved_generators(save_dir: str = "optimized_generators") -> List[Dict[str, Any]]:
        """
        List all saved optimized generators.
        
        Args:
            save_dir: Directory where generators are saved
            
        Returns:
            List of generator metadata dictionaries
        """
        raise NotImplementedError("Loading saved generators is not supported with the three-stage pipeline")
    
    def import_from_taco_verified(self, row: Dict[str, Any] = None, 
                                  exploit_description: str = "") -> Dict[str, Any]:
        """
        Import a problem from the likaixin/TACO-verified dataset and generate missing components.
        
        Args:
            row: A row from the TACO-verified dataset.
            exploit_description: The description of the exploit to generate.
            
        Returns:
            Dictionary with generation result.
        """
        if not row:
            return {"success": False, "error": "No dataset row provided"}
            
        start_time = time.time()
        
        # Extract components from dataset using configured column names
        prompt_col = self.dataset_config["prompt_col"]
        solution_col = self.dataset_config["solution_col"]
        
        problem_description = row.get(prompt_col, "")
        solutions = row.get(solution_col, [])
        
        if not problem_description or not solutions:
            return {
                "success": False, 
                "error": f"Missing '{prompt_col}' or '{solution_col}' in dataset row. Row keys: {list(row.keys())}"
            }
        
        # Select up to 3 random solutions
        num_to_select = min(len(solutions), 3)
        selected_solutions = random.sample(solutions, num_to_select)
        reference_ground_truth = "\n\n---\n\n".join(selected_solutions)
        
        print(f"🔄 Importing from TACO-verified with {num_to_select} reference solutions")
        
        try:
            # Use the component-based generation pipeline
            result = self.generate_from_components(
                exploit_description=exploit_description,
                problem_description=problem_description,
                ground_truth_solution=reference_ground_truth,
            )
            
            end_time = time.time()
            result['duration'] = end_time - start_time
            result['source_dataset'] = 'taco-verified'
            result['source_row'] = row

            return result
        
        except Exception as e:
            import traceback
            return {
                "success": False,
                "error": f"Exception during generation: {str(e)}",
                "traceback": traceback.format_exc()
            }

    def import_from_prime_intellect(self, problem_id: str = None, row: Dict[str, Any] = None, 
                                  exploit_description: str = "", 
                                  provided_exploit: str = "", provided_insecure_verifier: str = "",
                                  provided_secure_verifier: str = "") -> Dict[str, Any]:
        """
        Import a problem from the PrimeIntellect dataset and generate missing components.
        
        Args:
            problem_id: The ID of the problem to import (optional if row is provided).
            row: A row from the dataset (optional if problem_id is provided).
            exploit_description: The description of the exploit to generate.
            provided_exploit: Pre-written exploit code (optional).
            provided_insecure_verifier: Pre-written insecure verifier code (optional).
            provided_secure_verifier: Pre-written secure verifier code (optional).
            
        Returns:
            Dictionary with generation result.
        """
        if problem_id and not row:
            row = self._get_problem_by_id(problem_id)
            if not row:
                return {"success": False, "error": f"Problem with ID '{problem_id}' not found"}
        elif not row:
            return {"success": False, "error": "Either problem_id or row must be provided"}
        
        start_time = time.time()
        
        # Extract components from dataset using configured column names
        prompt_col = self.dataset_config["prompt_col"]
        solution_col = self.dataset_config["solution_col"]
        
        problem_description = row.get(prompt_col, "")
        ground_truth_solution = row.get(solution_col, "")
        test_cases = row.get("test_cases", "")
        
        if not problem_description:
            return {
                "success": False, 
                "error": f"Missing '{prompt_col}' in dataset row. Row keys: {list(row.keys())}"
            }
        
        print(f"🔄 Importing from PrimeIntellect dataset")
        if problem_id:
            print(f"   Problem ID: {problem_id}")
        
        try:
            # Use the unified generation pipeline
            result = self.generate_from_components(
                exploit_description=exploit_description,
                problem_description=problem_description,
                ground_truth_solution=ground_truth_solution,
                test_cases=test_cases
            )
            
            end_time = time.time()
            result['duration'] = end_time - start_time
            result['source_dataset'] = 'primeintellect'
            result['source_row'] = row

            return result
        
        except Exception as e:
            import traceback
            return {
                "success": False,
                "error": f"Exception during generation: {str(e)}",
                "traceback": traceback.format_exc()
            }

    def sample_and_import(self, exploit_description: str, n: int = 5, filter_with_ground_truth: bool = True, 
                         max_workers: int = 5) -> List[Dict[str, Any]]:
        """
        Sample and import multiple problems from the configured dataset in parallel.
        
        Args:
            exploit_description: Description of the vulnerability to introduce (required)
            n: Number of problems to sample and import
            filter_with_ground_truth: Only sample problems that have ground truth solutions
            max_workers: Maximum number of parallel import jobs (default: 5)
            
        Returns:
            List of import results
        """
        if not exploit_description:
            raise ValueError("exploit_description is required - specify what vulnerability to introduce")
        
        if not self.dataset_name:
            raise ValueError("Generator not configured with a dataset. Please initialize with a 'dataset_name'.")

        filter_fn = None
        import_function = None
        solution_col = self.dataset_config["solution_col"]

        if self.dataset_name == "primeintellect":
            if filter_with_ground_truth:
                filter_fn = lambda x: x[solution_col]
            import_function = self.import_from_prime_intellect
        elif self.dataset_name == "taco-verified":
            # For TACO, GT is always present in 'solutions', so we filter for non-empty lists.
            filter_fn = lambda x: x[solution_col] and len(x[solution_col]) > 0
            import_function = self.import_from_taco_verified
        else:
            raise ValueError(f"Unsupported dataset for import: {self.dataset_name}")

        print(f"🎲 Sampling {n} problems from {self.dataset_name} dataset...")
        print(f"   Max parallel workers: {max_workers}")
        print(f"🎯 Exploit type: {exploit_description}")
        
        samples = self._sample_problems(n=n, filter_fn=filter_fn)
        print(f"📋 Found {len(samples)} problems to import")
        
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_problem = {
                executor.submit(import_function, row=problem, exploit_description=exploit_description): problem
                for problem in samples
            }
            
            print(f"🚀 Started {len(samples)} import jobs in parallel...")
            
            for future in as_completed(future_to_problem):
                problem = future_to_problem[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    import traceback
                    print(f"Error importing problem: {e}")
                    results.append({
                        "success": False,
                        "error": str(e),
                        "problem_info": problem,
                        "traceback": traceback.format_exc()
                    })
        
        # Summary
        successful = sum(1 for r in results if r and r.get("success"))
        print(f"\n{'='*60}")
        print(f"IMPORT SUMMARY")
        print(f"{'='*60}")
        print(f"Total problems attempted: {len(results)}")
        print(f"Successful imports: {successful}")
        print(f"Failed imports: {len(results) - successful}")
        
        return results

    def __repr__(self):
        return f"ProblemGenerator(model='{self.model}', enable_evaluation={self.enable_evaluation})"