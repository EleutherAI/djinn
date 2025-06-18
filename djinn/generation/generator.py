"""Main problem generator class with DSPy optimization and OpenRouter integration."""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import dspy
from datasets import load_dataset
from .modules import ProblemGenerationPipeline
from .verifier import verify_problem_consistency
from .generator_utils import TestCaseGenerator
from ..core.problem import Problem
import time


class ProblemGenerator:
    """Main class for automated problem generation using DSPy and OpenRouter."""
    
    @classmethod
    def create_evaluation_optimized(cls, model: str = "openrouter/anthropic/claude-sonnet-4", 
                                   api_key: Optional[str] = None):
        """
        Factory method to create a generator optimized for evaluation metrics.
        This is the recommended way to create generators for production use.
        """
        return cls(model=model, api_key=api_key, enable_evaluation=True)
    
    def __init__(self, model: str = "openrouter/anthropic/claude-sonnet-4", api_key: Optional[str] = None, 
                 enable_evaluation: bool = False):
        """
        Initialize the problem generator.
        
        Args:
            model: OpenRouter model identifier
            api_key: OpenRouter API key (if not provided, will use OPENROUTER_API_KEY env var)
            enable_evaluation: Whether to run detailed evaluation during generation
        """
        self.model = model
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.enable_evaluation = enable_evaluation
        
        if not self.api_key:
            raise ValueError("OpenRouter API key required. Set OPENROUTER_API_KEY environment variable or pass api_key parameter.")
        
        # Configure DSPy with OpenRouter
        self._setup_dspy()
        
        # Initialize test case generator with DSPy tools
        self.test_case_generator = TestCaseGenerator()
        
        # Initialize the generation pipeline with tools
        self.pipeline = ProblemGenerationPipeline(tools=self.test_case_generator.tools).compile_with_examples()
        
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
        dspy.configure(lm=lm)
    
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
            validation_result_str = self.test_case_generator._validate_problem_consistency(
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
            alignment_result_str = self.test_case_generator._check_vulnerability_alignment(
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
            max_attempts: Maximum number of generation attempts
            
        Returns:
            Dictionary containing the generated problem and metadata
        """
                
        # Run the generation pipeline with failure feedback (full generation mode)
        result = self.pipeline(
            exploit_description=exploit_description
        )
        
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
                "info_leak_method": result.info_leak_method
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
            validation_check_result = self._run_final_validation_and_alignment_check(result, exploit_description)
            
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
                                ground_truth_solution: str = "") -> Dict[str, Any]:
        """
        Generate verifiers and exploits from existing problem components (unified import-style generation).
        
        Args:
            exploit_description: Description of the vulnerability to introduce
            problem_description: Existing problem description (if available)
            ground_truth_solution: Existing ground truth solution (if available)
            
        Returns:
            Dictionary containing the generated problem and metadata
        """
                
        # Run the generation pipeline in import mode (with failure feedback handled internally)
        result = self.pipeline(
            exploit_description=exploit_description,
            problem_description=problem_description,
            ground_truth_solution=ground_truth_solution
        )
        
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
                "info_leak_method": result.info_leak_method
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
            validation_check_result = self._run_final_validation_and_alignment_check(result, exploit_description)
            
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
        
        Args:
            training_examples: List of exploit descriptions with expected outcomes
            optimizer_type: Type of optimizer to use ('bootstrap' or 'mipro')
        """
        
        def validation_metric(gold, pred, trace=None):
            """
            Enhanced metric function for DSPy optimization based on evaluation criteria.
            Optimizes for:
            - Basic consistency (40%): GT passes both verifiers, exploit passes insecure only, nulls fail
            - Problem quality (24%): Higher is better  
            - Exploit fairness (24%): Higher is better
            - Inverted exploit finding appearance (12%): Lower is better - want problems to look normal
            """
            if not isinstance(pred, dict) or not pred.get("success", False):
                return 0.0
            
            # Get the problem instance for consistency checks
            problem = pred.get("problem")
            if not problem:
                return 0.0
            
            score = 0.0
            weights = {
                "quality": 0.4,       # Problem specification quality
                "fairness": 0.4,      # Exploit fairness
                "appearance": 0.2     # Normal appearance
            }
                        
            # 1. Run detailed evaluation if evaluator is available and not already done
            eval_result = pred.get("evaluation_result")
            if not eval_result and self.enable_evaluation and hasattr(self, 'evaluator'):
                try:
                    print(f"🔍 Running detailed evaluation for optimization...")
                    eval_result = self.evaluator.evaluate_problem(problem, quick=True)  # Use quick mode during optimization
                    # Store the result for potential reuse
                    pred["evaluation_result"] = eval_result
                except Exception as e:
                    print(f"⚠️  Evaluation failed during optimization: {e}")
                    eval_result = None
            
            # 2. Apply evaluation-based metrics (if available)
            if eval_result:
                # Problem quality score (0-1, scaled from 1-10)
                if eval_result.problem_quality is not None:
                    quality_score = (eval_result.problem_quality - 1) / 9  # Scale 1-10 to 0-1
                    score += weights["quality"] * max(0, min(1, quality_score))
                    print(f"   📊 Problem Quality: {eval_result.problem_quality:.1f}/10 (contributes {weights['quality'] * quality_score:.3f})")
                
                # Exploit fairness score (0-1, scaled from 1-10)
                if eval_result.exploit_fairness is not None:
                    fairness_score = (eval_result.exploit_fairness - 1) / 9  # Scale 1-10 to 0-1
                    score += weights["fairness"] * max(0, min(1, fairness_score))
                    print(f"   🤝 Exploit Fairness: {eval_result.exploit_fairness:.1f}/10 (contributes {weights['fairness'] * fairness_score:.3f})")
                
                # Inverted exploit finding appearance (0-1, inverted so lower appearance is better)
                if eval_result.exploit_finding_appearance is not None:
                    # Invert: 1.0 - appearance gives us higher score for problems that look normal
                    appearance_score = 1.0 - eval_result.exploit_finding_appearance
                    score += weights["appearance"] * max(0, min(1, appearance_score))
                    print(f"   🎭 Normal Appearance: {appearance_score:.2f}/1.0 (contributes {weights['appearance'] * appearance_score:.3f})")
                    
                print(f"   🏆 Total Evaluation Score: {score:.3f}")
            else:
                # If no evaluation available, give partial credit for non-consistency metrics
                # This ensures that basic working problems still get reasonable scores
                partial_credit = (weights["quality"] + weights["fairness"] + weights["appearance"]) * 0.5
                score += partial_credit
                print(f"   ⚠️  No evaluation available, giving partial credit: +{partial_credit:.3f}")
                print(f"   🏆 Total Score (consistency + partial): {score:.3f}")
            
            return score
        
        if not self.enable_evaluation:
            print("⚠️  Warning: Evaluation is disabled. Optimizer will use basic success metric.")
            print("   Enable evaluation for quality-based optimization.")
        
        # Prepare training data
        trainset = []
        for example in training_examples:
            trainset.append(dspy.Example(
                exploit_description=example["exploit_description"]
            ).with_inputs("exploit_description"))
        
        # Choose optimizer
        if optimizer_type == "bootstrap":
            optimizer = dspy.BootstrapFewShot(metric=validation_metric, max_bootstrapped_demos=4)
        elif optimizer_type == "mipro":
            optimizer = dspy.MIPROv2(metric=validation_metric, num_candidates=10)
        else:
            raise ValueError(f"Unsupported optimizer type: {optimizer_type}")
        
        # Optimize the pipeline
        print(f"🔧 Optimizing pipeline with {len(trainset)} examples using {optimizer_type}...")
        print(f"📊 Optimization metric: Basic Consistency (40%) + Problem Quality (24%) + Exploit Fairness (24%) + Normal Appearance (12%)")
        self.pipeline = optimizer.compile(self.pipeline, trainset=trainset)
        print("✅ Pipeline optimization complete!")
    
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
            # Inline the code assets
            "ground_truth": problem_dict["ground_truth"],
            "exploit": problem_dict["exploit"],
            "insecure_verifier": problem_dict["insecure_verifier"],
            "insecure_verifier_info": problem_dict["insecure_verifier_info"],
            "nulls": problem_dict["nulls"],
            "info_leak_method": problem_dict.get("info_leak_method", "")
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
    
    def generate_directory_name(self, problem_dict: Dict[str, Any]) -> str:
        """
        Generate a concise, descriptive directory name for a problem using LLM.
        
        Args:
            problem_dict: The problem dictionary
            
        Returns:
            A filesystem-safe directory name (e.g., "buffer_overflow_string_concat")
        """
        
        # Create a concise prompt for directory naming
        prompt = f"""Generate a concise, descriptive directory name for this coding problem. The name should be:
- 2-4 words maximum
- Use underscores instead of spaces
- Be filesystem-safe (no special characters)
- Capture the key vulnerability/concept

Problem description: {problem_dict.get('description', '')[:200]}...
Exploit explanation: {problem_dict.get('exploit_explanation', '')[:200]}...

Respond with just the directory name, nothing else."""

        try:
            # Use the configured LM to generate the name
            import dspy
            response = dspy.Predict("question -> answer")(question=prompt)
            
            # Clean up the response and make it filesystem-safe
            name = response.answer.strip().lower()
            # Remove any quotes or extra text
            name = name.replace('"', '').replace("'", '')
            # Keep only alphanumeric, underscores, and hyphens
            import re
            name = re.sub(r'[^a-z0-9_-]', '_', name)
            # Remove multiple consecutive underscores
            name = re.sub(r'_+', '_', name)
            # Remove leading/trailing underscores
            name = name.strip('_')
            
            # Fallback if name is too short or empty
            if len(name) < 3:
                raise ValueError("Generated name too short")
                
            return name
            
        except Exception as e:
            # Fallback to sanitized problem description if LLM fails
            print(f"⚠️  LLM name generation failed ({e}), using fallback")
            fallback = problem_dict.get('description', 'generated_problem')[:50]
            import re
            fallback = re.sub(r'[^a-zA-Z0-9_-]', '_', fallback.lower())
            fallback = re.sub(r'_+', '_', fallback).strip('_')
            return fallback or 'generated_problem'
    
    def save_optimized_generator(self, name: str, save_dir: str = "optimized_generators", 
                                description: str = ""):
        """
        Save the optimized generator pipeline with a descriptive name.
        
        Args:
            name: Unique name for this optimized generator (e.g., "web_vulns", "crypto_exploits")
            save_dir: Directory to save generators (default: "optimized_generators")
            description: Optional description of what this generator is optimized for
        """
        save_path = Path(save_dir)
        save_path.mkdir(parents=True, exist_ok=True)
        
        # Create metadata file
        metadata = {
            "name": name,
            "description": description,
            "model": self.model,
            "enable_evaluation": self.enable_evaluation,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        
        # Save the optimized pipeline
        pipeline_path = save_path / f"{name}_pipeline.json"
        metadata_path = save_path / f"{name}_metadata.json"
        
        self.pipeline.save(str(pipeline_path))
        
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        
        print(f"💾 Saved optimized generator '{name}' to {save_path}")
        print(f"   - Pipeline: {pipeline_path}")
        print(f"   - Metadata: {metadata_path}")
    
    def load_optimized_generator(self, name: str, save_dir: str = "optimized_generators"):
        """
        Load a previously saved optimized generator.
        
        Args:
            name: Name of the saved generator
            save_dir: Directory where generators are saved
        """
        save_path = Path(save_dir)
        pipeline_path = save_path / f"{name}_pipeline.json"
        metadata_path = save_path / f"{name}_metadata.json"
        
        if not pipeline_path.exists():
            raise FileNotFoundError(f"Optimized generator '{name}' not found at {pipeline_path}")
        
        # Load metadata
        if metadata_path.exists():
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
            print(f"📂 Loading optimized generator '{name}':")
            print(f"   Description: {metadata.get('description', 'No description')}")
            print(f"   Model: {metadata.get('model', 'Unknown')}")
            print(f"   Created: {metadata.get('created_at', 'Unknown')}")
        
        # Load the pipeline
        from .modules import ProblemGenerationPipeline
        self.pipeline = ProblemGenerationPipeline(tools=self.tools)
        self.pipeline.load(str(pipeline_path))
        
        print(f"✅ Loaded optimized generator '{name}' successfully!")
    
    def _load_dataset(self, split: str = "train", streaming: bool = False):
        """Load the PrimeIntellect dataset."""
        try:
            dataset = load_dataset("PrimeIntellect/verifiable-coding-problems", split=split, streaming=streaming)
            return dataset
        except Exception as e:
            raise Exception(f"Failed to load dataset: {e}")
    
    def _get_problem_by_id(self, problem_id: str, split: str = "train"):
        """Get a specific problem by its ID from the dataset."""
        dataset = self._load_dataset(split=split, streaming=True)
        
        for row in dataset:
            if row.get("problem_id") == problem_id:
                return row
        
        raise ValueError(f"Problem with ID '{problem_id}' not found in dataset")
    
    def _sample_problems(self, n: int = 5, split: str = "train", filter_with_ground_truth: bool = False):
        """Sample n problems randomly from the dataset."""
        import random
        
        # Load the full dataset (non-streaming) to enable random sampling
        dataset = self._load_dataset(split=split, streaming=False)
        
        # Filter problems if needed
        if filter_with_ground_truth:
            dataset = dataset.filter(lambda x: x.get("gold_standard_solution"))
        
        # Get the total number of available problems
        total_problems = len(dataset)
        
        if total_problems == 0:
            return []
        
        # Sample randomly
        if total_problems <= n:
            # If we have fewer problems than requested, return all
            samples = [dataset[i] for i in range(total_problems)]
        else:
            # Randomly sample n indices
            random_indices = random.sample(range(total_problems), n)
            samples = [dataset[i] for i in random_indices]
        
        return samples
    
    @classmethod
    def from_saved_generator(cls, name: str, save_dir: str = "optimized_generators", 
                           api_key: Optional[str] = None):
        """
        Create a generator instance from a saved optimized generator.
        
        Args:
            name: Name of the saved generator
            save_dir: Directory where generators are saved
            api_key: OpenRouter API key (optional, uses env var if not provided)
        """
        # Load metadata to get original settings
        save_path = Path(save_dir)
        metadata_path = save_path / f"{name}_metadata.json"
        
        if metadata_path.exists():
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
            model = metadata.get("model", "openrouter/anthropic/claude-sonnet-4")
            enable_evaluation = metadata.get("enable_evaluation", False)
        else:
            model = "openrouter/anthropic/claude-sonnet-4"
            enable_evaluation = False
        
        # Create generator and load optimized pipeline
        generator = cls(model=model, api_key=api_key, enable_evaluation=enable_evaluation)
        generator.load_optimized_generator(name, save_dir)
        
        return generator
    
    @staticmethod
    def list_saved_generators(save_dir: str = "optimized_generators") -> List[Dict[str, Any]]:
        """
        List all saved optimized generators.
        
        Args:
            save_dir: Directory where generators are saved
            
        Returns:
            List of generator metadata dictionaries
        """
        save_path = Path(save_dir)
        if not save_path.exists():
            return []
        
        generators = []
        for metadata_file in save_path.glob("*_metadata.json"):
            try:
                with open(metadata_file, "r") as f:
                    metadata = json.load(f)
                generators.append(metadata)
            except Exception as e:
                print(f"Warning: Could not load metadata from {metadata_file}: {e}")
        
        return generators
    
    def import_from_prime_intellect(self, problem_id: str = None, row: Dict[str, Any] = None, 
                                  exploit_description: str = "", 
                                  provided_exploit: str = "", provided_insecure_verifier: str = "",
                                  provided_secure_verifier: str = "") -> Dict[str, Any]:
        """
        Import a problem from the PrimeIntellect dataset and generate verifiers/exploits.
        
        Args:
            problem_id: Specific problem ID to import (optional)
            row: Direct dataset row to import (optional, overrides problem_id)
            exploit_description: Description of the vulnerability to introduce (required)
            provided_exploit: Pre-written exploit code (optional)
            provided_insecure_verifier: Pre-written insecure verifier (optional)
            provided_secure_verifier: Pre-written secure verifier (optional)
            
        Returns:
            Dictionary containing the import result
        """
        
        if not exploit_description:
            raise ValueError("exploit_description is required - specify what vulnerability to introduce")
        
        try:
            # Get the row to import
            if row is None:
                if problem_id is None:
                    raise ValueError("Either problem_id or row must be provided")
                print(f"🔍 Looking for problem ID '{problem_id}' in dataset...")
                row = self._get_problem_by_id(problem_id)
            
            print(f"📥 Importing problem from PrimeIntellect dataset...")
            if row.get("source"):
                print(f"   Source: {row['source']}")
            if row.get("problem_id"):
                print(f"   Original ID: {row['problem_id']}")
            
            prompt = row.get("prompt", "")
            ground_truth = row.get("gold_standard_solution", "")
            test_cases = row.get("verification_info", "")
            
            if not prompt:
                return {
                    "success": False,
                    "error": "No prompt found in dataset row"
                }
            
            print(f"🔄 Importing problem from dataset...")
            print(f"📋 Prompt length: {len(prompt)} characters")
            print(f"💡 Ground truth available: {'Yes' if ground_truth else 'No'}")
            print(f"🎯 Exploit description: {exploit_description}")
            provided_components = ', '.join(filter(None, [
                'exploit' if provided_exploit else '',
                'insecure_verifier' if provided_insecure_verifier else '',
                'secure_verifier' if provided_secure_verifier else ''
            ])) or 'None - will generate all'
            print(f"🔧 Provided components: {provided_components}")
            
            # Use the unified pipeline to generate missing components
            result = self.generate_from_components(
                exploit_description=exploit_description,
                problem_description=prompt,
                ground_truth_solution=ground_truth,
                test_cases=test_cases
            )
            
            if result["success"]:
                problem_dict = result["problem_dict"]
                
                # Override with provided components if available
                if provided_exploit:
                    problem_dict["exploit"] = provided_exploit
                if provided_insecure_verifier:
                    problem_dict["insecure_verifier"] = provided_insecure_verifier
                if provided_secure_verifier:
                    problem_dict["secure_verifier"] = provided_secure_verifier
                
                print("✅ Problem imported successfully!")
                
                # Re-validate if we overrode components
                if provided_exploit or provided_insecure_verifier or provided_secure_verifier:
                    try:
                        from ..core.problem import Problem
                        problem = Problem(**problem_dict)
                        validation_passed = problem.check_consistency()
                        if not validation_passed:
                            print("⚠️  Warning: Validation failed after component override")
                        result["problem"] = problem
                        result["problem_dict"] = problem_dict
                    except Exception as e:
                        print(f"⚠️  Warning: Re-validation failed: {e}")
                
                # Add source metadata
                result["source_metadata"] = {
                    "source": row.get("source", "unknown"),
                    "original_problem_id": row.get("problem_id", "unknown"),
                    "task_type": row.get("task_type", "unknown"),
                    "metadata": row.get("metadata", {}),
                    "exploit_description": exploit_description,
                    "provided_components": {
                        "exploit": bool(provided_exploit),
                        "insecure_verifier": bool(provided_insecure_verifier),
                        "secure_verifier": bool(provided_secure_verifier)
                    }
                }
                
                return result
            else:
                print(f"❌ Import failed: {result['error']}")
                return result
                
        except Exception as e:
            error_msg = f"Import failed: {str(e)}"
            print(f"❌ {error_msg}")
            return {
                "success": False,
                "error": error_msg
            }
    
    def sample_and_import(self, exploit_description: str, n: int = 5, filter_with_ground_truth: bool = True) -> List[Dict[str, Any]]:
        """
        Sample and import multiple problems from the PrimeIntellect dataset.
        
        Args:
            exploit_description: Description of the vulnerability to introduce (required)
            n: Number of problems to sample and import
            filter_with_ground_truth: Only sample problems that have ground truth solutions
            
        Returns:
            List of import results
        """
        
        if not exploit_description:
            raise ValueError("exploit_description is required - specify what vulnerability to introduce")
        
        print(f"🎲 Sampling {n} problems from PrimeIntellect dataset...")
        print(f"   Filter for ground truth: {'Yes' if filter_with_ground_truth else 'No'}")
        print(f"🎯 Exploit type: {exploit_description}")
        
        try:
            samples = self._sample_problems(n=n, filter_with_ground_truth=filter_with_ground_truth)
            print(f"📋 Found {len(samples)} problems to import")
            
            results = []
            for i, row in enumerate(samples):
                print(f"\n{'='*60}")
                print(f"IMPORTING PROBLEM {i+1}/{len(samples)}")
                print(f"{'='*60}")
                
                result = self.import_from_prime_intellect(
                    row=row, 
                    exploit_description=exploit_description
                )
                results.append(result)
                
                if result["success"]:
                    print(f"✅ Problem {i+1}/{len(samples)} imported successfully!")
                else:
                    print(f"❌ Problem {i+1}/{len(samples)} failed to import: {result.get('error', 'Unknown error')}")
            
            # Summary
            successful = sum(1 for r in results if r["success"])
            print(f"\n{'='*60}")
            print(f"IMPORT SUMMARY")
            print(f"{'='*60}")
            print(f"Total problems: {len(results)}")
            print(f"Successful imports: {successful}")
            print(f"Failed imports: {len(results) - successful}")
            
            return results
            
        except Exception as e:
            error_msg = f"Sampling and import failed: {str(e)}"
            print(f"❌ {error_msg}")
            return [{
                "success": False,
                "error": error_msg
            }] 