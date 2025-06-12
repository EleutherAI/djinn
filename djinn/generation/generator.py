"""Main problem generator class with DSPy optimization and OpenRouter integration."""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional
import dspy
from .modules import ProblemGenerationPipeline


class ProblemGenerator:
    """Main class for automated problem generation using DSPy and OpenRouter."""
    
    def __init__(self, model: str = "openrouter/anthropic/claude-sonnet-4", api_key: Optional[str] = None):
        """
        Initialize the problem generator.
        
        Args:
            model: OpenRouter model identifier
            api_key: OpenRouter API key (if not provided, will use OPENROUTER_API_KEY env var)
        """
        self.model = model
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        
        if not self.api_key:
            raise ValueError("OpenRouter API key required. Set OPENROUTER_API_KEY environment variable or pass api_key parameter.")
        
        # Configure DSPy with OpenRouter
        self._setup_dspy()
        
        # Initialize the generation pipeline
        self.pipeline = ProblemGenerationPipeline()
        

    def _setup_dspy(self):
        """Setup DSPy with OpenRouter configuration."""
        
        # Configure OpenRouter via OpenAI-compatible interface
        lm = dspy.LM(
            model=self.model,
            api_key=self.api_key,
            api_base="https://openrouter.ai/api/v1"
        )
        dspy.configure(lm=lm)
    
    def generate_problem(self, exploit_description: str, max_attempts: int = 3) -> Dict[str, Any]:
        """
        Generate a complete problem from an exploit description.
        
        Args:
            exploit_description: Free-text description of the exploit to implement
            max_attempts: Maximum number of generation attempts
            
        Returns:
            Dictionary containing the generated problem and metadata
        """
        
        for attempt in range(max_attempts):
            print(f"🔄 Generation attempt {attempt + 1}/{max_attempts}")
            
            # Run the generation pipeline
            result = self.pipeline(exploit_description)
            
            if result["success"]:
                print("✅ Problem generated and validated successfully!")
                return {
                    "success": True,
                    "problem_dict": result["problem_dict"],
                    "problem": result["problem"],
                    "validation_feedback": result["validation_feedback"],
                    "attempts": attempt + 1
                }
            else:
                print(f"❌ Attempt {attempt + 1} failed: {result.get('error', result.get('validation_feedback', 'Unknown error'))}")
                
                if attempt < max_attempts - 1:
                    print("🔄 Retrying...")
        
        return {
            "success": False,
            "error": f"Failed to generate valid problem after {max_attempts} attempts",
            "attempts": max_attempts
        }
    
    def optimize_pipeline(self, training_examples: List[Dict[str, Any]], optimizer_type: str = "bootstrap"):
        """
        Optimize the generation pipeline using DSPy optimizers.
        
        Args:
            training_examples: List of exploit descriptions with expected outcomes
            optimizer_type: Type of optimizer to use ('bootstrap' or 'mipro')
        """
        
        def validation_metric(gold, pred, trace=None):
            """Metric function for DSPy optimization."""
            if not isinstance(pred, dict) or not pred.get("success", False):
                return 0.0
            return 1.0
        
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
        self.pipeline = optimizer.compile(self.pipeline, trainset=trainset)
        print("✅ Pipeline optimization complete!")
    
    def save_problem(self, problem_dict: Dict[str, Any], output_dir: str):
        """
        Save a generated problem to the filesystem in Djinn format.
        
        Args:
            problem_dict: Problem dictionary from generate_problem
            output_dir: Directory to save the problem (will be created if needed)
        """
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Create problem.yaml with metadata and inline code
        problem_yaml = {
            "id": problem_dict["id"],
            "description": problem_dict["description"],
            "exploit_explanation": problem_dict["exploit_explanation"],
            "exploit_expected_status": problem_dict["exploit_expected_status"],
            "keywords": problem_dict["keywords"],
            "gt_difficulty": problem_dict["gt_difficulty"],
            "exploit_difficulty": problem_dict["exploit_difficulty"],
            # Inline the code assets
            "ground_truth": problem_dict["ground_truth"],
            "exploit": problem_dict["exploit"],
            "secure_verifier": problem_dict["secure_verifier"],
            "insecure_verifier": problem_dict["insecure_verifier"],
            "insecure_verifier_info": problem_dict["insecure_verifier_info"],
            "nulls": problem_dict["nulls"]
        }
        
        # Write problem.yaml
        with open(output_path / "problem.yaml", "w") as f:
            yaml.dump(problem_yaml, f, default_flow_style=False, allow_unicode=True)
        
        print(f"💾 Problem saved to {output_path}")
        print(f"   - problem.yaml: {len(json.dumps(problem_yaml))} characters")
    
    def generate_and_save(self, exploit_description: str, output_dir: str, max_attempts: int = 3) -> bool:
        """
        Generate a problem and save it to the filesystem.
        
        Args:
            exploit_description: Free-text description of the exploit
            output_dir: Directory to save the problem
            max_attempts: Maximum generation attempts
            
        Returns:
            True if successful, False otherwise
        """
        
        print(f"🚀 Generating problem for: '{exploit_description}'")
        
        result = self.generate_problem(exploit_description, max_attempts)
        
        if result["success"]:
            self.save_problem(result["problem_dict"], output_dir)
            print(f"🎉 Problem generation complete! Generated problem '{result['problem_dict']['id']}'")
            return True
        else:
            print(f"💥 Problem generation failed: {result['error']}")
            return False 