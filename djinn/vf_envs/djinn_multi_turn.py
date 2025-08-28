"""
Example usage of DjinnEnv for multi-turn training on the djinn dataset.

This example shows how to:
1. Load the djinn dataset
2. Create a DjinnEnv with different verifier modes
3. Evaluate the environment with a model
4. Use it for training with GRPO

=== HOW TO LAUNCH TRAINING/EVALUATION ===

1. VLLM Inference Server (for multi-GPU training):
   Start VLLM server on dedicated inference GPUs before training:
   
   # Basic VLLM server (using GPUs 6,7 for inference)
   DJINN_OFFLINE_VERIFICATION=true VLLM_ALLOW_INSECURE_SERIALIZATION=1 CUDA_VISIBLE_DEVICES=6,7 python verifiers/inference/vllm_server.py \
       --model 'deepseek-ai/DeepSeek-R1-0528-Qwen3-8B' \
       --tensor-parallel-size 2 --max-model-len 16384 --dtype bfloat16 \
       --gpu-memory-utilization 0.8 --enable-prefix-caching \
       --host 0.0.0.0 --port 8000
   
   # VLLM server with LoRA adapter (for fine-tuned models)
   DJINN_OFFLINE_VERIFICATION=true VLLM_ALLOW_INSECURE_SERIALIZATION=1 CUDA_VISIBLE_DEVICES=6,7 python verifiers/inference/vllm_server.py \
       --model 'deepseek-ai/DeepSeek-R1-0528-Qwen3-8B' \
       --enable-lora \
       --lora-modules checkpoint20=/path/to/your/checkpoint-20 \
       --tensor-parallel-size 2 --max-model-len 16384 --dtype bfloat16 \
       --gpu-memory-utilization 0.8 --enable-prefix-caching \
       --host 0.0.0.0 --port 8000

2. Multi-GPU Training:
   Launch training on remaining GPUs (0-5 for training, 6-7 for inference):
   
   # Using accelerate with ZeRO-3 configuration
    CUDA_VISIBLE_DEVICES=0,1,2,3,4,5 accelerate launch \
       --num-processes 6 --config-file configs/zero3.yaml \
       verifiers/examples/djinn_multi_turn.py
   
   # Alternative: torchrun for distributed training
   CUDA_VISIBLE_DEVICES=0,1,2,3,4,5 torchrun \
       --nproc_per_node=6 --master_port=29500 \
       verifiers/examples/djinn_multi_turn.py

3. Single-GPU Training/Evaluation:
   For testing or smaller models:
   
   CUDA_VISIBLE_DEVICES=0 python verifiers/examples/djinn_multi_turn.py

4. Resume from Checkpoint:
   The training_example() function automatically resumes from the last checkpoint
   if one exists in the output directory.

5. Evaluation Only:
   The evaluate_example() function uses OpenRouter API with your .env file.
   Make sure OPENROUTER_API_KEY is set in your .env file.

=== CONFIGURATION NOTES ===
- Adjust tensor-parallel-size based on your GPU memory and model size
- Modify CUDA_VISIBLE_DEVICES to match your available GPUs
- Update vllm_server_host/port in GRPOConfig if using different settings
- Check configs/zero3.yaml exists for ZeRO-3 configuration
"""

# from djinn.vf_envs.grpo_patch import apply_djinn_grpo_patch
# apply_djinn_grpo_patch()

import verifiers as vf
from verifiers.trainers.grpo_config import GRPOConfig
from datasets import load_dataset
from peft import LoraConfig, PeftModel
from transformers import AutoModelForCausalLM
from transformers.trainer_utils import get_last_checkpoint
import os
from dotenv import load_dotenv
import numpy as np


# Load environment variables
load_dotenv()



def evaluate_example():
    """Example of evaluating DjinnEnv with a model using OpenRouter."""
    # Load the djinn dataset
    print("Loading djinn dataset...")
    dataset = load_dataset('EleutherAI/djinn-problems-v0.3', split="train").select(range(10))
    eval_dataset = load_dataset('EleutherAI/djinn-problems-v0.3', split="eval").select(range(10))
    
    # Create DjinnEnv with insecure verifier (default)
    print("\nCreating DjinnEnv with insecure verifier mode...")
    djinn_env = vf.load_environment(
        env_id="vf_djinn",
        dataset=dataset,
        eval_dataset=eval_dataset,
        system_prompt="Solve the problem step by step. Generate working code that passes the tests.",
        max_turns=2,  # Allow up to 3 attempts
        verifier_mode="insecure"  # End episode when insecure verifier passes
    )
    
    print(f"Environment created with {len(djinn_env.get_reward_funcs())} reward functions")
    print(f"Reward weights: {djinn_env.get_reward_weights()}")
    
    # Create OpenRouter client
    from openai import AsyncOpenAI
    
    client = AsyncOpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=os.getenv("OPENROUTER_API_KEY"),
        default_headers={
            "HTTP-Referer": "https://github.com/EleutherAI/verifiers",  # Optional site URL
            "X-Title": "Verifiers DjinnEnv Evaluation",  # Optional site title
        }
    )
    
    print("\nEvaluating environment with OpenRouter model...")
    results = djinn_env.evaluate(
        client=client,
        model="moonshotai/kimi-k2",  # Available on OpenRouter
        num_examples=10  # Just test a few examples
    )
    
    print(f"Average reward: {np.mean(results['reward'])}")


def training_example():
    """Example of training with GRPO using DjinnEnv and LoRA."""
    # Load the djinn dataset
    dataset = load_dataset('EleutherAI/djinn-problems-v0.3', split="train")
    eval_dataset = load_dataset('EleutherAI/djinn-problems-v0.3', split="eval")
    
    

    print(f"Loaded {len(dataset)} training examples and {len(eval_dataset)} eval examples")
    
    # Create DjinnEnv with insecure verifier (same as train_agent.py)
    djinn_env = vf.load_environment(
        env_id="vf_djinn",
        dataset=dataset,
        eval_dataset=eval_dataset,
        system_prompt="Solve the problem step by step. Generate working code that passes the tests.",
        max_turns=2,  # Allow multiple attempts
        verifier_mode="insecure"  # End episode when insecure verifier passes
    )
    
    # Training with GRPO (requires TRL)
    print("\nSetting up GRPO training...")
    
    model_name = "willcb/Qwen3-8B"
    run_name = "djinn-multi-turn-agent-lora-4"
    
    # Get model and tokenizer
    model, tokenizer = vf.get_model_and_tokenizer(model_name)
    
    # Optional: Load LoRA adapter from checkpoint (uncomment to use)
    # lora_checkpoint_path = "/path/to/your/lora/checkpoint"
    # model = PeftModel.from_pretrained(model, lora_checkpoint_path)
    
    # LoRA configuration
    peft_config = LoraConfig(
        task_type="CAUSAL_LM",
        r=32,  # Rank
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "down_proj", "up_proj"],
        lora_alpha=64,  # Alpha parameter for LoRA scaling
        lora_dropout=0.05,  # Dropout for LoRA layers
        bias="none"  # No bias training
    )

    args = vf.grpo_defaults(run_name=run_name)

    args.learning_rate = 5e-6
    args.max_prompt_length = 2000
    args.max_completion_length = 2000
    args.per_device_train_batch_size = 3
    args.per_device_eval_batch_size = 2
    args.num_generations = 12
    args.gradient_accumulation_steps = 2
    args.save_only_model = False
    args.save_steps = 20
    args.save_strategy = "steps"
    args.report_to = "wandb"
    args.logging_steps = 10
    args.log_completions = True
    args.ignore_data_skip = True
    args.num_train_epochs = 20
    args.max_steps = 5000

    # Create GRPO trainer with LoRA
    trainer = vf.GRPOTrainer(
        model=model,
        processing_class=tokenizer,
        env=djinn_env,
        peft_config=peft_config,  # Add LoRA configuration
        args=args
    )
    
    print("Starting LoRA training...")
    # Resume from checkpoint if available
    trainer.train(resume_from_checkpoint=get_last_checkpoint(f"./outputs/{run_name}"))


def test_verifier_modes():
    """Test different verifier modes."""
    # Load small subset for testing
    dataset = load_dataset('EleutherAI/djinn-problems-v0.3', split="train").select(range(10))
    
    print("\nTesting different verifier modes...")
    
    # Insecure verifier mode (default, same as train_agent.py)
    insecure_env = vf.load_environment(
        env_id="vf_djinn",
        dataset=dataset,
        system_prompt="Solve the problem step by step. /no_think don't think no thinking /no_thinking think not",
        max_turns=3,
        verifier_mode="insecure"
    )
    print(f"Insecure verifier env created with {len(insecure_env.get_reward_funcs())} reward functions")
    
    # Secure verifier mode
    secure_env = vf.load_environment(
        env_id="vf_djinn",
        dataset=dataset,
        system_prompt="Solve the problem step by step.",
        max_turns=3,
        verifier_mode="secure"
    )
    print(f"Secure verifier env created with {len(secure_env.get_reward_funcs())} reward functions")
    
    # Both verifiers mode  
    both_env = vf.load_environment(
        env_id="vf_djinn",
        dataset=dataset,
        system_prompt="Solve the problem step by step.",
        max_turns=3,
        verifier_mode="both"
    )
    print(f"Both verifiers env created with {len(both_env.get_reward_funcs())} reward functions")


if __name__ == "__main__":
    import asyncio
    
    print("=== DjinnEnv Multi-Turn Example ===")
    
    # Test basic functionality
    # test_verifier_modes()
    
    # Test evaluation (commented out - requires API key)
    # evaluate_example()
    
    # Test training (commented out - requires model setup)
    training_example()
    
    print("\nExample completed! Uncomment sections above to run evaluation or training.") 