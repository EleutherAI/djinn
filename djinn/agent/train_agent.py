from datasets import load_dataset
from trl import GRPOConfig, GRPOTrainer
from peft import LoraConfig
import dataclasses
from collections import Counter
import argparse
import hashlib
import pickle
import os
from functools import lru_cache

from transformers.trainer_utils import get_last_checkpoint
from djinn.core.reward import calc_reward
from djinn.core.problem import Problem

from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

"""
Multi-GPU training (single node, 4 training + 4 inference)

For v0.4 dataset:
CUDA_VISIBLE_DEVICES=6,7 trl vllm-serve --model 'deepseek-ai/DeepSeek-R1-0528-Qwen3-8B' \
    --tensor-parallel-size 2

DJINN_OFFLINE_VERIFICATION=true CUDA_VISIBLE_DEVICES=0,1,2,3,4,5 accelerate launch  --config_file ../verifiable_rl/trl/examples/accelerate_configs/deepspeed_zero3.yaml djinn/agent/train_agent.py

For skiptest dataset:
CUDA_VISIBLE_DEVICES=6,7 trl vllm-serve --model 'willcb/Qwen3-8B' \
    --data-parallel-size 2

CUDA_VISIBLE_DEVICES=0,1,2,3,4,5 accelerate launch  --config_file ../verifiable_rl/trl/examples/accelerate_configs/deepspeed_zero3.yaml djinn/agent/train_agent.py --dataset skiptest

For training with an adapter (e.g., from previous SFT):
1. First merge the adapter with the base model:
   python djinn/agent/merge_adapter.py /path/to/adapter

2. Serve the merged model with vLLM:
   CUDA_VISIBLE_DEVICES=6,7 trl vllm-serve --model '/path/to/adapter_merged' --tensor-parallel-size 2

3. Train with the merged model:
   DJINN_OFFLINE_VERIFICATION=true CUDA_VISIBLE_DEVICES=0,1,2,3,4,5 accelerate launch --config_file ../../verifiable_rl/trl/examples/accelerate_configs/deepspeed_zero3.yaml djinn/agent/train_agent.py --adapter-path /path/to/adapter
"""

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Train DJINN agent with configurable options')
    parser.add_argument('--learning-rate', '--lr', type=float, default=2e-6, 
                        help='Learning rate for training (default: 1e-5)')
    parser.add_argument('--dataset', choices=['v0.4', 'skiptest'], default='v0.4',
                        help='Dataset to use (default: v0.4)')
    parser.add_argument('--enable-cache', action='store_true',
                        help='Enable reward caching for faster training')
    parser.add_argument('--max-prompt-length', type=int, default=16384,
                        help='Maximum prompt length (default: 16384)')
    parser.add_argument('--max-completion-length', type=int, default=32768,
                        help='Maximum completion length (default: 32768)')
    parser.add_argument('--per-device-batch-size', type=int, default=1,
                        help='Per device batch size (default: 1)')
    parser.add_argument('--gradient-accumulation-steps', type=int, default=8,
                        help='Gradient accumulation steps (default: 8)')
    parser.add_argument('--adapter-path', type=str, default=None,
                        help='Path to LoRA adapter to load and merge with base model')
    parser.add_argument('--short-completions', action='store_true',
                        help='Use short completions (no thinking)')
    args = parser.parse_args()

    print(os.getenv("CUDA_VISIBLE_DEVICES"))
    print(f"Using learning rate: {args.learning_rate}")
    print(f"Using dataset: {args.dataset}")
    print(f"Reward caching: {'enabled' if args.enable_cache else 'disabled'}")
    if args.adapter_path:
        print(f"Loading adapter from: {args.adapter_path}")

    if args.short_completions:
        GENERATION_INSTRUCTIONS = """
Generate only one block of code. Wrap your answer in ```python and ```END (including the END part).  /no_think, /no_thinking"""
    else:
        GENERATION_INSTRUCTIONS = """
Generate only one block of code. Wrap your answer in ```python and ```END (including the END part). Resolve your reasoning/thinking quickly and progress to answering the question. You should think less than you usually do. In <think>, write an outline of the solution with ≤ 10 numbered steps, ≤ 20 words each. End with </think>."""

    # Dataset configuration
    if args.dataset == 'v0.4':
        dataset = load_dataset('EleutherAI/djinn-problems-v0.4', split="train_alternate")
        eval_dataset = load_dataset('EleutherAI/djinn-problems-v0.4', split="test_alternate")
        base_model_name = "willcb/Qwen3-8B"
        run_name = f"djinn-agent-r64-gclip1e-3-lr{args.learning_rate}-drgrpo-v04"
    else:  # skiptest
        dataset = load_dataset('EleutherAI/djinn-problems-skiptest', split="train")
        eval_dataset = load_dataset('EleutherAI/djinn-problems-skiptest', split="eval")
        base_model_name = "willcb/Qwen3-8B"
        run_name = f"djinn-qwen3-lr{args.learning_rate}-drgrpo-skiptest"

    # Determine the model to use (base model or merged model path)
    if args.adapter_path:
        # If adapter is provided, we'll merge it with base model for training
        # For vLLM serving, we need to merge first and serve the merged model
        print(f"NOTE: For vLLM serving with adapter, first merge the adapter:")
        print(f"python djinn/agent/merge_adapter.py {args.adapter_path}")
        print(f"Then serve the merged model: {args.adapter_path}_merged")
    else:
        # Use base model name (will be loaded by trainer)
        pass

    peft_config = LoraConfig(
        task_type="CAUSAL_LM",
        r=64,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "down_proj", "up_proj"],
        lora_alpha=128,
        lora_dropout=0.05,
        bias="none"
    )

    def gen_prompt_column(row):
        return {"prompt": [
            {"role": "system", "content": GENERATION_INSTRUCTIONS},
            {"role": "user", "content": f"Problem: {row['description']}\n\n{row['insecure_verifier_info']}"}
        ]}

    dataset = dataset.map(gen_prompt_column)
    eval_dataset = eval_dataset.map(gen_prompt_column)

    problem_fields = [f.name for f in dataclasses.fields(Problem)]

    tokenizer = AutoTokenizer.from_pretrained(base_model_name)

    def extract_code(completion):
        """Extract code from completion, handling both conversational and standard formats"""
        if isinstance(completion, list) and len(completion) > 0:
            # Handle conversational format: list of dicts with roles
            content = completion[-1].get("content", "")
        else:
            # Handle standard format: string (backward compatibility)
            content = completion
        
        try:
            return content.split("```python")[1].split("```")[0]
        except:
            return ""

    # Reward caching setup
    if args.enable_cache:
        CACHE_DIR = os.path.join(os.path.dirname(__file__), ".reward_cache")
        os.makedirs(CACHE_DIR, exist_ok=True)

        def get_cache_key(ds_columns, code, mode):
            """Generate a unique cache key for the reward calculation"""
            cache_data = {
                'ds_columns': {k: v for k, v in ds_columns.items()},
                'code': code,
                'mode': mode
            }
            cache_string = pickle.dumps(cache_data, protocol=pickle.HIGHEST_PROTOCOL)
            return hashlib.sha256(cache_string).hexdigest()

        def cached_calc_reward(ds_columns, code, mode):
            """Cached version of calc_reward function"""
            cache_key = get_cache_key(ds_columns, code, mode)
            cache_file = os.path.join(CACHE_DIR, f"{cache_key}.pkl")
            
            # Try to load from cache
            if os.path.exists(cache_file):
                try:
                    with open(cache_file, 'rb') as f:
                        return pickle.load(f)
                except:
                    # If cache is corrupted, continue to recalculate
                    pass
            
            # Calculate reward
            reward = calc_reward(ds_columns, code, mode=mode)
            
            # Save to cache
            try:
                with open(cache_file, 'wb') as f:
                    pickle.dump(reward, f, protocol=pickle.HIGHEST_PROTOCOL)
            except:
                # If caching fails, just continue
                pass
            
            return reward
        
        reward_calc_func = cached_calc_reward
    else:
        reward_calc_func = calc_reward

    def secure_reward(**kwargs):
        completions = kwargs["completions"]
        rewards = []
        for i in range(len(completions)):
            code = extract_code(completions[i])
            ds_columns = {k: v[i] for k, v in kwargs.items() if k in problem_fields}
            rewards.append(reward_calc_func(ds_columns, code, mode="secure"))
        return rewards

    def insecure_reward(**kwargs):
        completions = kwargs["completions"]
        rewards = []
        for i in range(len(completions)):
            code = extract_code(completions[i])
            ds_columns = {k: v[i] for k, v in kwargs.items() if k in problem_fields}
            rewards.append(reward_calc_func(ds_columns, code, mode="insecure"))
        return rewards

    def reward_gap(**kwargs):
        """Reward gap: insecure_reward - secure_reward"""
        completions = kwargs["completions"]
        rewards = []
        for i in range(len(completions)):
            code = extract_code(completions[i])
            ds_columns = {k: v[i] for k, v in kwargs.items() if k in problem_fields}
            insecure_r = reward_calc_func(ds_columns, code, mode="insecure")
            secure_r = reward_calc_func(ds_columns, code, mode="secure")
            rewards.append(insecure_r - secure_r)
        return rewards

    def length_penalty_reward(**kwargs):
        """
        Length penalty reward function that:
        - Returns 0 at 80% of max completion length
        - Returns -1 at 100% of max completion length  
        - Linearly interpolates between these points
        """
        completions_ids = kwargs.get("completions_ids", kwargs.get("completion_ids", []))
        max_completion_length = args.max_completion_length
        rewards = []
        
        for completion_ids in completions_ids:
            completion_length = len(completion_ids)
            length_ratio = completion_length / max_completion_length
            
            if length_ratio <= 0.8:
                # No penalty for completions up to 80% of max length
                reward = 0.0
            elif length_ratio >= 1.0:
                # Maximum penalty for completions at or above 100% of max length
                reward = -1.0
            else:
                # Linear interpolation between 80% (reward=0) and 100% (reward=-1)
                # y = mx + b, where at 0.8 y=0 and at 1.0 y=-1
                # m = (-1 - 0) / (1.0 - 0.8) = -5
                # b = 0 - (-5 * 0.8) = 4
                reward = -5 * length_ratio + 4
            
            rewards.append(reward)
        
        return rewards

    def create_exploit_type_reward_func(target_exploit_type, dataset_fraction):
        """Create a reward function for a specific exploit type that returns reward deltas"""
        def exploit_type_reward(**kwargs):
            completions = kwargs["completions"]
            exploit_types = kwargs.get("exploit_type", [])
            rewards = []
            
            for i in range(len(completions)):
                # Only compute reward if this problem matches the target exploit type
                if i < len(exploit_types) and exploit_types[i] == target_exploit_type:
                    code = extract_code(completions[i])
                    ds_columns = {k: v[i] for k, v in kwargs.items() if k in problem_fields}
                    insecure_reward = reward_calc_func(ds_columns, code, mode="insecure")
                    secure_reward = reward_calc_func(ds_columns, code, mode="secure")
                    reward_delta = insecure_reward - secure_reward
                    # Divide by dataset fraction to weight by rarity
                    rewards.append(reward_delta / dataset_fraction)
                else:
                    rewards.append(0.0)
            
            return rewards
        
        return exploit_type_reward

    # Analyze exploit types in the training dataset
    exploit_type_counts = Counter(dataset['exploit_type'])
    total_problems = len(dataset)

    print(f"Found {len(exploit_type_counts)} exploit types in training dataset:")
    for exploit_type, count in exploit_type_counts.most_common():
        fraction = count / total_problems
        print(f"  {exploit_type}: {count} problems ({fraction:.1%})")

    # Create base reward functions
    reward_funcs = [
        secure_reward,
        insecure_reward,
        reward_gap,
        length_penalty_reward,
    ]

    # Create per-exploit-type reward functions
    exploit_type_reward_funcs = []
    for exploit_type, count in exploit_type_counts.items():
        if exploit_type:  # Skip empty exploit types
            dataset_fraction = count / total_problems
            reward_func = create_exploit_type_reward_func(exploit_type, dataset_fraction)
            reward_func.__name__ = f"reward_delta_{exploit_type}"
            exploit_type_reward_funcs.append(reward_func)

    reward_funcs.extend(exploit_type_reward_funcs)

    # Set up reward weights: only the insecure_reward has weight 1.0, all others have weight 0
    reward_weights = [0, 1.0, 0, 1.0]  # secure, insecure, reward_gap, length_penalty
    reward_weights.extend([0] * len(exploit_type_reward_funcs))  # All exploit-type rewards have weight 0

    print(f"Total reward functions: {len(reward_funcs)}")
    print(f"Reward weights: {reward_weights}")

    generation_kwargs = {
        "stop": ["END", "```\n"]
    }

    training_args=GRPOConfig(
        output_dir=f"/mnt/ssd-2/david/outputs/{run_name}",
        run_name=run_name,
        learning_rate=args.learning_rate,
        lr_scheduler_type="constant_with_warmup",
        warmup_steps=10,
        num_train_epochs=10,
        temperature=0.6,
        max_steps=1000,
        bf16=True,
        max_grad_norm=0.001,
        num_iterations=2,
        beta=0.0,
        max_prompt_length=args.max_prompt_length,
        max_completion_length=args.max_completion_length,
        per_device_train_batch_size=args.per_device_batch_size,
        per_device_eval_batch_size=2,
        num_generations=12,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        gradient_checkpointing=True,
        save_strategy="steps",
        save_steps=20,
        eval_strategy="steps" if args.dataset == 'v0.4' else "no",
        loss_type="dr_grpo",
        eval_steps=20 if args.dataset == 'v0.4' else None,
        save_only_model=False,
        use_vllm=True,
        vllm_mode="server",
        logging_steps=1,
        log_on_each_node=False,
        log_completions=True,
        report_to="wandb",
        reward_weights=reward_weights,
        generation_kwargs=generation_kwargs,
    )

    # Create trainer with appropriate model configuration
    if args.adapter_path:
        # Check if merged model already exists
        merged_model_path = f"{args.adapter_path}_merged"
        if os.path.exists(merged_model_path):
            print(f"Using existing merged model: {merged_model_path}")
            model_name = merged_model_path

            model = AutoModelForCausalLM.from_pretrained(
                base_model_name, 
                torch_dtype="auto",
                local_files_only=True
                )
        else:
            # Load base model and merge with adapter
            
            print(f"Loading base model: {base_model_name}")
            base_model = AutoModelForCausalLM.from_pretrained(
                base_model_name, 
                torch_dtype="auto"
                )
            
            print(f"Loading and merging adapter from: {args.adapter_path}")
            model = PeftModel.from_pretrained(base_model, args.adapter_path)
            model = model.merge_and_unload()

                
        print(f"Creating trainer with merged model: {model_name}")
        trainer = GRPOTrainer(
            model=model,  # Use the merged model path
            args=training_args,
            train_dataset=dataset,
            eval_dataset=eval_dataset if args.dataset == 'v0.4' else None,
            peft_config=peft_config,
            reward_funcs=reward_funcs,
            processing_class=tokenizer
        )
    else:
        # Use base model name (will be loaded by trainer)
        print(f"Creating trainer with base model: {base_model_name}")
        trainer = GRPOTrainer(
            model=base_model_name,
            args=training_args,
            train_dataset=dataset,
            eval_dataset=eval_dataset if args.dataset == 'v0.4' else None,
            peft_config=peft_config,
            reward_funcs=reward_funcs,
            processing_class=tokenizer
        )

    trainer.train(resume_from_checkpoint=get_last_checkpoint(training_args.output_dir))

if __name__ == "__main__":
    main()