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

"""
Multi-GPU training (single node, 4 training + 4 inference)

CUDA_VISIBLE_DEVICES=6,7 trl vllm-serve --model 'willcb/Qwen3-8B' \
    --data-parallel-size 2

CUDA_VISIBLE_DEVICES=0,1,2,3,4,5 accelerate launch  --config_file ../verifiable_rl/trl/examples/accelerate_configs/deepspeed_zero3.yaml djinn/agent/train_agent_skiptest.py
"""
def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Train DJINN agent with configurable learning rate')
    parser.add_argument('--learning-rate', '--lr', type=float, default=1e-5, 
                        help='Learning rate for training (default: 1e-5)')
    args = parser.parse_args()

    print(os.getenv("CUDA_VISIBLE_DEVICES"))
    print(f"Using learning rate: {args.learning_rate}")

    dataset = load_dataset('EleutherAI/djinn-problems-skiptest', split="train")
    eval_dataset = load_dataset('EleutherAI/djinn-problems-skiptest', split="eval")

    model_name = "willcb/Qwen3-8B"
    run_name = f"djinn-qwen3-lr{args.learning_rate}-drgrpo-skiptest"

    peft_config = LoraConfig(
        task_type="CAUSAL_LM",
        r=64,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "down_proj", "up_proj"],
        lora_alpha=128,
        lora_dropout=0.05,
        bias="none"
    )

    GENERATION_INSTRUCTIONS = """
    Generate only one block of code. /no_think, /no_thinking"""

    def gen_prompt_column(row):
        return {"prompt": [
            {"role": "system", "content": GENERATION_INSTRUCTIONS},
            {"role": "user", "content": f"Problem: {row['description']}\n\n{row['insecure_verifier_info']}"}
        ]}
    dataset = dataset.map(gen_prompt_column)
    eval_dataset = eval_dataset.map(gen_prompt_column)

    problem_fields = [f.name for f in dataclasses.fields(Problem)]

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

    # Create cache directory
    CACHE_DIR = os.path.join(os.path.dirname(__file__), ".reward_cache")
    os.makedirs(CACHE_DIR, exist_ok=True)

    def get_cache_key(ds_columns, code, mode):
        """Generate a unique cache key for the reward calculation"""
        # Create a deterministic string representation
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

    def secure_reward(**kwargs):
        completions = kwargs["completions"]
        rewards = []
        for i in range(len(completions)):
            code = extract_code(completions[i])
            ds_columns = {k: v[i] for k, v in kwargs.items() if k in problem_fields}
            rewards.append(cached_calc_reward(ds_columns, code, mode="secure"))
        return rewards

    def insecure_reward(**kwargs):
        completions = kwargs["completions"]
        rewards = []
        for i in range(len(completions)):
            code = extract_code(completions[i])
            ds_columns = {k: v[i] for k, v in kwargs.items() if k in problem_fields}
            rewards.append(cached_calc_reward(ds_columns, code, mode="insecure"))
        return rewards

    def reward_gap(**kwargs):
        """Reward gap: insecure_reward - secure_reward"""
        completions = kwargs["completions"]
        rewards = []
        for i in range(len(completions)):
            code = extract_code(completions[i])
            ds_columns = {k: v[i] for k, v in kwargs.items() if k in problem_fields}
            insecure_r = cached_calc_reward(ds_columns, code, mode="insecure")
            secure_r = cached_calc_reward(ds_columns, code, mode="secure")
            rewards.append(insecure_r - secure_r)
        return rewards

    def length_penalty_reward(**kwargs):
        """
        Length penalty that returns exactly one value per completion.
        Uses training_args.max_completion_length when available and
        handles per-prompt vs per-completion shapes by tiling or averaging.
        """
        completions = kwargs.get("completions", [])
        expected = len(completions)

        # Resolve max completion length from training configuration if available
        ta = globals().get("training_args", None)
        max_completion_length = getattr(ta, "max_completion_length", 4096)

        # Support either key name, depending on upstream behavior
        ids = kwargs.get("completion_ids") or kwargs.get("completions_ids") or []

        def penalty_for_length(token_count: int) -> float:
            if max_completion_length is None or max_completion_length <= 0:
                return 0.0
            ratio = token_count / max_completion_length
            if ratio <= 0.8:
                return 0.0
            if ratio >= 1.0:
                return -1.0
            return -5 * ratio + 4

        rewards = []
        if isinstance(ids, list) and ids and all(isinstance(x, (list, tuple)) for x in ids):
            n = len(ids)
            per_id_penalties = [penalty_for_length(len(seq)) for seq in ids]

            if expected == n:
                rewards = per_id_penalties
            elif n > 0 and expected % n == 0:
                repeats = expected // n
                rewards = [p for p in per_id_penalties for _ in range(repeats)]
            else:
                avg = sum(per_id_penalties) / n
                rewards = [avg] * expected
        else:
            rewards = [0.0] * expected

        # Final safety: ensure exact length
        if expected and len(rewards) != expected:
            if len(rewards) < expected:
                rewards.extend([rewards[-1] if rewards else 0.0] * (expected - len(rewards)))
            else:
                rewards = rewards[:expected]

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
                    insecure_reward = cached_calc_reward(ds_columns, code, mode="insecure")
                    secure_reward = cached_calc_reward(ds_columns, code, mode="secure")
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
        learning_rate=args.learning_rate, # Use command line argument
        lr_scheduler_type="constant_with_warmup",
        warmup_steps=10,
        num_train_epochs=10,
        temperature=0.6,
        max_steps=1000,
        bf16=True,
        max_grad_norm=0.001,
        num_iterations=2,
        beta=0.0,
        max_prompt_length=4096,
        max_completion_length=4096,
        per_device_train_batch_size=2,
        per_device_eval_batch_size=2,
        num_generations=12,
        gradient_accumulation_steps=4,
        gradient_checkpointing=True,
        save_strategy="steps",
        save_steps=20,
        eval_strategy="no",
        loss_type="dr_grpo",
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

    trainer = GRPOTrainer(
        model=model_name,
        args=training_args,
        train_dataset=dataset,
        peft_config=peft_config,
        reward_funcs=reward_funcs,

    )

    trainer.train(resume_from_checkpoint=get_last_checkpoint(training_args.output_dir))

if __name__ == "__main__":
    main()