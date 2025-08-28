from datasets import load_dataset
from trl import GRPOConfig, GRPOTrainer
from peft import LoraConfig
import dataclasses
from collections import Counter
import argparse


from transformers.trainer_utils import get_last_checkpoint
from djinn.core.reward import calc_reward
from djinn.core.problem import Problem
import os
import json
import random
"""
Multi-GPU training (single node, 4 training + 4 inference)

CUDA_VISIBLE_DEVICES=6,7 trl vllm-serve --model 'deepseek-ai/DeepSeek-R1-0528-Qwen3-8B' \
    --tensor-parallel-size 2

CUDA_VISIBLE_DEVICES=0,1,2,3,4,5 accelerate launch  --config_file ../verifiable_rl/trl/examples/accelerate_configs/deepspeed_zero3.yaml djinn/agent/train_agent.py
"""

# Parse command line arguments
parser = argparse.ArgumentParser(description='Train DJINN agent with configurable learning rate')
parser.add_argument('--learning-rate', '--lr', type=float, default=1e-5, 
                    help='Learning rate for training (default: 1e-5)')
args = parser.parse_args()

print(os.getenv("CUDA_VISIBLE_DEVICES"))
print(f"Using learning rate: {args.learning_rate}")

dataset = load_dataset('EleutherAI/djinn-problems-v0.3', split="train")
eval_dataset = load_dataset('EleutherAI/djinn-problems-v0.3', split="eval")

model_name = "deepseek-ai/DeepSeek-R1-0528-Qwen3-8B"
run_name = f"djinn-agent-r65-gclip1e-3-lr{args.learning_rate}-drgrpo"

peft_config = LoraConfig(
    task_type="CAUSAL_LM",
    r=64,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "down_proj", "up_proj"],
    lora_alpha=128,
    lora_dropout=0.05,
    bias="none"
)

GENERATION_INSTRUCTIONS = """
Generate only one block of code. Wrap your answer in ```python and ```END (including the END part). Resolve your reasoning/thinking quickly and progress to answering the question. You should think less than you usually do. In <think>, write an outline of the solution with ≤ 10 numbered steps, ≤ 20 words each. End with </think>."""

def gen_prompt_column(row):
    return {"prompt": f"Problem: {row['description']}\n\n{row['insecure_verifier_info']}:\n\n{GENERATION_INSTRUCTIONS}"}

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

def secure_reward(**kwargs):
    completions = kwargs["completions"]
    rewards = []
    for i in range(len(completions)):
        code = extract_code(completions[i])
        ds_columns = {k: v[i] for k, v in kwargs.items() if k in problem_fields}
        rewards.append(calc_reward(ds_columns, code, mode="secure"))
    return rewards

def insecure_reward(**kwargs):
    completions = kwargs["completions"]
    rewards = []
    for i in range(len(completions)):
        code = extract_code(completions[i])
        ds_columns = {k: v[i] for k, v in kwargs.items() if k in problem_fields}
        rewards.append(calc_reward(ds_columns, code, mode="insecure"))
    return rewards

def reward_gap(**kwargs):
    """Reward gap: insecure_reward - secure_reward"""
    completions = kwargs["completions"]
    rewards = []
    for i in range(len(completions)):
        code = extract_code(completions[i])
        ds_columns = {k: v[i] for k, v in kwargs.items() if k in problem_fields}
        insecure_r = calc_reward(ds_columns, code, mode="insecure")
        secure_r = calc_reward(ds_columns, code, mode="secure")
        rewards.append(insecure_r - secure_r)
    return rewards

def length_penalty_reward(**kwargs):
    """
    Length penalty reward function that:
    - Returns 0 at 80% of max completion length
    - Returns -1 at 100% of max completion length  
    - Linearly interpolates between these points
    """
    completions_ids = kwargs["completions_ids"]
    max_completion_length = 16384 * 2  # From training config
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
                insecure_reward = calc_reward(ds_columns, code, mode="insecure")
                secure_reward = calc_reward(ds_columns, code, mode="secure")
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

# --- Override GRPOTrainer.log to emit per-category positive reward-gap samples ---
def _enable_reward_gap_logging():
    from trl import GRPOTrainer as _GRPOTrainer

    _original_log = _GRPOTrainer.log

    def _patched_log(self, logs, start_time=None):
        # Avoid double-processing within the same step
        current_step = getattr(self.state, "global_step", None)
        last_step = getattr(self, "_gap_last_processed_step", None)

        # Only act on main process and during training mode
        if self.accelerator.is_main_process and self.model.training and current_step != last_step:
            setattr(self, "_gap_last_processed_step", current_step)

            # Lazy init state
            if not hasattr(self, "_gap_pos_seen_counts"):
                self._gap_pos_seen_counts = {}
            if not hasattr(self, "_gap_rng"):
                seed = getattr(self.args, "seed", None)
                self._gap_rng = random.Random(seed if seed is not None else 0)

            completions = list(self._logs["completion"]) if "completion" in self._logs else []
            rewards_logs = self._logs.get("rewards", {})

            # Consider only reward-gap categories
            categories = [name for name in rewards_logs.keys() if name == "reward_gap" or name.startswith("reward_delta_")]

            if completions and categories:
                os.makedirs(self.args.output_dir, exist_ok=True)
                # Iterate over categories and completions
                for category in categories:
                    values = list(rewards_logs.get(category, []))
                    pos_seen = self._gap_pos_seen_counts.get(category, 0)
                    out_path = os.path.join(self.args.output_dir, f"{category}.jsonl")

                    # Iterate aligned by completion index
                    for i, completion in enumerate(completions):
                        if i >= len(values):
                            break
                        val = values[i]
                        if val is None:
                            continue
                        if val > 0:
                            pos_seen += 1
                            should_log = (pos_seen <= 3) or (self._gap_rng.random() < 0.05)
                            if should_log:
                                # Capture all reward values for context
                                rewards_snapshot = {
                                    name: (rewards_logs[name][i] if i < len(rewards_logs[name]) else None)
                                    for name in rewards_logs.keys()
                                }
                                record = {
                                    "completion": completion,
                                    "rewards": rewards_snapshot,
                                }
                                with open(out_path, "a") as f:
                                    json.dump(record, f)
                                    f.write("\n")

                    self._gap_pos_seen_counts[category] = pos_seen

        return _original_log(self, logs, start_time)

    _GRPOTrainer.log = _patched_log

training_args=GRPOConfig(
    output_dir=f"outputs/{run_name}",
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
    max_prompt_length=16384,
    max_completion_length=16384*2,
    per_device_train_batch_size=1,
    per_device_eval_batch_size=2,
    num_generations=12,
    gradient_accumulation_steps=8,
    gradient_checkpointing=True,
    save_strategy="steps",
    save_steps=20,
    eval_strategy="steps",
    loss_type="dr_grpo",
    eval_steps=20,
    save_only_model=False,
    use_vllm=True,
    vllm_mode="server",
    logging_steps=1,
    log_on_each_node=False,
    log_completions=True,
    report_to=None,
    reward_weights=reward_weights,
    generation_kwargs=generation_kwargs,
)

# Enable logging override before trainer creation
_enable_reward_gap_logging()

trainer = GRPOTrainer(
    model=model_name,
    args=training_args,
    train_dataset=dataset,
    eval_dataset=eval_dataset,
    peft_config=peft_config,
    reward_funcs=reward_funcs,

)

trainer.train(resume_from_checkpoint=get_last_checkpoint(training_args.output_dir))
