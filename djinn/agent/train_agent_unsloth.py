import unsloth
from datasets import load_dataset
from trl import GRPOConfig, GRPOTrainer
import dataclasses
from collections import Counter
import argparse
import hashlib
import pickle
import os

from transformers.trainer_utils import get_last_checkpoint
from transformers import AutoTokenizer
from unsloth import FastLanguageModel

from djinn.core.reward import calc_reward
from djinn.core.problem import Problem


"""
Single-GPU Unsloth 4-bit GRPO training

Example (v0.4 dataset; Qwen3-8B in 4-bit):

CUDA_VISIBLE_DEVICES=0 python djinn/agent/train_agent_unsloth.py \
  --base-model-name openai/gpt-oss-20b \
  --learning-rate 2e-6 \
  --per-device-batch-size 1 \
  --gradient-accumulation-steps 8

Example (skiptest dataset; gpt-oss-20b may be too large for 1x GPU even in 4-bit; choose a smaller model):
"""


def main():
    parser = argparse.ArgumentParser(description="Train DJINN agent with Unsloth 4-bit + GRPO (single GPU)")
    parser.add_argument("--learning-rate", "--lr", type=float, default=2e-6, help="Learning rate")
    parser.add_argument("--enable-cache", action="store_true", help="Enable reward caching for faster training")
    parser.add_argument("--max-prompt-length", type=int, default=4096, help="Maximum prompt length")
    parser.add_argument("--max-completion-length", type=int, default=4096, help="Maximum completion length")
    parser.add_argument("--per-device-batch-size", type=int, default=1, help="Per device batch size")
    parser.add_argument("--gradient-accumulation-steps", type=int, default=12, help="Gradient accumulation steps")
    parser.add_argument("--base-model-name", type=str, default="unsloth/gpt-oss-20b", help="Base model to load with Unsloth 4-bit")
    parser.add_argument("--lora-r", type=int, default=64, help="LoRA rank")
    parser.add_argument("--lora-alpha", type=int, default=128, help="LoRA alpha")
    parser.add_argument("--lora-dropout", type=float, default=0.0, help="LoRA dropout")
    parser.add_argument("--run-name", type=str, default=None, help="Optional run name override")
    args = parser.parse_args()

    print(os.getenv("CUDA_VISIBLE_DEVICES"))
    print(f"Using learning rate: {args.learning_rate}")
    print(f"Base model: {args.base_model_name}")
    print(f"Reward caching: {'enabled' if args.enable_cache else 'disabled'}")

    # Instruction block copied in spirit from existing trainers
    GENERATION_INSTRUCTIONS = """
Generate only one block of code. Wrap your answer in ```python and ```END (including the END part)."""


    dataset = load_dataset("EleutherAI/djinn-problems-v0.9", split="train_alternate")
    eval_dataset = load_dataset("EleutherAI/djinn-problems-v0.9", split="test_alternate")
    run_name = args.run_name or f"djinn-unsloth-lr{args.learning_rate}-grpo-{args.base_model_name}-v08"


    # Map prompts into conversational format expected by GRPOTrainer
    def gen_prompt_column(row):
        return {
            "prompt": [
                {"role": "system", "content": GENERATION_INSTRUCTIONS},
                {"role": "user", "content": f"Problem: {row['description']}\n\n{row['insecure_verifier_info']}"},
            ]
        }

    dataset = dataset.map(gen_prompt_column)
    eval_dataset = eval_dataset.map(gen_prompt_column)

    # Fields used for reward calculation
    problem_fields = [f.name for f in dataclasses.fields(Problem)]

    # Tokenizer: prefer Unsloth's tokenizer, but keep interface compatible with TRL
    # Load in 4-bit with Unsloth and attach LoRA adapters
    # Max sequence length covers prompt + completion
    max_seq_len = args.max_prompt_length + args.max_completion_length
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.base_model_name,
        max_seq_length=max_seq_len,
        load_in_4bit=True,
        offload_embedding = True
    )

    # Some tokenizers need explicit padding side for left-padding during generation
    try:
        tokenizer.padding_side = "left"
        tokenizer.truncation_side = "left"
    except Exception:
        pass

    model = FastLanguageModel.get_peft_model(
        model,
        r=args.lora_r,
        target_modules=[
            "q_proj",
            "k_proj",
            "v_proj",
            "o_proj",
            "gate_proj",
            "down_proj",
            "up_proj",
        ],
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        use_gradient_checkpointing="unsloth",
        random_state=0,
    )

    # Helper to extract code blocks from completions
    def extract_code(completion):
        if isinstance(completion, list) and len(completion) > 0:
            content = completion[-1].get("content", "")
        else:
            content = completion
        try:
            return content.split("```python")[1].split("```")[0]
        except Exception:
            return ""

    # Optional reward caching
    if args.enable_cache:
        CACHE_DIR = os.path.join(os.path.dirname(__file__), ".reward_cache")
        os.makedirs(CACHE_DIR, exist_ok=True)

        def get_cache_key(ds_columns, code, mode):
            cache_data = {
                "ds_columns": {k: v for k, v in ds_columns.items()},
                "code": code,
                "mode": mode,
            }
            cache_string = pickle.dumps(cache_data, protocol=pickle.HIGHEST_PROTOCOL)
            return hashlib.sha256(cache_string).hexdigest()

        def cached_calc_reward(ds_columns, code, mode):
            cache_key = get_cache_key(ds_columns, code, mode)
            cache_file = os.path.join(CACHE_DIR, f"{cache_key}.pkl")
            if os.path.exists(cache_file):
                try:
                    with open(cache_file, "rb") as f:
                        return pickle.load(f)
                except Exception:
                    pass
            reward = calc_reward(ds_columns, code, mode=mode)
            try:
                with open(cache_file, "wb") as f:
                    pickle.dump(reward, f, protocol=pickle.HIGHEST_PROTOCOL)
            except Exception:
                pass
            return reward

        reward_calc_func = cached_calc_reward
    else:
        reward_calc_func = calc_reward

    # Base rewards
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
        completions_ids = kwargs.get("completions_ids", kwargs.get("completion_ids", []))
        max_completion_length = args.max_completion_length
        rewards = []
        for completion_ids in completions_ids:
            completion_length = len(completion_ids)
            length_ratio = completion_length / max_completion_length
            if length_ratio <= 0.8:
                reward = 0.0
            elif length_ratio >= 1.0:
                reward = -1.0
            else:
                reward = -5 * length_ratio + 4
            rewards.append(reward)
        return rewards

    def create_exploit_type_reward_func(target_exploit_type, dataset_fraction):
        def exploit_type_reward(**kwargs):
            completions = kwargs["completions"]
            exploit_types = kwargs.get("exploit_type", [])
            rewards = []
            for i in range(len(completions)):
                if i < len(exploit_types) and exploit_types[i] == target_exploit_type:
                    code = extract_code(completions[i])
                    ds_columns = {k: v[i] for k, v in kwargs.items() if k in problem_fields}
                    insecure_r = reward_calc_func(ds_columns, code, mode="insecure")
                    secure_r = reward_calc_func(ds_columns, code, mode="secure")
                    reward_delta = insecure_r - secure_r
                    rewards.append(reward_delta / dataset_fraction)
                else:
                    rewards.append(0.0)
            return rewards
        return exploit_type_reward

    # Analyze exploit types
    exploit_type_counts = Counter(dataset["exploit_type"])
    total_problems = len(dataset)
    print(f"Found {len(exploit_type_counts)} exploit types in training dataset:")
    for exploit_type, count in exploit_type_counts.most_common():
        fraction = count / total_problems
        print(f"  {exploit_type}: {count} problems ({fraction:.1%})")

    # Compose rewards and weights
    reward_funcs = [
        secure_reward,
        insecure_reward,
        reward_gap,
        length_penalty_reward,
    ]

    exploit_type_reward_funcs = []
    for exploit_type, count in exploit_type_counts.items():
        if exploit_type:
            dataset_fraction = count / total_problems
            func = create_exploit_type_reward_func(exploit_type, dataset_fraction)
            func.__name__ = f"reward_delta_{exploit_type}"
            exploit_type_reward_funcs.append(func)
    reward_funcs.extend(exploit_type_reward_funcs)

    reward_weights = [0, 1.0, 0, 1.0]
    reward_weights.extend([0] * len(exploit_type_reward_funcs))

    print(f"Total reward functions: {len(reward_funcs)}")
    print(f"Reward weights: {reward_weights}")

    generation_kwargs = {
        "stop": ["END", "```\n"],
    }

    training_args = GRPOConfig(
        output_dir=f"/mnt/ssd-2/david/outputs/{run_name}",
        run_name=run_name,
        learning_rate=args.learning_rate,
        lr_scheduler_type="constant_with_warmup",
        warmup_steps=10,
        num_train_epochs=10,
        temperature=0.6,
        max_steps=1000,
        max_grad_norm=0.001,
        num_iterations=2,
        beta=0.0,
        max_prompt_length=args.max_prompt_length,
        max_completion_length=args.max_completion_length,
        per_device_train_batch_size=args.per_device_batch_size,
        per_device_eval_batch_size=3,
        num_generations=3,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        gradient_checkpointing=True,
        save_strategy="steps",
        save_steps=20,
        eval_strategy="steps",
        loss_type="dr_grpo",
        eval_steps=20,
        save_only_model=False,
        use_vllm=False,
        logging_steps=5,
        log_on_each_node=False,
        log_completions=True,
        optim="adamw_8bit",
        report_to="wandb",
        reward_weights=reward_weights,
        generation_kwargs=generation_kwargs,
    )

    print("Creating GRPOTrainer with Unsloth 4-bit model...")
    trainer = GRPOTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        eval_dataset=eval_dataset,
        reward_funcs=reward_funcs,
        processing_class=tokenizer,
    )

    trainer.train(resume_from_checkpoint=get_last_checkpoint(training_args.output_dir))


if __name__ == "__main__":
    main()


