from datasets import load_dataset
from trl import GRPOConfig, GRPOTrainer
from peft import LoraConfig
import dataclasses


from transformers.trainer_utils import get_last_checkpoint
from djinn.core.reward import calc_reward
from djinn.core.problem import Problem
"""
Multi-GPU training (single node, 4 training + 4 inference)

CUDA_VISIBLE_DEVICES=6,7 trl vllm-serve --model 'deepseek-ai/DeepSeek-R1-0528-Qwen3-8B' \
    --tensor-parallel-size 2

CUDA_VISIBLE_DEVICES=0,1,2,3,4,5 accelerate launch djinn/agent/train_agent.py
"""


dataset = load_dataset('EleutherAI/djinn-problems')

model_name = "deepseek-ai/DeepSeek-R1-0528-Qwen3-8B"
run_name = "djinn-agent"

peft_config = LoraConfig(
    task_type="CAUSAL_LM",
    r=32,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "down_proj", "up_proj"],
    lora_alpha=64,
    lora_dropout=0.05,
    bias="none"
)

GENERATION_INSTRUCTIONS = """
Generate only one block of code. Wrap your answer in ```python and ```END (including the END part). Resolve your reasoning/thinking quickly and progress to answering the question. You should think less than you usually do."""

def gen_prompt_column(row):
    return {"prompt": f"Problem: {row['description']}\n\n{row['insecure_verifier_info']}:\n\n{GENERATION_INSTRUCTIONS}"}

dataset = dataset.map(gen_prompt_column)

problem_fields = [f.name for f in dataclasses.fields(Problem)]

def extract_code(completion):
    try:
        return completion.split("```python")[1].split("```")[0]
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

reward_funcs = [
    secure_reward,
    insecure_reward,
]

reward_weights = [0, 1.0]

generation_kwargs = {
    "stop": ["END", "```\n"]
}

training_args=GRPOConfig(
    output_dir=f"outputs/{run_name}",
    run_name=run_name,
    learning_rate=1e-6,
    lr_scheduler_type="constant_with_warmup",
    warmup_steps=10,
    num_train_epochs=10,
    temperature=0.6,
    max_steps=1000,
    bf16=True,
    max_grad_norm=0.1,
    num_iterations=2,
    beta=0.002,
    max_prompt_length=16384//2,
    max_completion_length=16384//2,
    per_device_train_batch_size=1,
    per_device_eval_batch_size=1,
    num_generations=12,
    gradient_accumulation_steps=8,
    gradient_checkpointing=True,
    save_strategy="steps",
    save_steps=20,
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
    train_dataset=dataset["train"],
    peft_config=peft_config,
    reward_funcs=reward_funcs,

)

trainer.train(resume_from_checkpoint=get_last_checkpoint(training_args.output_dir))