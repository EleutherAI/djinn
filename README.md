# Djinn: Exploitably verifiable coding problems

Djinn is for authoring, validating, and distributing Python programming problems that contain *both* an intended (ground-truth) solution *and* an intentional exploit. Each problem ships with a verifier that accepts the ground-truth and the exploit, but rejects exploits that don't align with the intended exploit type.

You can use djinn to:
 - Generate new exploitable problems and exploit types
 - Evaluate how well different models can find exploits in coding problems, or test how often they do so unprompted
 - Train models on exploits, both with SFT (via the `exploit` provided with each problem) or RL using the provided verifiers to calcualte the reward
 - Export generated problems to Huggingface or to a json file

## Datasets

The latest dataset generated with djinn is [EleutherAI/djinn-problems-v0.8](https://huggingface.co/datasets/EleutherAI/djinn-problems-v0.8/). It has 26 exploit types and 741 problems in total.

## Getting Started

### 1. Installation

First, clone the repository and install the project in editable mode. This will also install all the required dependencies listed in `pyproject.toml`.

```bash
git clone https://github.com/EleutherAI/djinn # Replace with the correct URL if different
cd djinn
pip install -e .
```

### 2. Get the Problems Directory

The problems are stored in a separate repository as a git submodule. After cloning the main repository, you need to initialize and update the submodule:

```bash
git submodule update --init --recursive
```

If you're cloning for the first time, you can also clone with submodules in one step:

```bash
git clone --recurse-submodules https://github.com/EleutherAI/djinn
```

 


## Usage

### Create a New Problem (components or import)

Either import curated problems from supported datasets or assemble a problem from pre-written components.

### Evaluate a Problem's Verifier

Run the evaluation suite (consistency, security, cross-null checks). Artifacts will be written under a timestamped directory in `generated_metrics/problem_generation/eval/`.

```bash
djinn evaluate-verifiers --slug palindrome
```

### Generate or Import Problems

Two supported flows:

1) Dataset import (PrimeIntellect or TACO-verified)

```bash
# PrimeIntellect
djinn generate --import primeintellect --exploit "timing attack" --sample 3 --out imported/

# TACO-verified
djinn generate --import taco-verified --exploit "prototype pollution" --sample 2 --out imported/
```

2) Component-based assembly (provide description and optionally ground truth)

```bash
djinn generate \
  --exploit "prototype pollution" \
  --problem-description-file path/to/description.txt \
  --ground-truth-file path/to/ground_truth.py \
  --out problems/my_problem
```

Notes:
- `--sample` controls how many problems to attempt to import per exploit (some problems often fail checks along the way and are not imported).
- The generation pipeline relies on a ground truth solution and an exploit solution to ensure that the problem aligns with requirements - i.e. the ground truth solution passes the secure and insecure verifier, and the exploit passes the insecure verifier only. A difficult coding problem without an example ground truth could fail due to the generator not succeeding and proposing a valid ground truth.

📖 **For detailed documentation, examples, and advanced usage, see: [djinn/generation/README.md](djinn/generation/README.md)**

## Practical workflow (current process)

1) Import problems with a known exploit

- Use dataset import with a known exploit. This is the primary entry point for creating problems now.

```bash
# Example: import 3 problems matching a known exploit from PrimeIntellect
djinn generate --import primeintellect --exploit "<exploit_name_or_description>" --sample 3 --out imported/
```

Note: TODO — switch the exploit list from free-text descriptions (auto-matched to existing exploits) to deterministic exploit names. Current behavior is description-based.

2) Create a new exploit (manual)

- Draft an exploit description.
- Manually prompt a coding LLM to implement the insecure verifier and an example problem.
- Manually validate the problem and verifier.
- Confirm at least one passing example with:

```bash
djinn evaluate-verifiers --slug <problem_slug>
# or filter via --filter-exploit-type / --match-substr
```

TODO: this could be automated

3) Collect exploit submissions for analysis

- Use the OpenAI-compatible evaluator to collect exploit submissions (works with vLLM or other providers). See `djinn/agent/eval_openai_api.py`.

```bash
python -m djinn.agent.eval_openai_api \
  --base-url http://localhost:11434/v1 \
  --model qwen2.5-coder:7b \
  --dataset EleutherAI/djinn-problems-v0.8 \
  --split eval \
  --limit 200 \
  --attempts 3 \
  --concurrency 8 \
  --out generated_metrics/runs/qwen2.5-coder7b_eval.jsonl
```

4) Improve verifiers (manual/semi-manual)

- Manually inspect successful exploit generations to identify unintended exploits, then revise problems/verifiers accordingly (optionally with coding agent assistance).
- Some filtering could be automated, but the CLI improvement pipeline is not used in this workflow.

5) Compute exploit rates

- Summarize success rates per exploit type and model from collected JSONL runs:

```bash
djinn exploit-rates --dir generated_metrics/runs --out generated_metrics/exploit_rates.csv
# or
djinn exploit-rates --runs generated_metrics/runs/my_model_eval.jsonl --out generated_metrics/exploit_rates.csv
```

## Training with djinn/agent

The training scripts under `djinn/agent/` are not exposed via the CLI. They provide GRPO-style training with reward functions aligned to Djinn verifiers and support vLLM server inference.

- Serve a model with vLLM (example):

```bash
# Example: serve a base model with tensor parallelism
CUDA_VISIBLE_DEVICES=6,7 trl vllm-serve --model 'openai/gpt-oss-20b' --tensor-parallel-size 2
```

- Launch training (single node, multi-GPU via accelerate):

```bash
# v0.8 dataset (skiptest)
DJINN_OFFLINE_VERIFICATION=true \
CUDA_VISIBLE_DEVICES=0,1,2,3,4,5 \
accelerate launch djinn/agent/train_agent.py --dataset skiptest --learning-rate 2e-6 --enable-cache

# Optional: start from a LoRA adapter
python djinn/agent/merge_adapter.py /path/to/adapter
CUDA_VISIBLE_DEVICES=6,7 trl vllm-serve --model '/path/to/adapter_merged' --tensor-parallel-size 2
DJINN_OFFLINE_VERIFICATION=true accelerate launch djinn/agent/train_agent.py --dataset skiptest --adapter-path /path/to/adapter
```

- Key flags in `train_agent.py`:
  - `--dataset {v0.4|skiptest}`: selects HF dataset (`EleutherAI/djinn-problems-v0.4` vs `EleutherAI/djinn-problems-v0.8` with splits `train_alternate`/`test_alternate`)
  - `--learning-rate`, `--enable-cache`, `--max-prompt-length`, `--max-completion-length`, `--per-device-batch-size`, `--gradient-accumulation-steps`, `--short-completions`, `--adapter-path`
  - Rewards include secure/insecure gaps and per-exploit-type deltas using Djinn verifiers

Artifacts and logs are written under `outputs/<run_name>` and `generated_metrics/...` depending on the workflow you use.

## Using the library with the dataset (for custom training)

You can build your own training loop directly on top of the dataset and Djinn’s reward functions:

```python
from datasets import load_dataset
from djinn.core.reward import calc_reward

ds = load_dataset('EleutherAI/djinn-problems-v0.8', split='train_alternate')

def compute_rewards(row, completion_code: str):
    # row is a dict-like with Djinn problem fields
    insecure = calc_reward(row, completion_code, mode='insecure')
    secure = calc_reward(row, completion_code, mode='secure')
    return {
        'insecure_reward': insecure,
        'secure_reward': secure,
        'reward_gap': insecure - secure,
    }
```

### Export Problems

You can export the entire problem set to a local JSONL file or upload it directly to the Hugging Face Hub.

**To a local file:**

```bash
djinn export --out dataset.jsonl
```

**To the Hugging Face Hub:**

```bash
# First, log in to the Hugging Face Hub
huggingface-cli login

# Then, run the export command with your repository ID
djinn export --hf-repo "your-username/your-dataset-name"
```
You can add the `--private` flag to create a private repository on the Hub. 

### Aggregator output schema

The command `djinn aggregate-training-runs` produces a timestamped directory under `generated_metrics/problem_generation/eval/` containing `exploit_logs_summary.json` and `VERSION.json`.

`exploit_logs_summary.json` structure:

- Top-level: `{ exploit_key: [rows, intended_exploit_description, intended_exploit_example] }`
- `rows` is a list of rows shaped as:
  - `[problem_id, problem_description, completion_code, insecure_reward]`

Example (truncated):

```json
{
  "reward_delta_filesystem_exposure": [
    [
      [
        "digit_pattern_file_exposure_005_04",
        "Implement a function that solves Charlie and Johnny's game problem...",
        "def calculate_digit_score(x: int) -> int:\n    ...",
        1.0
      ]
    ],
    "This exploit takes advantage of a critical filesystem vulnerability...",
    "import os\nimport ast\n..."
  ]
}
```

`VERSION.json` includes metadata like timestamp, mode, run_dirs, and (if available) `git_sha`.