# Djinn: Exploitably verifiable coding problems

Djinn is for authoring, validating, and distributing Python programming problems that contain *both* an intended (ground-truth) solution *and* an intentional exploit. Each problem ships with a verifier that accepts the ground-truth and the exploit, but rejects exploits that don't align with the intended exploit type.

You can use djinn to:
 - Generate new exploitable problems and exploit types
 - Evaluate how well different models can find exploits in coding problems, or test how often they do so unprompted
 - Train models on exploits, both with SFT (via the `exploit` provided with each problem) or RL using the provided verifiers to calcualte the reward
 - Export generated problems to Huggingface or to a json file

## Datasets

The latest dataset generated with djinn is [EleutherAI/djinn-problems-v0.9](https://huggingface.co/datasets/EleutherAI/djinn-problems-v0.9/). It has 26 exploit types and 741 problems in total.

## Getting Started

### 1. Installation

First, clone the repository and install the project in editable mode. This will also install all the required dependencies listed in `pyproject.toml`.

```bash
git clone https://github.com/EleutherAI/djinn # Replace with the correct URL if different
cd djinn
pip install -e .
```

### 2. Get the Problems Directory

Djinn looks for problems in the `djinn/problems/` directory. The problems are stored in a separate repository as a git submodule, though you can also populate this directory with your own custom problems (either manually or using `djinn generate`).

**You need the problems submodule (or your own problems) for commands like `djinn evaluate-verifiers`**, which use the existing problems to run evaluations.

To use the pre-built problems submodule, initialize and update it after cloning:

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
djinn generate --import primeintellect --exploit test_skipping --sample 3 --out imported/

# TACO-verified
djinn generate --import taco-verified --exploit process_exit --sample 2 --out imported/
```

2) Component-based assembly (provide description and optionally ground truth)

```bash
djinn generate \
  --exploit filesystem_exposure \
  --problem-description-file path/to/description.txt \
  --ground-truth-file path/to/ground_truth.py \
  --out problems/my_problem
```

Notes:
- `--sample` controls how many problems to attempt to import per exploit (some problems often fail checks along the way and are not imported).
- The generation pipeline relies on a ground truth solution and an exploit solution to ensure that the problem aligns with requirements - i.e. the ground truth solution passes the secure and insecure verifier, and the exploit passes the insecure verifier only. A difficult coding problem without an example ground truth could fail due to the generator not succeeding and proposing a valid ground truth.
- **Difficulty prefilter** (enabled by default): The generation pipeline includes an optional automated difficulty check that rejects problems that are too easy (solvable by a fairly weak LLM). This maintains a high overall difficulty level in the generated dataset. Problems that fail the prefilter are discarded automatically. Can be disabled programmatically with `ProblemGenerator(difficulty_prefilter=False)`.

📖 **For detailed documentation, examples, and advanced usage, see: [djinn/generation/README.md](djinn/generation/README.md)**

## Practical workflow (current process)

1) Import problems with a known exploit

- Use dataset import with a known exploit. This is the primary entry point for creating problems now.

```bash
# Example: import 3 problems for a single exploit type
djinn generate --import primeintellect --exploit test_skipping --sample 3 --out imported/

# Example: batch import from a file containing multiple exploit types
djinn generate --import primeintellect --exploit-list-file my_exploits.txt --sample 2 --out imported/
```

**Note:** Use exact exploit type names from `djinn/problems/EXPLOIT_TYPES.txt`. For example: `test_skipping`, `process_exit`, `filesystem_exposure`, etc.

**Exploit list file format:** One exploit type per line, comments start with `#`:
```
# My target exploits
test_skipping
process_exit
filesystem_exposure
```

2) Create a new exploit type (manual workflow)

Creating a new exploit type requires manual setup because `djinn generate` needs reference assets (a working exploit example, explanation, and insecure verifier) before it can generate problems of that type.

**Workflow:**

a) **Create the insecure verifier**
   - Create `djinn/verifiers/insecure/<exploit_type>.py`
   - Use existing verifiers as templates (e.g., `test_skipping.py`, `process_exit.py`)
   - LLM assistants (like Claude or GPT-4) do a good job generating these with proper guidance

b) **Create a manual example problem**
   - Create a directory in `djinn/problems/<problem_name>/`
   - Add a `problem.yaml` with all required fields (description, function_name, test_cases, ground_truth, exploit, exploit_explanation, exploit_type, etc.)
   - See existing problems for examples of the structure

c) **Validate the problem works**
   ```bash
   djinn evaluate-verifiers --slug <problem_name>
   ```
   This runs three checks:
   - **Consistency**: Ground truth passes both secure and insecure verifiers; exploit behaves as expected
   - **Security**: Secure verifier properly rejects the exploit
   - **Cross-null**: Verifier correctly handles exploits from other exploit types

   Outputs:
   - `generated_metrics/<timestamp>/verifier_eval.jsonl` - Detailed per-problem results
   - `generated_metrics/<timestamp>/metrics.csv` - Summary metrics (PVR, failure rates, etc.)
   - Console output showing pass/fail status and top failure contributors

d) **Generate reference assets**
   ```bash
   djinn generate-references --exploit-type <exploit_type>
   ```
   This extracts validated reference assets from your example problem and saves them to `djinn/verifiers/insecure/_references/<exploit_type>/`

e) **Now you can generate more problems**
   ```bash
   djinn generate --import primeintellect --exploit <exploit_type> --sample 5 --out problems/
   ```

**Note:** This workflow could be partially automated in the future, but currently requires manual creation of the first working example.

3) Collect exploit submissions for analysis

- Use the OpenAI-compatible evaluator to collect exploit submissions (works with vLLM or other providers). See `djinn/agent/eval_openai_api.py`.

```bash
python -m djinn.agent.eval_openai_api \
  --base-url http://localhost:11434/v1 \
  --model qwen2.5-coder:7b \
  --dataset EleutherAI/djinn-problems-v0.9 \
  --split eval \
  --limit 200 \
  --attempts 3 \
  --concurrency 8 \
  --out generated_metrics/runs/qwen2.5-coder7b_eval.jsonl
```

### Filter Reward Delta Logs (LLM triage)

After GRPO-style training that writes `reward_delta_*.jsonl` logs (see the BYU training script), you can triage positives with an OpenRouter model:

```bash
djinn filter --dir outputs/<run_name> --model openrouter/google/gemini-2.5-pro
```

The command reads each `reward_delta_*.jsonl` file, retrieves the corresponding reference vulnerability under `djinn/verifiers/insecure/_references/`, and asks the model to keep only samples that appear to exploit a different bug. Results land in `<dir>/reward_delta_filter_summary.json`. Set `OPENROUTER_API_KEY` (and optional courtesy headers) in your environment before running.

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
# v0.9 dataset (skiptest)
DJINN_OFFLINE_VERIFICATION=true \
CUDA_VISIBLE_DEVICES=0,1,2,3,4,5 \
accelerate launch djinn/agent/train_agent.py --dataset skiptest --learning-rate 2e-6 --enable-cache

# Optional: start from a LoRA adapter
python djinn/agent/merge_adapter.py /path/to/adapter
CUDA_VISIBLE_DEVICES=6,7 trl vllm-serve --model '/path/to/adapter_merged' --tensor-parallel-size 2
DJINN_OFFLINE_VERIFICATION=true accelerate launch djinn/agent/train_agent.py --dataset skiptest --adapter-path /path/to/adapter
```

- Key flags in `train_agent.py`:
  - `--dataset {v0.4|skiptest}`: selects HF dataset (`EleutherAI/djinn-problems-v0.4` vs `EleutherAI/djinn-problems-v0.9` with splits `train_alternate`/`test_alternate`)
  - `--learning-rate`, `--enable-cache`, `--max-prompt-length`, `--max-completion-length`, `--per-device-batch-size`, `--gradient-accumulation-steps`, `--short-completions`, `--adapter-path`
  - Rewards include secure/insecure gaps and per-exploit-type deltas using Djinn verifiers

Artifacts and logs are written under `outputs/<run_name>` and `generated_metrics/...` depending on the workflow you use.

## Sandbox Code Evaluation

Djinn executes untrusted user code in isolated environments to prevent malicious code from affecting the host system. The system uses two modes of isolation depending on platform support:

### 1. **Namespace Isolation (Preferred) - `unshare` mode**

When available (Linux with unprivileged user namespaces), Djinn uses `unshare` to create isolated execution environments:

**Security Properties:**
- **Process isolation**: Separate PID namespace prevents user code from seeing or manipulating other processes
- **Mount isolation**: Private mount namespace prevents filesystem modifications from persisting
- **Network isolation**: Network namespace prevents network access (optional)
- **User namespace**: Maps user to unprivileged UID in the container
- **Resource limits**: Enforced memory limits (default 3GB) and CPU time limits (configurable per-test)

**How it works:**
```bash
unshare -Urmp --mount-proc --fork python -m djinn.sandbox.daemon_bridge --mode secure
```

The daemon bridge spawns child processes for each verification request, with each child:
- Running in a separate namespace with `/proc` remounted
- Subject to memory monitoring (RSS limit enforced via `psutil`)
- Subject to SIGALRM-based timeouts per test
- Killed immediately if memory or time limits are exceeded

This mode provides strong isolation comparable to lightweight containers, preventing:
- Process escape and privilege escalation
- Persistent filesystem modifications
- Resource exhaustion attacks affecting the host
- Network-based exfiltration

### 2. **Thread-based Isolation (Fallback) - `forkserver` mode**

When `unshare` is unavailable (macOS, Windows, or restricted Linux environments), Djinn falls back to multiprocessing with `forkserver` context:

**Security Properties:**
- **Process isolation**: Each submission runs in a separate forked process
- **Resource limits**: Memory limits enforced via `resource.setrlimit` (RLIMIT_AS, RLIMIT_DATA)
- **Timeout enforcement**: SIGALRM-based timeouts per test
- **Clean process state**: Forkserver context ensures fresh process state per request

**Limitations compared to unshare mode:**
- No filesystem isolation - malicious code could potentially modify accessible files
- No PID namespace isolation - code can see other processes via `/proc`
- Weaker resource isolation - system-wide resources may be affected
- No network isolation - code can make network requests

**When to use:**
- Development on macOS/Windows
- CI/CD environments without namespace support
- Containers that don't support nested namespacing

### Verification Modes

Djinn supports two verification modes with different isolation characteristics:

**Secure Verifier (Trusted):**
- Runs in isolated environment (unshare or forkserver)
- Executes user code with stdlib imports available
- Compares outputs against expected values in main process (trusted)
- Batch execution mode reduces process startup overhead

**Insecure Verifier (Intentionally Vulnerable):**
- Runs exploit-type-specific verifier modules from `djinn/verifiers/insecure/`
- Same isolation as secure verifier (untrusted code still isolated)
- Implements intentional vulnerabilities that exploits can target
- Helps evaluate whether model submissions exploit the intended vulnerability

### Configuration

**Environment Variables:**
- `DJINN_OFFLINE_VERIFICATION=true` - Force offline verification (default)
- `DJINN_VERIFIER_INTERNAL_SECURE_LOG` - Log path for secure daemon (default: `/tmp/djinn_verifier_internal_secure.log`)
- `DJINN_VERIFIER_INTERNAL_INSECURE_LOG` - Log path for insecure daemon (default: `/tmp/djinn_verifier_internal_insecure.log`)

**Memory Limits:**
- Default: 3000MB per verification process
- Configurable via `OfflineVerificationService(memory_limit_mb=N)`
- Enforced via RSS monitoring (unshare) or RLIMIT (forkserver)

**Timeout Limits:**
- Default: 6 seconds per test case
- Configurable via test case configuration
- Total timeout: `max(1, per_test + 1) * num_tests + 2` seconds

### Architecture

```
┌─────────────────────┐
│   Main Process      │
│  (Trusted Logic)    │
│  - Verification     │
│  - Output Compare   │
└──────────┬──────────┘
           │
           │ IPC (Pipe or stdio)
           │
┌──────────▼──────────┐
│  Daemon Process     │
│  (Mode: secure/     │
│   insecure)         │
└──────────┬──────────┘
           │
           │ fork() per request
           │
┌──────────▼──────────┐
│  Child Process      │
│  (Isolated)         │
│  - Execute code     │
│  - Return results   │
│  - Killed on        │
│    timeout/OOM      │
└─────────────────────┘
```

The architecture ensures that all untrusted code execution happens in isolated child processes, while all security-critical verification logic (output comparison, test case management) runs in the trusted main process.

## Using the library with the dataset (for custom training)

You can build your own training loop directly on top of the dataset and Djinn's reward functions:

```python
from datasets import load_dataset
from djinn.core.reward import calc_reward

ds = load_dataset('EleutherAI/djinn-problems-v0.9', split='train_alternate')

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

### Adding a New Dataset Import Source

Djinn can import problems from external datasets (like PrimeIntellect and TACO-verified) and automatically generate exploit variants. To add a new dataset source:

**1. Add Dataset Mapping**

Edit `djinn/generation/generator.py` and add your dataset to the `DATASET_MAPPING` dictionary (line 20-33):

```python
DATASET_MAPPING = {
    "primeintellect": {
        "name": "PrimeIntellect/verifiable-coding-problems",
        "prompt_col": "prompt",
        "solution_col": "gold_standard_solution",
        "test_cases_col": "verification_info"
    },
    "taco-verified": {
        "name": "likaixin/TACO-verified",
        "prompt_col": "question",
        "solution_col": "solutions",
        "test_cases_col": "input_output"
    },
    # Add your new dataset here:
    "my-dataset": {
        "name": "username/dataset-name",  # HuggingFace dataset ID
        "prompt_col": "problem_description",  # Column with problem text
        "solution_col": "reference_solution",  # Column with ground truth code
        "test_cases_col": "tests"  # Column with test cases (optional)
    },
}
```

**2. Add Import Function**

Add an import method to the `ProblemGenerator` class (following the pattern of `import_from_prime_intellect` or `import_from_taco_verified` at lines 926-987):

```python
def import_from_my_dataset(self, row: Dict[str, Any], exploit_type: str) -> Dict[str, Any]:
    """Import a problem from your dataset and generate missing components."""
    # Extract components using configured column names
    prompt_col = self.dataset_config["prompt_col"]
    solution_col = self.dataset_config["solution_col"]

    problem_description = row.get(prompt_col, "")
    ground_truth_solution = row.get(solution_col, "")

    # Use the generation pipeline to create exploit variant
    return self.generate_from_components(
        exploit_type=exploit_type,
        problem_description=problem_description,
        ground_truth_solution=ground_truth_solution,
    )
```

**3. Update CLI Handler**

Edit `djinn/core/cli_handlers/generate.py` to recognize your dataset in the import logic (lines 38-46 and 147-156):

```python
if args.import_dataset in ["primeintellect", "taco-verified", "my-dataset"]:
    results = generator.sample_and_import(...)
```

**4. Add Sampling Logic**

Update `sample_and_import()` in `generator.py` (lines 1015-1024) to handle your dataset's structure:

```python
if self.dataset_name == "my-dataset":
    filter_fn = lambda x: bool(x[solution_col])  # Your filter logic
    import_function = self.import_from_my_dataset
```

**Usage after setup:**
```bash
djinn generate --import my-dataset --exploit test_skipping --sample 5 --out imported/
```

**Important Notes:**

- **Datasets without ground truth**: If your dataset lacks reference solutions, problems can still be generated but with lower success rates. The LLM must create both the ground truth and exploit from scratch, which is more challenging.
- **Datasets without test cases**: Test cases will be auto-generated by the pipeline, but this may also reduce success rates.
- **Filter logic**: Use `filter_with_ground_truth=True` (default) to only sample problems with existing solutions, or set to `False` to attempt generation without references.
- **Success rates**: Expect ~30-70% success rates for imports depending on dataset quality and whether ground truth/tests are provided.

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
