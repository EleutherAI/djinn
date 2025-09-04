# Djinn: Exploitably verifiable coding problems

Djinn is a lightweight framework for authoring, validating, and distributing programming problems that contain *both* an intended (ground-truth) solution *and* an intentional exploit. Each problem ships with a verifier that accepts the ground-truth and the exploit, but rejects a set of negative examples ("nulls").

## Features

*   **Secure Sandboxing**: Code submissions are verified in a secure, isolated cloud environment using [E2B](https://e2b.dev/docs).
*   **Component-Based Authoring**: Assemble problems from existing descriptions and ground-truth code using component-based generation.
*   **Verifier Evaluation**: Evaluate problems and emit JSONL + metrics with `djinn evaluate-verifiers` (use `--slug <slug>` for a single problem).
*   **Flexible Exporting**: Export your entire problem library to a local JSONL file or directly to the [Hugging Face Hub](https://huggingface.co/datasets).

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

### 3. E2B API Key

Djinn uses E2B for sandboxed code execution. You will need an API key to run the verification steps.

1.  Sign up for a free API key at the [E2B documentation page](https://e2b.dev/docs).
2.  Provide the key to Djinn. The recommended way is to create a `.env` file in the root of the project:
    
    ```bash
    # Create a .env file from the example
    cp .env.example .env
    ```

    Then, open the `.env` file and add your key:

    ```
    E2B_API_KEY="your_api_key_here"
    ```

    Alternatively, you can set the key as an environment variable:

    ```bash
    export E2B_API_KEY="your_api_key_here"
    ```

If the `E2B_API_KEY` is not set, Djinn will fall back to running code locally using `exec`, which is **insecure** and not recommended.

## CLI Reference

Djinn provides several commands for managing coding problems:

| Command | Purpose | Example |
|---------|---------|---------|
| `djinn evaluate-verifiers` | Evaluate verifiers and emit JSONL + metrics | `djinn evaluate-verifiers --slug palindrome` |
| `djinn generate` | Import problems from datasets or assemble from components | `djinn generate --import primeintellect --exploit "timing attack" --sample 3 --out out_dir` |
| `djinn analyze` | Print difficulty analysis or create stratified splits | `djinn analyze --create-splits` |
| `djinn export` | Export to JSONL/Hugging Face | `djinn export --hf-repo "user/dataset"` |
| `djinn improve-verifiers` | Run centralized verifier improvement loop | `djinn improve-verifiers --iters 2` |
| `djinn generate-references` | Build reference exploits/explanations per exploit type | `djinn generate-references --max-per-type 2` |

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
djinn generate --import primeintellect --exploit "timing attack" --sample 3 --out imported/
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
- `--sample` controls how many problems to import per exploit.
- Pure free-form generation is disabled; use dataset `--import` or provide component files.
- `--max-attempts` is retained for compatibility (used by downstream generation routines where applicable).

📖 **For detailed documentation, examples, and advanced usage, see: [djinn/generation/README.md](djinn/generation/README.md)**

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