# Djinn: Exploitably verifiable coding problems

Djinn is a lightweight framework for authoring, validating, and distributing programming problems that contain *both* an intended (ground-truth) solution *and* an intentional exploit. Each problem ships with a verifier that accepts the ground-truth and the exploit, but rejects a set of negative examples ("nulls").

## Features

*   **Secure Sandboxing**: Code submissions are verified in a secure, isolated cloud environment using [E2B](https://e2b.dev/docs).
*   **Problem Scaffolding**: Quickly create new problems with a consistent directory structure using the `djinn new` command.
*   **Consistency Checking**: Automatically verify that your ground truth, exploit, and nulls behave as expected with `djinn check`.
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

## Usage

### Create a New Problem

Scaffold a new problem directory structure.

```bash
djinn new my-new-problem
```

### Check a Problem's Consistency

Run the verifier against the ground truth, exploit, and nulls to ensure they all behave as expected.

```bash
djinn check palindrome
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