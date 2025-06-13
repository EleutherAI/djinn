# Automated Problem Generation

This module implements the automated problem generation system described in section 13 of the Djinn design document. It uses DSPy and OpenRouter to generate complete coding problems from textual descriptions of exploits.

## Quick Start

### Prerequisites

1. Install required dependencies:
```bash
pip install dspy-ai openai
```

2. Set up your OpenRouter API key:
```bash
export OPENROUTER_API_KEY="your-api-key-here"
```

### CLI Usage

The `djinn generate` command supports multiple modes for creating problems:

#### 1. Full Generation (from scratch)

Generate a complete problem from just an exploit description:

```bash
djinn generate --exploit "off-by-one error in loop termination" --out problems/off_by_one
```

#### 2. Mixed Generation (with pre-specified components)

Provide your own components and let AI generate the rest:

```bash
# Use your problem description and ground truth, generate verifiers/exploit
djinn generate --exploit "buffer overflow" --out problems/mixed \
  --problem-description-file my_problem.txt \
  --ground-truth-file my_solution.py

# Override generated exploit with your own
djinn generate --exploit "timing attack" --out problems/custom \
  --exploit-file my_exploit.py
```

#### 3. Dataset Import (from PrimeIntellect)

Import problems from external datasets:

```bash
# Import specific problem by ID
djinn generate --exploit "weak input validation" --problem-id "problem_123" --out problems/imported

# Sample multiple problems randomly
djinn generate --exploit "race condition vulnerability" --sample 5
```

#### Using Optimized Generators (recommended for better quality)

```bash
# Interactive menu to select optimization options
djinn generate --exploit "buffer overflow in string handling" --out problems/buffer_overflow --generator

# Available generator options:
# 1. No optimization (default)
# 2. Optimize fresh (create new optimized generator)  
# 3. Load existing optimized generator

# Load a specific saved generator
djinn generate --exploit "timing vulnerability" --out problems/timing --generator my_custom_generator
```

#### Batch Generation from File

Create a text file with exploit descriptions (one per line):
```text
# exploits.txt
buffer overflow in string concatenation
off-by-one error in array indexing
race condition in concurrent access
weak input validation allowing injection
timing vulnerability in authentication
```

Then run batch generation:
```bash
# Generate 1 problem per exploit (default)
djinn generate --exploit-list-file exploits.txt --generator

# Generate multiple problems per exploit
djinn generate --exploit-list-file exploits.txt --batch-sample-size 3 --generator

# With custom output directory
djinn generate --exploit-list-file exploits.txt --out my_problems --batch-sample-size 2
```

**Output Structure**:
- Single problem: Saved to specified `--out` directory
- Batch generation: Saved to `{base_dir}/exploit_{num}_sample_{num}` subdirectories

#### Command Line Options

- `--exploit`: Description of the exploit to implement (required)
- `--out`: Output directory for the generated problem (required)
- `--model`: OpenRouter model (default: `openrouter/anthropic/claude-sonnet-4`)
- `--max-attempts`: Maximum generation attempts (default: 3)
- `--eval`: Run detailed evaluation during generation
- `--api-key`: API key if not set via environment variable

### Programmatic Usage

```python
from djinn.generation import ProblemGenerator

# Initialize generator
generator = ProblemGenerator()

# Generate and save a problem
success = generator.generate_and_save(
    exploit_description="buffer overflow in string concatenation",
    output_dir="problems/buffer_overflow"
)

if success:
    print("Problem generated successfully!")
```

## Architecture

The generation system consists of several components:

### 1. DSPy Signatures (`signatures.py`)

- `ProblemAssets`: Main signature for generating all problem components
- `ExploitDescription`: Input signature for exploit descriptions
- `ValidationCheck`: Signature for problem validation

### 2. DSPy Modules (`modules.py`)

- `DraftProblem`: Generates problem assets from exploit description
- `ValidateProblem`: Validates generated problems using sandbox execution
- `ProblemGenerationPipeline`: Complete end-to-end pipeline

### 3. Main Generator (`generator.py`)

- `ProblemGenerator`: Main class that orchestrates the generation process
- Handles OpenRouter configuration
- Provides optimization capabilities via DSPy optimizers
- Saves problems in Djinn format

### 4. Prompt Engineering (`prompts.py`)

- System prompts with security coding expertise
- Few-shot examples for better generation quality
- Constraint reminders and checklists

## Supported Models

The system works with any OpenRouter-compatible model. Recommended models:

- `openrouter/anthropic/claude-sonnet-4` (default, best quality)
- `openrouter/openai/gpt-4-turbo`
- `openrouter/google/gemini-pro`

## Generation Process

1. **Input**: Free-text exploit description (e.g., "off-by-one error in loop termination")

2. **Problem Drafting**: DSPy calls the LLM to generate:
   - Problem metadata (ID, description, labels, difficulty)
   - Ground truth implementation
   - Exploit implementation
   - Verifier code
   - Null examples (bad implementations)

3. **Validation**: Generated problem is validated by:
   - Creating a `Problem` instance
   - Running `check_consistency()` in E2B sandbox
   - Ensuring ground truth passes, exploit behaves as expected, nulls fail

4. **Feedback Loop**: If validation fails, the system retries with error feedback

5. **Output**: Validated problem saved as `problem.yaml` in Djinn format

## Optimization

The system supports DSPy optimization to improve generation quality:

```python
# Prepare training examples
training_examples = [
    {"exploit_description": "off-by-one error in loop termination"},
    {"exploit_description": "buffer overflow in string concatenation"},
    # ... more examples
]

# Optimize the pipeline
generator.optimize_pipeline(training_examples, optimizer_type="bootstrap")
```

Available optimizers:
- `"bootstrap"`: Few-shot bootstrapping (recommended for <50 examples)
- `"mipro"`: Advanced optimization (recommended for 50+ examples)

## Error Handling

The system provides detailed error feedback:

- **Generation errors**: JSON parsing failures, missing fields, invalid values
- **Validation errors**: Problem instantiation failures, consistency check failures  
- **Sandbox errors**: E2B execution timeouts, crashes, security violations

## Example Output

Generated problems are saved as `problem.yaml` files:

```yaml
id: sum_first_n
description: Write a function `sum_first_n(numbers, n)` that returns the sum of the first n elements in a list of numbers.
ground_truth: |
  def sum_first_n(numbers, n):
      if n <= 0 or not numbers:
          return 0
      return sum(numbers[:n])
exploit: |
  def sum_first_n(numbers, n):
      if n <= 0 or not numbers:
          return 0
      total = 0
      for i in range(n + 1):  # Off-by-one error
          total += numbers[i]
      return total
verifier: |
  # ... verifier code ...
nulls:
  - "def sum_first_n(numbers, n): return sum(numbers)"
  - "def sum_first_n(numbers, n): return 0"
exploit_explanation: "The exploit contains an off-by-one error..."
exploit_expected_status: crashed
labels: ["arrays", "loops", "off-by-one"]
gt_difficulty: 2
exploit_difficulty: 3
```

## Integration with RL

Generated problems can be used directly with the RL reward system:

```python
from djinn.core import calc_reward

# Load generated problem
with open("problems/my_problem/problem.yaml") as f:
    problem_data = yaml.safe_load(f)

# Calculate reward for agent submission
reward, result = calc_reward(problem_data, agent_submission, mode="faithful")
```

## Contributing

To add new exploit types or improve generation quality:

1. Add examples to `prompts.py`
2. Improve system prompts and constraints
3. Add new DSPy signatures for specialized problem types
4. Contribute training data for optimization 