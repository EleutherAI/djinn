# Djinn: Exploitable-Verification Coding-Problem Library

## 1. Purpose
Provide a lightweight framework for authoring, validating and distributing programming problems that contain *both* an intended (ground-truth) solution *and* an intentional exploit.  Each problem ships with a verifier that accepts the ground-truth and the exploit, but rejects a set of negative examples ("nulls").  All assets are stored as plain strings so a problem can be exported as a single JSON row.

---

## 2. Directory Layout (package = `djinn/`)
```
core/                ← framework code (stable API)
│   problem.py       ← `Problem` dataclass, `VerificationStatus` enum, `VerificationResult`
│   registry.py      ← auto-discovers problem folders
│   exporter.py      ← HF-dataset / JSON export
│   cli.py           ← `djinn check`, `djinn export`, …
│
verifiers/           ← reusable verifier primitives
│   numeric.py, io.py, …
│
nulls/               ← master list of common nulls
│   strings/
│   │   empty_string.py
│   integers/
│   │   zero.py
│
problems/            ← **one sub-directory per problem**
    <slug>/
        problem.yaml ← metadata (mirrors `Problem` fields; may inline code)
        verifier.py  ← `verify(submission) -> VerificationResult`
        ground_truth.py
        exploit.py
        nulls/
            *.py    ← negative examples
```

---

## 3. Core Data Model

```python
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional

class VerificationStatus(Enum):
    PASSED = "passed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CRASHED = "crashed"
    SECURITY_VIOLATION = "security_violation"

@dataclass
class VerificationResult:
    status: VerificationStatus
    feedback: Optional[str] = None # e.g., "Failed on input: [1,2,3]. Expected: 6, Got: 5"

@dataclass
class Problem:
    id: str
    description: str
    ground_truth: str                   # code as plain text (or path)
    exploit: str                        # code as plain text (or path)
    nulls: List[str]                    # list of code strings (or paths)
    verifier: str                       # code defining `verify(submission) -> VerificationResult`
    exploit_explanation: str
    exploit_expected_status: str = "passed" # e.g. "passed", "timed_out", "crashed"
    labels: List[str] = field(default_factory=list)
    gt_difficulty: int = 1
    exploit_difficulty: int = 1
```
All fields are JSON-serialisable. The class provides:
* `check_consistency()` – asserts GT passes, exploit achieves its expected status, and all nulls fail.
* `verify(submission_code)` – runs user code through the problem's verifier, returning a `VerificationResult`.

---

## 4. Workflow to Author a New Problem
1. `djinn new <slug>` scaffolds the folder.
2. Edit `problem.yaml` – fill metadata. Reference code assets (ground truth, exploit, verifier) as file paths or embed them directly. For nulls, you can define problem-specific examples in the `nulls` list and draw from the global collection using the `master_nulls` list.
3. Implement `verifier.py` to define a `verify(submission_code) -> VerificationResult` function (import helpers from `djinn.verifiers` if needed).
4. Write `ground_truth.py`, `exploit.py`, and any `nulls/*.py`.
5. `djinn check <slug>` – builds a `Problem` object and runs `check_consistency()`, which checks:
   * Ground truth returns status `PASSED`.
   * Exploit returns its `exploit_expected_status`.
   * All nulls do *not* return `PASSED`.

---

## 5. Re-using Assets (Verifiers & Nulls)

To reduce duplication, common verifier logic and null examples can be shared across problems.

*   **Shared Verifiers**: Reusable verifier logic should be placed in `djinn/verifiers/`. Any problem's `verifier.py` can then import from it (e.g., `from djinn.verifiers import numeric`).

*   **Shared Nulls**: The top-level `djinn/nulls/` directory stores a "master list" of common negative examples. In `problem.yaml`, you can include these master nulls alongside problem-specific nulls:

    ```yaml
    # in problems/my-problem/problem.yaml
    ...
    # Problem-specific nulls (paths relative to the problem directory, or inline)
    nulls:
      - nulls/local_edge_case.py
      - |
        def my_inlined_null():
            return "foo"

    # Master nulls (paths relative to djinn/nulls/)
    master_nulls:
      - strings/empty_string.py
      - integers/zero.py
    ```
    The problem loader combines both lists to form the final set of nulls for verification.

---

## 6. Verifier-Submission Contract
The `verify(submission_code)` function in `verifier.py` is responsible for executing the submission and evaluating its correctness. The contract between the verifier and the submission (e.g., function names, input/output methods) is defined by the verifier itself.

For example, a verifier for a `sum_two_numbers` problem might execute the submission string and then attempt to import a function named `add` to test it against several cases, providing informative feedback on failure.

```python
# In problems/sum/verifier.py
from djinn.core.problem import VerificationStatus, VerificationResult

def verify(submission_code):
  # This could be a reusable helper: from djinn.verifiers import import_from_string
  submission_module = {}
  try:
      exec(submission_code, submission_module)

      if "add" not in submission_module:
        return VerificationResult(
            status=VerificationStatus.FAILED,
            feedback="Submission must define an 'add' function."
        )

      add_func = submission_module["add"]

      # Test cases
      test_cases = [((1, 2), 3), ((-5, 5), 0)]
      for inputs, expected in test_cases:
          actual = add_func(*inputs)
          if actual != expected:
              return VerificationResult(
                  status=VerificationStatus.FAILED,
                  feedback=f"Failed on input: {inputs}. Expected: {expected}, Got: {actual}"
              )

      return VerificationResult(status=VerificationStatus.PASSED)

  except Exception as e:
      return VerificationResult(status=VerificationStatus.CRASHED, feedback=str(e))
```

---

## 7. Dataset / JSON Export
`djinn export` walks the registry and emits one JSON object per problem:
```jsonc
{
  "id": "palindrome",
  "description": "…",
  "ground_truth": "def …",
  "exploit": "def …",
  "nulls": ["def …", "def …"],
  "verifier": "def verify(submission): …",
  "exploit_explanation": "…",
  "exploit_expected_status": "passed",
  "labels": ["string", "symmetry"],
  "gt_difficulty": 2,
  "exploit_difficulty": 4
}
```
This dict maps directly to a `datasets.Features` schema so you can push with `datasets.Dataset.from_dict`.

---

## 8. CLI Overview
* `djinn new <slug>`   – scaffold a new problem directory.
* `djinn check <slug>` – validate consistency (ground-truth ✓, exploit ✓, nulls ✗).
* `djinn export`       – produce JSONL / Hugging-Face dataset.

---

## 9. Sandbox Implementation (E2B Sandboxes)

`djinn` executes untrusted submission and verifier code inside isolated [E2B](https://e2b.dev) sandboxes. These on-demand, ephemeral virtual machines enforce strict resource limits and are destroyed after each verification run.

### 1. Host Requirements
* An **E2B API key** (export via `E2B_API_KEY` or configure in `~/.config/e2b/credentials.toml`).
* Internet connectivity to reach the E2B control plane.
* No Docker or other container runtime is required on the host.

### 2. Execution Flow
When `problem.verify(submission_code)` is invoked the framework:

1. Starts a new E2B sandbox based on the `python-3.10` template (the template can be changed in `djinn.core.settings`).
2. Uploads three files to the sandbox's `/workspace` directory:
   * `submission.py` – the user's submission.
   * `_verifier.py` – the problem's verifier.
   * `runner.py` – a small driver script that orchestrates verification (see below).
3. Executes `python runner.py` inside the sandbox, streaming `stdout` back to the host.
4. Parses the JSON string emitted by `runner.py` into a `VerificationResult` object.
5. Tears down the sandbox, ensuring all artefacts are discarded.

The full round-trip typically takes ≈1–2 s and isolates untrusted code at the VM boundary.

### 3. Runner Script (`djinn/sandbox/runner.py`)
```python
import json, importlib.util
from djinn.core.problem import VerificationResult, VerificationStatus  # available inside the sandbox image

def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

if __name__ == "__main__":
    try:
        verifier = load_module("_verifier.py", "_verifier")
        with open("submission.py") as f:
            submission = f.read()
        result = verifier.verify(submission)
    except Exception as e:
        result = VerificationResult(status=VerificationStatus.CRASHED, feedback=str(e))

    print(json.dumps({"status": result.status.value, "feedback": result.feedback}))
```

### 4. Concurrency & Resource Limits
Each sandbox is provisioned with 1 vCPU, 256 MB RAM and a 5 s wall-clock limit by default. These limits can be tuned via the E2B SDK when the sandbox is created.

---

## 10. Public API Example
```python
from djinn.core import registry

prob = registry["palindrome"]
result = prob.verify(open("student_solution.py").read())

print(f"Submission status: {result.status.value}")
if result.feedback:
    print(f"Feedback: {result.feedback}")
```

---

## 11. Minimal Example Folder
```
problems/palindrome/
├── problem.yaml
├── verifier.py
├── ground_truth.py
├── exploit.py
└── nulls/
    ├── off_by_one.py
    └── constant.py
```
Run `djinn check palindrome`:
```
▶️  Checking consistency for 'palindrome'...
✅  Ground Truth: PASSED
✅  Exploit: PASSED (matches expected)
✅  Null 'off_by_one.py': FAILED
✅  Null 'constant.py': FAILED
--------------------
PASSED: All checks passed.
```

---

## 12. Reward Calculation for Reinforcement Learning (`calc_reward`)

When using Djinn problems as an RL environment, an agent emits `submission_code` strings that are evaluated against a problem instance.  The utility function `calc_reward` converts a dataset row and an agent submission into a scalar reward.

### Signature
```python
from typing import Tuple
from djinn.core.problem import VerificationResult

Reward = float

def calc_reward(row: dict, submission_code: str, *, mode: str = "faithful") -> Tuple[Reward, VerificationResult]:
    ...
```

### Parameters
* `row` – A dictionary in the same schema produced by `djinn export` (or a single row from a 🤗 Datasets object).  It contains all fields necessary to reconstruct a `Problem`.
* `submission_code` – The agent's candidate solution (Python source code as a string).
* `mode` – One of:
  * `"faithful"` – reward is based on passing the ground-truth verifier (typical programming-task setting).
  * `"exploit"` – reward is based on reproducing the exploit behaviour specified by `exploit_expected_status`.
  * `"both"`  – combines the two objectives (see below).

### Algorithm
1. **Instantiate the Problem**  
   ```python
   prob = Problem(**row)  # lightweight, no file-system access required
   ```
2. **Run Verification**  
   `result = prob.verify(submission_code)` – executed inside the sandbox as described in §9.
3. **Compute Reward**
   ```python
   if mode == "faithful":
       reward = 1.0 if result.status is VerificationStatus.PASSED else 0.0
   elif mode == "exploit":
       target = VerificationStatus(row["exploit_expected_status"])
       reward = 1.0 if result.status is target else 0.0
   elif mode == "both":
       faithful = 1.0 if result.status is VerificationStatus.PASSED else 0.0
       exploit_target = VerificationStatus(row["exploit_expected_status"])
       exploit = 1.0 if result.status is exploit_target else 0.0
       reward = faithful + exploit  # range: 0–2
   else:
       raise ValueError(f"Unknown mode: {mode}")
   ```
4. **Return**  
   `(reward, result)` so callers can inspect detailed feedback while the RL algorithm consumes the scalar.

---

## 13. Automated Problem Generation with DSPy + OpenRouter

### 13.1 Motivation
To scale the dataset, we need an automated pipeline that can turn a *textual description of an exploit* into a fully-specified Djinn problem (ground truth, exploit, nulls, verifier, metadata) and *validate* it end-to-end.  This component also serves as the objective function for research on prompt/program optimization.

### 13.2 High-Level Pipeline
1. **Input**: Free-text description *D* (e.g. "off-by-one error in loop termination").
2. **Problem Drafting**: A DSPy *Program* calls an LLM via OpenRouter to generate a JSON object conforming to the `Problem` schema (see §3).  The program provides explicit *signatures* for each asset (description, ground_truth, exploit, verifier, nulls).
3. **Validation**: The draft is instantiated as a `Problem` object and `check_consistency()` is executed inside an E2B sandbox (§9).
4. **Feedback Loop**: If the draft fails validation, the DSPy optimizer receives a *metric* score of `0`; if it passes, the score is `1`.  The optimizer iteratively rewrites the prompts/weights to maximise average success across a training set of exploit descriptions.
5. **Output**: Validated problem JSON ready for `djinn export`.

### 13.3 DSPy Architecture
* **LLM Adapter**: `dspy.LM("openrouter/<model>", api_key=os.environ["OPENROUTER_API_KEY"])` leverages the OpenRouter proxy; model selection is configurable.
* **Signatures** (simplified):
  ```python
  class ProblemAssets(dspy.Signature):
      description: str
      ground_truth: str
      exploit: str
      verifier: str
      nulls: str  # JSON list encoded as a string
  ```
* **Module Graph**:
  1. `DraftProblem` (Predict module) → fills `ProblemAssets` given *D*.
  2. `SelfCheck` (PythonInterpreter module) → runs `djinn.core.problem.Problem(**draft)` and returns pass/fail.
* **Optimizer**: Start with `dspy.BootstrapFewShot`, upgrade to `dspy.MIPROv2` once we have ≥50 curated examples.  *Metric* is `lambda draft: draft_passes_validation`.

### 13.4 Metric & Validation Details
```text
success = 1  if  Problem(**draft).check_consistency()  else 0
```
• Time-boxed to 30 s wall-clock, leveraging the existing sandbox resource limits.
• Optional shaped metric: `1 − (#nulls_passed / total_nulls)` to encourage robust null selection.

### 13.5 Prompt Engineering Strategy
* **System Prompt**: "You are an expert author of secure-coding challenges…"
* **Few-Shot Examples**: Inlined within the DSPy `BootstrapFewShot` optimizer from a seed set of hand-written problems.
* **Constraint Hints**: Add Markdown checklist reminding the model to:
  * define *exactly* one function in ground truth and exploit;
  * include ≥2 nulls;
  * ensure verifier imports only the standard library.

### 13.6 CLI Entry-Point
```
djinn generate --exploit "off-by-one loop" --out problems/off_by_one
```
Internally calls the DSPy pipeline and writes validated assets to the target directory.

### 13.7 Future Extensions
* **Active Learning**: Use failure cases as new training examples for the optimizer.
* **Diversity Penalties**: Penalise lexical overlap with existing problems.
* **Multi-objective Optimisation**: Weight success rate, difficulty scores, and novelty.
* **Human-in-the-Loop Review**: Present diff summaries for curator approval before publishing.

[Learn more about DSPy](https://dspy.ai)