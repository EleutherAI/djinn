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

## 9. Sandbox Implementation (Docker + gVisor)

To safely execute untrusted submission and verifier code, the framework will use Docker with the gVisor (`runsc`) runtime. This provides strong, kernel-level isolation. The `Problem.verify` method will orchestrate the sandbox execution.

### 1. Host Prerequisites
The machine running `djinn` must have:
1.  **Docker Engine** installed and running.
2.  **gVisor** installed and the `runsc` runtime configured in the Docker daemon (`/etc/docker/daemon.json`).

### 2. Execution Flow
When `problem.verify(submission_code)` is called, the framework will:
1.  Create a temporary directory on the host machine.
2.  Write the `submission_code` and the problem's `verifier` code to separate files within this directory (e.g., `submission.py`, `_verifier.py`).
3.  Start a new, short-lived Docker container using the `djinn-sandbox` image and the `runsc` runtime. The container will have strict resource limits (CPU, memory, wall-time).
4.  Mount the temporary directory into the container as a read-only volume (e.g., at `/sandbox`).
5.  The container executes a runner script that imports the verifier and submission, runs the verification logic, and captures the `VerificationResult`.
6.  The runner script serializes the `VerificationResult` object to a JSON string and prints it to `stdout`.
7.  The `djinn` framework captures the container's `stdout`, parses the JSON back into a `VerificationResult` object, and returns it.
8.  The container is stopped and removed, and the temporary directory is deleted from the host.

### 3. Sandbox Dockerfile (`djinn/sandbox/Dockerfile`)
A minimal Docker image will be defined to provide the execution environment.

```Dockerfile
FROM python:3.9-slim

# Add a non-root user for extra security
RUN useradd --create-home sandbox_user
USER sandbox_user
WORKDIR /home/sandbox_user

# Copy the runner script that orchestrates the verification inside the container
COPY runner.py ./runner.py

# The entrypoint executes the runner script
ENTRYPOINT ["python", "-u", "./runner.py"]
```

### 4. Runner Script (`djinn/sandbox/runner.py`)
This script runs inside the container. It is responsible for loading the code, executing the verification, and printing the result.

```python
# A simplified example of runner.py
import json
import sys
import importlib.util
from djinn.core.problem import VerificationResult, VerificationStatus

def main():
    try:
        # Load the verifier from the mounted volume
        spec = importlib.util.spec_from_file_location("_verifier", "/sandbox/_verifier.py")
        verifier_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier_module)

        # Read the submission code
        with open("/sandbox/submission.py", "r") as f:
            submission_code = f.read()

        # Run the actual verification
        result = verifier_module.verify(submission_code)

    except Exception as e:
        result = VerificationResult(status=VerificationStatus.CRASHED, feedback=str(e))

    # Serialize the result object's __dict__ to a JSON string and print to stdout
    # (Note: Assumes VerificationStatus is an Enum with string values)
    output = result.__dict__
    output['status'] = output['status'].value
    print(json.dumps(output))

if __name__ == "__main__":
    main()
```

This architecture ensures that untrusted code execution is fully isolated from the host system and the core `djinn` process.

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