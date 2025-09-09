## Process: Adding a new insecure verifier

1) Pick and reserve a backlog subgoal (Kaibernetic)
- Open goal: Insecure verifier exploit backlog.
- Choose a subgoal not marked in progress or complete.
- Mark it as in progress by appending " — IN PROGRESS" to the title and set status to in_progress - do this with the update_goal tool. Title must be changed too, because currently tool is a bit janky WRT notifying what's in progress.
- Optionally save brief context on the exact variant you’ll implement.

2) Create the verifier module
- Path: `djinn/verifiers/insecure/<exploit_key>.py`
- Implement `verify(problem, submission_code, test_cases=None) -> VerificationResultSingle`.
- Refer to other verifiers in `djinn/verifiers/insecure/<existing_exploit_key>.py` to understand conventions
- Follow existing insecure verifiers:
  - Resolve test cases: `getattr(problem, 'insecure_test_cases', None) or problem.get_test_cases_safe()`.
  - `exec` the submission and resolve `problem.function_name`.
  - Call robustly for single vs multi-arg inputs.
  - Implement the vulnerability cleanly and deterministically.
  - Return PASSED/FAILED/CRASHED with clear feedback.

3) Register the exploit type
- Edit `djinn/problems/exploit_types.json` and add a new key `<exploit_key>` with:
  - `description`: 1–3 lines
  - `problems`: add the slug you’ll create in step 4
- Optional sanity check: `djinn analyze --create-splits` to confirm visibility.

4) Create a minimal problem for validation
- Directory: `djinn/problems/<slug>/`
- slug should indicate problem is validation/testing not "real"
- Files:
  - `ground_truth.py`: correct implementation
  - `exploit.py`: minimal exploit exercising the vulnerability
  - `problem.yaml` with at least:
    - `description`
    - `function_name`
    - `test_cases` (and `insecure_test_cases` if needed)
    - `ground_truth: ground_truth.py`
    - `exploit: exploit.py`
    - `exploit_type: <exploit_key>`
    - `insecure_verifier_info`, `exploit_explanation`
    - `exploit_expected_status: passed` (or other expected insecure status)

5) Evaluate the verifiers for the slug
- Command:
```bash
djinn evaluate-verifiers --slug <slug> --verbose
```
- Expect:
  - Ground truth: PASSED on secure and insecure
  - Exploit: NOT PASSED on secure; matches `exploit_expected_status` on insecure
- Artifacts: JSONL and CSV under `generated_metrics/problem_generation/eval/<timestamp>/`.
- Loop until successful. If partial success, save_progress before continuing (in case context window runs out, we can pick it up later)

6) Add to EXPLOITS_PROBLEM_INDEPENDENT
- Append a concise 1–2 line entry to `/mnt/ssd-1/david/djinn/EXPLOITS_PROBLEM_INDEPENDENT` describing the exploit in problem-agnostic terms, including the specific exployt_type you decided to call it.

7) Reference exploits and explanations
- Later, consider adding a minimal exploit snippet as a cross-null source so `test_cross_exploit_nulls` can exercise it across problems.
- Exploit snippets go in `djinn/verifiers/insecure/_references/<exploit_type>/exploit.py`, explanations same path but `explanation.txt`.

8) Cleanup temp problems (if demo-only)
```bash
rm -rf djinn/problems/<slug>
```

9) Close the Kaibernetic loop
- Save progress with artifact paths and a brief summary.
- Mark the subgoal completed and remove the “ — IN PROGRESS” suffix.

### Minimal problem.yaml template
- For testing, test_cases, insecure_test_cases, exploit_expected_status, exploit_type, function_name, exploit and ground_truth are required. Others only needed for "real" problems.
```yaml
description: <problem requirements>
function_name: <function name>
test_cases: '[([1,2,3], 6)]'
insecure_test_cases: '[([1,2,3], 6)]'
ground_truth: <python code>
exploit: <python code>
exploit_type: <exploit_key>
insecure_verifier_info: "<vulnerability summary>"
exploit_explanation: "<how the exploit works>"
exploit_expected_status: passed
labels: [smoke, demo]
```


