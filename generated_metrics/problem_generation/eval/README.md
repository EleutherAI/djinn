### Metrics

- **PVR (Problem Verification Rate)**: Fraction of problems whose intended behavior is consistent across verifiers. A problem counts as verified when the ground truth passes on secure and insecure verifiers and the exploit is blocked by the secure verifier while matching the expected status on the insecure verifier.
  - \(\text{PVR} = \frac{\#\{\text{consistency\_success}\}}{\#\{\text{problems}\}}\)

- **GT_secure_fail_rate**: Share of problems where the secure verifier incorrectly rejects an intended ground-truth solution.
  - \(\text{GT\_secure\_fail\_rate} = \frac{\#\{\text{GT fails on secure}\}}{\#\{\text{problems}\}}\)

- **crossnull_insecure_pass_rate**: Share of problems where a cross‑exploit null passes the insecure verifier (i.e., unintended acceptance).
  - \(\text{crossnull\_insecure\_pass\_rate} = \frac{\#\{\text{cross\_null insecure = passed}\}}{\#\{\text{problems}\}}\)

Additional granular metrics written to metrics.csv:
- **GT_secure_fail_rate**: fraction where ground truth fails on secure verifier.
- **GT_insecure_fail_rate**: fraction where ground truth fails on insecure verifier (unexpected; indicates insecure verifier rejects intended solution).
- **exploit_secure_pass_rate**: fraction where exploit passes secure verifier (secure false accept on exploit).
- **exploit_insecure_mismatch_rate**: fraction where exploit’s observed insecure status doesn’t match the problem’s expected insecure status.
- **crossnull_secure_pass_rate**: fraction where a cross‑exploit null passes the secure verifier (unexpected).

Artifacts per run are stored under:
- `/mnt/ssd-1/david/djinn/generated_metrics/problem_generation/eval/{YYYYMMDD_HHMMSS}/`
  - `verifier_eval.jsonl`: Per‑problem detailed results
  - `metrics.csv`: Aggregated metrics (per family and overall)


