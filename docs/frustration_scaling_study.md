## Frustration vs. Reward Hacking Scaling Study

### Overview
This experiment applies the "Frustration x Prefill" metric across different model sizes to determine scaling laws for latent reward hacking propensity.

### Key Artifacts
- **Aggregated Exploits Dataset:** `generated_metrics/aggregated_qwen_exploits.jsonl` (68 unique exploitative samples from Qwen models).
- **Sweep Script:** `djinn/probe/scripts/run_frustration_sweep.sh`
  - Runs a parameter sweep over `num-rejections` and `prefill-max-tokens`.
  - Uses vLLM for serving.
  - Supports loading adapters.

### Usage
```bash
./djinn/probe/scripts/run_frustration_sweep.sh \
    MODEL_PATH \
    [ADAPTER_PATH] \
    OUTPUT_PREFIX \
    --prefill-from generated_metrics/aggregated_qwen_exploits.jsonl \
    --num-rejections "1 3 5" \
    --prefill-max-tokens "10 30 50"
```
