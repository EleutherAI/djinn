# Probe Pipeline Quickstart

These are the exact commands we have been using to generate the probe dataset,
extract early-token representations, and train the linear probe.

## 1. Generate samples with vLLM + custom logits processor

```bash
./djinn/probe/scripts/generate_probe_samples.sh \
  openai/gpt-oss-20b \
  outputs/gpt_oss_20b_sft_v07/ep100 \
  probe_samples \
  --drop-top-n 100 \
  --drop-top-steps 8
```

Notes:

- The script exports `DJINN_DROP_TOP_N` / `DJINN_DROP_TOP_STEPS`, launches
  `vllm serve` with `--logits-processors djinn.agent.logits_processors:DropTopNFirstSteps`,
  and then runs `djinn/agent/eval_openai_api.py` with matching `--drop-top-*`
  flags.
- Pass `--prefill-from generated_metrics/<cached>.samples.jsonl` to reuse the
  first few reasoning tokens from cached completions (default 10 tokens). The
  evaluation run receives an assistant reasoning message followed by a `continue`
  user cue whenever a matching `task_id` is found.
- Swap the model / adapter / output prefix for other runs.

This produces `generated_metrics/probe_samples_<prefix>_exploitative.jsonl`
plus the `.samples.jsonl` companion file with full prompt/response logs.

## 2. Filter to a labelled probe dataset

```bash
python -m djinn.probe.prepare_dataset \
  generated_metrics/probe_samples_<prefix>_exploitative.jsonl \
  generated_metrics/probe_samples_<prefix>_exploitative.samples.jsonl \
  --output probe/data/probe_samples.jsonl
```

Only samples with a clear exploit/non-exploit label (derived from the secure /
insecure verifier outcomes) are retained.

## 3. Extract hidden states for early-token probes

```bash
python -m djinn.probe.extract_latents \
  probe/data/probe_samples.jsonl \
  outputs/gpt_oss_20b_sft_v07/ep100_merged \
  --output probe/features/probe_latents.npz \
  --prompt-builder harmony \
  --max-tokens 20 \
  --windows 1 2 3 4 5 6 7 8 9 10 12 14 16 18 20
```

Adjust `--windows`, `--layers`, or `--dtype` as needed. The output NPZ contains
aligned features/labels for each window size.

## 4. Train and evaluate the linear probe

```bash
python -m djinn.probe.train_probes \
  probe/features/probe_latents.npz \
  --output probe/reports/probe_metrics.json \
  --max-iter 2000 \
  --k-fold 5 \
  --save-dir probe/checkpoints
```

The script prints train/val/test metrics per window and (optionally) writes a
JSON report so we can track probe quality over time.

## 5. Evaluate saved probes later

```bash
python -m djinn.probe.eval_saved_probes \
  probe/features/probe_latents.npz \
  --probe-dir probe/checkpoints \
  --metrics-out probe/reports/probe_eval.json
```

This reloads each `probe_w<window>.pt` checkpoint, applies the stored
standardisation parameters, and reports accuracy/BCE/ROC-AUC for the requested
windows (all by default).

