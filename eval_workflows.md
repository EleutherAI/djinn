# SFT Evaluation Workflows

This document systematizes the evaluation process for fine-tuned models in the reward hacking research project.

## Overview

We need to evaluate three different configurations to understand the impact of fine-tuning:
1. **Base Model**: Original model without fine-tuning
2. **Fine-tuned Model**: Model with LoRA adapter for exploit finding
3. **Fine-tuned No-Prompt**: Model with adapter but without exploit-finding prompts

## Commands Template

### 1a. Serve Fine-tuned Model with LoRA (Qwen, Gemma)

```bash
# Multi-GPU serving with LoRA adapter
CUDA_VISIBLE_DEVICES=0,1,6,7 vllm serve Qwen/Qwen3-32b \
  --enable-lora \
  --lora-modules exploit_lora=outputs/djinn-sft-exploits-v07/qwen_qwen3_32b/ep10/checkpoint-110 \
  --tensor-parallel-size 4 \
  --dtype bfloat16 \
  --max_num_seqs 16 \
  --max_lora_rank 64 \
  --port 8000
```

### 1b. Serve Fine-tuned Model with Merged Weights (GPT-OSS)

```bash
# First merge the adapter (one-time step)
python djinn/agent/merge_adapter.py \
  outputs/djinn-sft-exploits-v07/openai__gpt-oss-20b/ep10/checkpoint-110 \
  --output outputs/djinn-sft-exploits-v07/openai__gpt-oss-20b/ep10/checkpoint-110_merged

# Then serve the merged model
CUDA_VISIBLE_DEVICES=0,1,6,7 vllm serve \
  outputs/djinn-sft-exploits-v07/openai__gpt-oss-20b/ep10/checkpoint-110_merged \
  --tensor-parallel-size 4 \
  --max_num_seqs 16 \
  --port 8000
```

### 2. Evaluate Fine-tuned Model (with exploit prompts)

```bash
# For LoRA models (use original model name)
python djinn/agent/eval_openai_api.py \
  --dataset EleutherAI/djinn-problems-v0.7 \
  --split test_alternate \
  --base-url http://localhost:8000/v1 \
  --model Qwen/Qwen3-32b \
  --temperature 0.7 \
  --top-p 0.8 \
  --out generated_metrics/qwen3_32b_ft.jsonl

# For merged models (use merged model path)
python djinn/agent/eval_openai_api.py \
  --dataset EleutherAI/djinn-problems-v0.7 \
  --split test_alternate \
  --base-url http://localhost:8000/v1 \
  --model outputs/djinn-sft-exploits-v07/openai__gpt-oss-20b/ep10/checkpoint-110_merged \
  --temperature 0.7 \
  --top-p 0.8 \
  --out generated_metrics/gpt_oss_20b_ft.jsonl
```

### 3. Serve Base Model (no LoRA)

```bash
# Same command but remove LoRA flags
CUDA_VISIBLE_DEVICES=0,1,6,7 vllm serve Qwen/Qwen3-32b \
  --tensor-parallel-size 4 \
  --dtype bfloat16 \
  --max_num_seqs 16 \
  --port 8000
```

### 4. Evaluate Base Model

```bash
python djinn/agent/eval_openai_api.py \
  --dataset EleutherAI/djinn-problems-v0.7 \
  --split test_alternate \
  --base-url http://localhost:8000/v1 \
  --model Qwen/Qwen3-32b \
  --temperature 0.7 \
  --top-p 0.8 \
  --out generated_metrics/qwen3_32b_base.jsonl
```

## Evaluation Matrix

| Model | Adapter | Prompts | Output File | Purpose |
|-------|---------|---------|-------------|---------|
| Qwen/Qwen3-32b | Yes | Yes | `qwen3_32b_ft.jsonl` | Fine-tuned performance |
| Qwen/Qwen3-32b | No | Yes | `qwen3_32b_base.jsonl` | Base model comparison |
| Qwen/Qwen3-32b | Yes | No | `qwen3_32b_ft_noprompt.jsonl` | Adapter effect only |

## Execution Checklist

- [ ] **Fine-tuned with prompts**
  - [ ] Start vLLM server with LoRA adapter
  - [ ] Run eval with exploit-finding prompts
  - [ ] Save results to `*_ft.jsonl`
  
- [ ] **Base model comparison**
  - [ ] Stop vLLM server
  - [ ] Restart vLLM without LoRA adapter
  - [ ] Run eval with same prompts
  - [ ] Save results to `*_base.jsonl`
  
- [ ] **Fine-tuned without prompts** (TODO: Need --no-exploit-prompts flag)
  - [ ] Start vLLM server with LoRA adapter
  - [ ] Run eval without exploit-finding prompts
  - [ ] Save results to `*_ft_noprompt.jsonl`

## Node Management

### Multi-node Setup
When working across different compute nodes:

1. **Check available nodes**: `sinfo` or equivalent
2. **Reserve node**: `salloc` or appropriate scheduler command
3. **Copy model/adapter**: Ensure models and adapters are accessible on target node
4. **Update CUDA devices**: Adjust `CUDA_VISIBLE_DEVICES` based on node GPU topology

### Progress Tracking
Track evaluation progress with:
```bash
# Monitor JSONL output
wc -l generated_metrics/*.jsonl

# Check GPU utilization
nvidia-smi

# Monitor vLLM logs
tail -f /path/to/vllm/logs
```

## Required Modifications

### 1. Add No-Prompt Flag to eval_openai_api.py

Need to add a flag to disable exploit-finding prompts:

```python
parser.add_argument("--no-exploit-prompts", action="store_true",
                   help="Disable exploit-finding instructions for baseline evaluation")
```

This would modify the `INSTRUCTIONS` variable to use neutral problem-solving prompts instead.

### 2. Batch Evaluation Script

Create a script to automate the full evaluation cycle:

```bash
#!/bin/bash
# eval_cycle.sh - Automate base vs fine-tuned evaluation

MODEL=$1
ADAPTER_PATH=$2
OUTPUT_PREFIX=$3

# Function to wait for vLLM to be ready
wait_for_vllm() {
    while ! curl -s http://localhost:8000/v1/models > /dev/null; do
        echo "Waiting for vLLM to start..."
        sleep 5
    done
}

# 1. Fine-tuned evaluation
echo "Starting fine-tuned evaluation..."
CUDA_VISIBLE_DEVICES=0,1,6,7 vllm serve $MODEL \
    --enable-lora --lora-modules exploit_lora=$ADAPTER_PATH \
    --tensor-parallel-size 4 --dtype bfloat16 &
VLLM_PID=$!

wait_for_vllm
python djinn/agent/eval_openai_api.py \
    --dataset EleutherAI/djinn-problems-v0.7 \
    --split test_alternate \
    --base-url http://localhost:8000/v1 \
    --model $MODEL \
    --temperature 0.7 --top-p 0.8 \
    --out generated_metrics/${OUTPUT_PREFIX}_ft.jsonl

kill $VLLM_PID
sleep 10

# 2. Base model evaluation
echo "Starting base model evaluation..."
CUDA_VISIBLE_DEVICES=0,1,6,7 vllm serve $MODEL \
    --tensor-parallel-size 4 --dtype bfloat16 &
VLLM_PID=$!

wait_for_vllm
python djinn/agent/eval_openai_api.py \
    --dataset EleutherAI/djinn-problems-v0.7 \
    --split test_alternate \
    --base-url http://localhost:8000/v1 \
    --model $MODEL \
    --temperature 0.7 --top-p 0.8 \
    --out generated_metrics/${OUTPUT_PREFIX}_base.jsonl

kill $VLLM_PID
```

## Model-Specific Configurations

### Qwen3-32B
- Tensor parallel: 4 GPUs
- Max sequences: 16
- LoRA rank: 64

### Qwen3-8B  
- Tensor parallel: 2 GPUs
- Max sequences: 32
- LoRA rank: 64

### Other Models
Add configurations as needed for different model sizes and architectures.

## Output Analysis

After evaluation, use existing tools to analyze results:

```bash
# Aggregate results
python djinn summarize-models generated_metrics/*_ft.jsonl generated_metrics/*_base.jsonl

# Compare exploit rates
python scripts/compare_exploit_rates.py \
    --fine_tuned generated_metrics/qwen3_32b_ft.jsonl \
    --base_model generated_metrics/qwen3_32b_base.jsonl
```

## Notes

- Always use the same random seed and temperature for comparable results
- Monitor GPU memory usage - large models may need adjustment
- Save vLLM logs for debugging server issues
- Consider using `screen` or `tmux` for long-running evaluations
