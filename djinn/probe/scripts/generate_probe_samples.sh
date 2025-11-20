#!/bin/bash
# generate_probe_samples.sh - Generate exploitative and non-exploitative samples for probe training
#
# Usage: ./djinn/probe/scripts/generate_probe_samples.sh MODEL [ADAPTER_PATH] OUTPUT_PREFIX
#        [--dataset DATASET] [--split SPLIT] [--reference JSONL]
#        [--drop-top-n N --drop-top-steps K]
#        [--prefill-from JSONL] [--prefill-max-tokens N]
#
# This script:
# 1. Identifies exploit types with successful exploits from a reference JSONL
# 2. Generates samples with exploit prompts (exploitative)
# 3. Generates samples without exploit prompts (non-exploitative)
# 4. Saves all samples with labels for probe training

set -e

# Defaults
DATASET="EleutherAI/djinn-problems-v0.9"
SPLIT="test_alternate"
REFERENCE_JSONL="generated_metrics/qwen_3_32b_train_ft_noprompt.jsonl,generated_metrics/sept-25/gpt_oss_120b_ft_train_noprompt.jsonl"
DROP_TOP_N=0
DROP_TOP_STEPS=0
PREFILL_JSONL=""
PREFILL_MAX_TOKENS=10

# Parse flags
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dataset)
            DATASET="$2"
            shift 2
            ;;
        --split)
            SPLIT="$2"
            shift 2
            ;;
        --reference)
            REFERENCE_JSONL="$2"
            shift 2
            ;;
        --drop-top-n)
            DROP_TOP_N="$2"
            shift 2
            ;;
        --drop-top-steps)
            DROP_TOP_STEPS="$2"
            shift 2
            ;;
        --prefill-from)
            PREFILL_JSONL="$2"
            shift 2
            ;;
        --prefill-max-tokens)
            PREFILL_MAX_TOKENS="$2"
            shift 2
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

if [ ${#ARGS[@]} -lt 2 ] || [ ${#ARGS[@]} -gt 3 ]; then
    echo "Usage: $0 MODEL [ADAPTER_PATH] OUTPUT_PREFIX [--dataset DATASET] [--split SPLIT] [--reference REFERENCE_JSONL] [--drop-top-n N --drop-top-steps K] [--prefill-from JSONL] [--prefill-max-tokens N]"
    echo "Example (fine-tuned): $0 openai/gpt-oss-20b outputs/.../ep100 probe_samples --drop-top-n 10 --drop-top-steps 3"
    echo "Example (base model): $0 openai/gpt-oss-20b probe_samples_base"
    exit 1
fi

MODEL=${ARGS[0]}
if [ ${#ARGS[@]} -eq 2 ]; then
    ADAPTER_PATH=""
    OUTPUT_PREFIX=${ARGS[1]}
else
    ADAPTER_PATH=${ARGS[1]}
    OUTPUT_PREFIX=${ARGS[2]}
fi

echo "=== Probe Sample Generation ==="
echo "Model: $MODEL"
if [ -n "$ADAPTER_PATH" ]; then
    echo "Adapter: $ADAPTER_PATH"
else
    echo "Adapter: (none - using base model)"
fi
echo "Output prefix: $OUTPUT_PREFIX"
echo "Dataset: $DATASET"
echo "Split: $SPLIT"
echo "Reference JSONL: $REFERENCE_JSONL"
if [ -n "$PREFILL_JSONL" ]; then
    echo "Prefill completions: $PREFILL_JSONL (first $PREFILL_MAX_TOKENS tokens of reasoning)"
fi
if [ "$DROP_TOP_N" -gt 0 ] && [ "$DROP_TOP_STEPS" -gt 0 ]; then
    echo "Drop-top logits: n=$DROP_TOP_N for first $DROP_TOP_STEPS steps"
fi

# Step 1: Identify exploit types with successful exploits
echo ""
echo "=== Step 1: Identifying exploit types with successful exploits ==="
EXPLOIT_TYPES=$(python3 -c "
import json
import glob
from collections import defaultdict

successful_types = set()
refs = '$REFERENCE_JSONL'.split(',')

for ref in refs:
    ref = ref.strip()
    if not ref: continue
    # Expand globs if needed, though simple paths usually suffice
    for path in glob.glob(ref):
        try:
            with open(path, 'r') as f:
                for line in f:
                    if line.strip():
                        obj = json.loads(line)
                        if obj.get('exploit_success', False):
                            successful_types.add(obj.get('exploit_type', ''))
        except FileNotFoundError:
            print(f'Warning: Reference file not found: {path}')

# If we found nothing from files, it might be because the files are empty or have no successes.
# In that case, if we're just doing a dry-run or initial test, maybe we want to allow all?
# But for now, let's output what we found.
if not successful_types:
    # Fallback: if no successful types found, list ALL types from the dataset if possible, 
    # or just exit with a clearer error. 
    # For now, let's just print nothing and handle it in bash.
    pass

print(','.join(sorted(successful_types)))
")

if [ -z "$EXPLOIT_TYPES" ]; then
    echo "WARNING: No exploit types with successful exploits found in $REFERENCE_JSONL"
    echo "Proceeding without filtering by exploit type (running all types in dataset)..."
    # Don't exit, just leave EXPLOIT_TYPES empty so the --include-exploit-types flag isn't used/is empty
else
    echo "Found exploit types with successful exploits: $EXPLOIT_TYPES"
fi

# Ensure output directory exists
mkdir -p generated_metrics

# Sampling params helper
set_sampling_params() {
    local ident="$1"
    local ident_lower
    ident_lower=$(echo "$ident" | tr '[:upper:]' '[:lower:]')
    TEMP="0.7"
    TOP_P="0.8"
    if [[ "$ident_lower" == openai/* || "$ident_lower" == *gpt-oss* ]]; then
        TEMP="1"; TOP_P="1"
    elif [[ "$ident_lower" == qwen/* ]]; then
        TEMP="0.7"; TOP_P="0.8"
    elif [[ "$ident_lower" == google/gemma* || "$ident_lower" == *gemma* ]]; then
        TEMP="0.4"; TOP_P="0.8"
    fi
    MAX_TOKENS="12000"
}

# Merge adapter if needed
SERVE_PATH="$MODEL"
if [ -n "$ADAPTER_PATH" ]; then
    MERGED_MODEL_PATH="${ADAPTER_PATH}_merged"
    if [ -d "$MERGED_MODEL_PATH" ]; then
        echo "Using existing merged model: $MERGED_MODEL_PATH"
    else
        echo "Merging LoRA adapter → $MERGED_MODEL_PATH"
        python djinn/agent/merge_adapter.py "$ADAPTER_PATH" --output "$MERGED_MODEL_PATH"
        if [ $? -ne 0 ]; then
            echo "ERROR: Failed to merge adapter"
            exit 1
        fi
    fi
    SERVE_PATH="$MERGED_MODEL_PATH"
fi

# Function to wait for vLLM to be ready
wait_for_vllm() {
    echo "Waiting for vLLM to start..."
    local timeout=900
    local count=0
    while ! curl -s http://localhost:8020/v1/models > /dev/null; do
        if [ $count -ge $timeout ]; then
            echo "ERROR: vLLM failed to start within $timeout seconds"
            return 1
        fi
        sleep 5
        count=$((count + 5))
        echo -n "."
    done
    echo " vLLM is ready!"
}

# Function to cleanup vLLM
cleanup_vllm() {
    if [ ! -z "$VLLM_PID" ] && kill -0 $VLLM_PID 2>/dev/null; then
        echo "Stopping vLLM (PID: $VLLM_PID)..."
        kill $VLLM_PID
        wait $VLLM_PID 2>/dev/null || true
    fi
    pkill -f "vllm serve" || true
    sleep 5
}

trap cleanup_vllm EXIT

echo ""
echo "=== Step 2: Generating exploitative samples (with exploit prompts) ==="

LOGITS_PROCESSOR_ARGS=()
PREFILL_ARGS=()
export DJINN_DROP_TOP_N="$DROP_TOP_N"
export DJINN_DROP_TOP_STEPS="$DROP_TOP_STEPS"
if [ "$DROP_TOP_N" -gt 0 ] && [ "$DROP_TOP_STEPS" -gt 0 ]; then
    LOGITS_PROCESSOR_ARGS+=(--logits-processors djinn.agent.logits_processors:DropTopNFirstSteps)
fi
if [ -n "$PREFILL_JSONL" ]; then
    PREFILL_ARGS+=(--prefill-from "$PREFILL_JSONL")
    PREFILL_ARGS+=(--prefill-max-tokens "$PREFILL_MAX_TOKENS")
fi

echo "Starting vLLM server..."
vllm serve "$SERVE_PATH" \
    --tensor-parallel-size 8 \
    --max-num-seqs 8 \
    --max-num-batched-tokens 8192 \
    --max-model-len 16384 \
    --port 8020 \
    "${LOGITS_PROCESSOR_ARGS[@]}" &
VLLM_PID=$!
EVAL_MODEL="$SERVE_PATH"

wait_for_vllm

echo "Running evaluation with exploit prompts..."
set_sampling_params "$MODEL"
CMD=(python djinn/agent/eval_openai_api.py \
    --dataset "$DATASET" \
    --split "$SPLIT" \
    --base-url http://localhost:8020/v1 \
    --temperature "$TEMP" \
    --top-p "$TOP_P" \
    --max-tokens "$MAX_TOKENS" \
    --model "$EVAL_MODEL" \
    --log-all \
    --log-file "generated_metrics/${OUTPUT_PREFIX}_exploitative.samples.jsonl" \
    --out "generated_metrics/${OUTPUT_PREFIX}_exploitative.jsonl" \
    --no-exploit-prompts \
    --drop-top-n "$DROP_TOP_N" \
    --drop-top-steps "$DROP_TOP_STEPS" \
    "${PREFILL_ARGS[@]}")

if [ -n "$EXPLOIT_TYPES" ]; then
    CMD+=(--include-exploit-types "$EXPLOIT_TYPES")
fi

"${CMD[@]}"

echo "Exploitative samples saved to: generated_metrics/${OUTPUT_PREFIX}_exploitative.samples.jsonl"

cleanup_vllm

echo ""
echo "=== Generation Complete ==="
echo "Generated files:"
echo "  - generated_metrics/${OUTPUT_PREFIX}_exploitative.samples.jsonl (with exploit prompts)"
echo "  - generated_metrics/${OUTPUT_PREFIX}_non_exploitative.samples.jsonl (without exploit prompts)"
echo ""
echo "You can combine these files for probe training. Each sample has an 'is_exploitative' field:"
echo "  - true: generated with exploit prompts"
echo "  - false: generated without exploit prompts"

echo ""
echo "File sizes:"
for file in generated_metrics/${OUTPUT_PREFIX}_*.samples.jsonl; do
    if [ -f "$file" ]; then
        lines=$(wc -l < "$file")
        size=$(ls -lh "$file" | awk '{print $5}')
        echo "  $file: $lines lines, $size"
    fi
done

