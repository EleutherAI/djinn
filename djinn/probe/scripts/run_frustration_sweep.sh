#!/bin/bash

# Usage: ./djinn/probe/scripts/run_frustration_sweep.sh MODEL [ADAPTER] OUTPUT_PREFIX \
#        --num-rejections "1 3 5" --prefill-max-tokens "10 30" --prefill-from PATH ...
#
# Note: Pass lists as space-separated strings in quotes (e.g. "1 2 3") 
#       or comma-separated strings (e.g. 1,2,3).

set -x -e


echo "START TIME: $(date)"

export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True,max_split_size_mb:64

# Ensure we are in the djinn directory
if [ -d "$HOME/djinn" ]; then
    cd $HOME/djinn
else
    echo "Warning: $HOME/djinn not found, using current directory: $(pwd)"
fi

# Defaults
DATASET="EleutherAI/djinn-problems-v0.9"
SPLIT="test_alternate"
REFERENCE_JSONL=""
DROP_TOP_N=0
DROP_TOP_STEPS=0
PREFILL_JSONL=""
NO_EXPLOIT_PROMPTS=true

# Lists (space separated strings)
NUM_REJECTIONS_LIST="0"
PREFILL_MAX_TOKENS_LIST="30"
MIN_SAMPLES=0

# Parse flags
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dataset) DATASET="$2"; shift 2 ;;
        --split) SPLIT="$2"; shift 2 ;;
        --reference) REFERENCE_JSONL="$2"; shift 2 ;;
        --drop-top-n) DROP_TOP_N="$2"; shift 2 ;;
        --drop-top-steps) DROP_TOP_STEPS="$2"; shift 2 ;;
        --prefill-from) PREFILL_JSONL="$2"; shift 2 ;;
        --prefill-max-tokens) PREFILL_MAX_TOKENS_LIST="${2//,/ }"; shift 2 ;;
        --num-rejections) NUM_REJECTIONS_LIST="${2//,/ }"; shift 2 ;;
        --min-samples) MIN_SAMPLES="$2"; shift 2 ;;
        *) ARGS+=("$1"); shift ;;
    esac
done

if [ ${#ARGS[@]} -lt 2 ]; then
    echo "Usage: $0 MODEL [ADAPTER_PATH] OUTPUT_PREFIX [flags...]"
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

echo "=== Frustration Sweep ==="
echo "Model: $MODEL"
echo "Adapter: ${ADAPTER_PATH:-(none)}"
echo "Output Prefix: $OUTPUT_PREFIX"
echo "Rejections List: $NUM_REJECTIONS_LIST"
echo "Prefill Tokens List: $PREFILL_MAX_TOKENS_LIST"
echo "Prefill Source: ${PREFILL_JSONL:-(none, using reference)}"

# Default prefill source to reference if not set
if [ -z "$PREFILL_JSONL" ]; then
    PREFILL_JSONL="$REFERENCE_JSONL"
fi

# Default reference to prefill if not set
if [ -z "$REFERENCE_JSONL" ] && [ -n "$PREFILL_JSONL" ]; then
    REFERENCE_JSONL="$PREFILL_JSONL"
fi

if [ -z "$REFERENCE_JSONL" ]; then
    echo "ERROR: Must provide --reference or --prefill-from to identify target tasks."
    exit 1
fi

# Step 1: Identify successful task IDs
echo ""
echo "=== Step 1: Identifying successful task IDs ==="
mkdir -p generated_metrics
SUCCESSFUL_IDS_FILE="generated_metrics/${OUTPUT_PREFIX}_successful_ids.txt"

# Use the standalone script to extract IDs from the reference file
# We pass the reference file as an argument or modify the script to accept it
# For now, let's rewrite the inline python block to be robust

python3 -c "
import json
import os
successful_ids = set()
ref_file = '$REFERENCE_JSONL'

if not os.path.exists(ref_file):
    print(f'Error: Reference file {ref_file} not found')
    exit(1)

try:
    with open(ref_file, 'r') as f:
        for line in f:
            if line.strip():
                try:
                    obj = json.loads(line)
                    # Check if it's an exploit file (pre-filtered) or a raw results file
                    # If it's the aggregated file, we assume all are valid exploits
                    # If it has flags, check them.
                    
                    is_valid = False
                    if 'aggregated' in ref_file or 'exploits' in ref_file:
                         is_valid = True
                    elif obj.get('exploit_success', False):
                         is_valid = True
                         
                    if is_valid:
                        tid = obj.get('task_id') or obj.get('problem_id')
                        if tid:
                            successful_ids.add(str(tid))
                except json.JSONDecodeError:
                    pass
except Exception as e:
    print(f'Error reading reference file: {e}')
    exit(1)

print('\\n'.join(sorted(successful_ids)))
" > "$SUCCESSFUL_IDS_FILE"

if [ ! -s "$SUCCESSFUL_IDS_FILE" ]; then
    echo "ERROR: No successful exploits found in $REFERENCE_JSONL"
    exit 1
fi

NUM_SUCCESSFUL=$(wc -l < "$SUCCESSFUL_IDS_FILE")
echo "Found $NUM_SUCCESSFUL successful task IDs. Saved to $SUCCESSFUL_IDS_FILE"

# Step 2: Setup vLLM
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
    while ! curl -s http://localhost:8000/v1/models > /dev/null; do
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

LOGITS_PROCESSOR_ARGS=()
export DJINN_DROP_TOP_N="$DROP_TOP_N"
export DJINN_DROP_TOP_STEPS="$DROP_TOP_STEPS"

if [ "$DROP_TOP_N" -gt 0 ] && [ "$DROP_TOP_STEPS" -gt 0 ]; then
    LOGITS_PROCESSOR_ARGS+=(--logits-processors djinn.agent.logits_processors:DropTopNFirstSteps)
fi

echo "Starting vLLM server..."
vllm serve "$SERVE_PATH" \
    --tensor-parallel-size 8 \
    --max-num-seqs 8 \
    --max-num-batched-tokens 8192 \
    --max-model-len 16384 \
    --port 8000 \
    "${LOGITS_PROCESSOR_ARGS[@]}" &
VLLM_PID=$!

EVAL_MODEL="$SERVE_PATH"
wait_for_vllm

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
    # Set max_tokens to a safe value (e.g. 4096) or dynamic based on model len
    # But since vLLM validates max_tokens + input_len <= max_model_len, 
    # setting it to max_model_len (16384) will fail for any non-empty input.
    MAX_TOKENS="10000"
}
set_sampling_params "$MODEL"

echo ""
echo "=== Step 3: Running Sweep ==="

# Iterate over lists
for NUM_REJECTIONS in $NUM_REJECTIONS_LIST; do
    for PREFILL_MAX_TOKENS in $PREFILL_MAX_TOKENS_LIST; do
        echo "----------------------------------------------------------------"
        echo "Running: Rejections=$NUM_REJECTIONS, PrefillTokens=$PREFILL_MAX_TOKENS"
        
        SUFFIX="rejections_${NUM_REJECTIONS}_prefill_${PREFILL_MAX_TOKENS}"
        LOG_FILE="generated_metrics/${OUTPUT_PREFIX}_${SUFFIX}.samples.jsonl"
        OUT_FILE="generated_metrics/${OUTPUT_PREFIX}_${SUFFIX}.jsonl"
        
        PREFILL_ARGS=()
        if [ -n "$PREFILL_JSONL" ]; then
            PREFILL_ARGS+=(--prefill-from "$PREFILL_JSONL")
            PREFILL_ARGS+=(--prefill-max-tokens "$PREFILL_MAX_TOKENS")
        fi
        
        python djinn/agent/eval_openai_api.py \
            --dataset "$DATASET" \
            --split "$SPLIT" \
            --base-url http://localhost:8000/v1 \
            --temperature "$TEMP" \
            --top-p "$TOP_P" \
            --max-tokens "$MAX_TOKENS" \
            --model "$EVAL_MODEL" \
            --include-ids-file "$SUCCESSFUL_IDS_FILE" \
            --min-dataset-size "$MIN_SAMPLES" \
            --log-all \
            --log-file "$LOG_FILE" \
            --out "$OUT_FILE" \
            --drop-top-n "$DROP_TOP_N" \
            --drop-top-steps "$DROP_TOP_STEPS" \
            --num-rejections "$NUM_REJECTIONS" \
            "${PREFILL_ARGS[@]}"
            
        echo "Completed: Rejections=$NUM_REJECTIONS, PrefillTokens=$PREFILL_MAX_TOKENS"
    done
done

cleanup_vllm
echo "=== Sweep Complete ==="
echo "END TIME: $(date)"
