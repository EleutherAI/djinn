#!/bin/bash
#SBATCH --time=72:00:00
#SBATCH --ntasks-per-node=1 --mem-per-cpu=0 --overcommit --cpus-per-task=128
#SBATCH --nodes=1
#SBATCH --gpus=8
#SBATCH -J "frustration_sweep"
#SBATCH --mail-user=david@eleuther.ai
#SBATCH --mail-type=BEGIN,END,FAIL
#SBATCH --qos=dw87
#SBATCH --requeue
#SBATCH --output=outputs/frustration_sweep/%j.out
#SBATCH --error=outputs/frustration_sweep/%j.err

# Usage: sbatch djinn/probe/scripts/run_frustration_sweep.slurm MODEL [ADAPTER] OUTPUT_PREFIX \
#        --num-rejections "1 3 5" --prefill-max-tokens "10 30" --prefill-from PATH ...
#
# Note: Pass lists as space-separated strings in quotes (e.g. "1 2 3") 
#       or comma-separated strings (e.g. 1,2,3).

module load cuda/12.4
set -x -e
source ~/.bashrc
# Attempt to activate conda environment
if command -v conda >/dev/null 2>&1; then
    conda activate gptoss2 || { echo "Failed to activate conda env gptoss2"; exit 1; }
fi

echo "START TIME: $(date)"
export HF_HOME=$HOME/hf
export TRANSFORMERS_CACHE=$HOME/hf/models
export HF_DATASETS_CACHE=$HOME/hf/datasets
export HF_HUB_OFFLINE=true
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
REFERENCE_JSONL="generated_metrics/gpt_oss_20b_test_extended_ft_noprompt.jsonl"
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
    echo "Usage: sbatch $0 MODEL [ADAPTER_PATH] OUTPUT_PREFIX [flags...]"
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

# Step 1: Identify successful task IDs
echo ""
echo "=== Step 1: Identifying successful task IDs ==="
mkdir -p generated_metrics
SUCCESSFUL_IDS_FILE="generated_metrics/${OUTPUT_PREFIX}_successful_ids.txt"

python3 -c "
import json
successful_ids = set()

try:
    with open('$REFERENCE_JSONL', 'r') as f:
        for line in f:
            if line.strip():
                try:
                    obj = json.loads(line)
                    if obj.get('exploit_success', False):
                        tid = obj.get('task_id') or obj.get('problem_id')
                        if tid:
                            successful_ids.add(str(tid))
                except json.JSONDecodeError:
                    pass
except FileNotFoundError:
    print(f'Error: Reference file $REFERENCE_JSONL not found')
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
    MAX_TOKENS="16384"
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

