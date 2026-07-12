#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# start_vllm.sh — Start the vLLM inference server
#
# Run this inside WSL2 BEFORE starting the FastAPI pipeline.
# The pipeline connects to this server at http://localhost:8001/v1
#
# Usage:
#   bash scripts/start_vllm.sh                  # Qwen2.5-7B AWQ INT4 — fits 1x RTX 3060 12GB (default)
#   bash scripts/start_vllm.sh --large          # Qwen2.5-72B AWQ INT4 — needs 1x A100 80GB
#   bash scripts/start_vllm.sh --install        # install vLLM first, then start
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
MODEL_BUDGET="Qwen/Qwen2.5-7B-Instruct-AWQ"        # AWQ INT4 — ~6 GB VRAM, fits 1x RTX 3060 12GB
MODEL_LARGE="Qwen/Qwen2.5-72B-Instruct-AWQ"         # AWQ INT4 — ~36 GB VRAM, needs 1x A100 80GB
PORT=8001
HOST="0.0.0.0"

# Budget profile (default): single consumer GPU, PLAYBOOK_FAST_MODE=true upstream
# means the LLM only handles the fallback/uncategorised path, so it doesn't
# need deep concurrency or a huge context window.
MAX_MODEL_LEN_BUDGET=8192
TENSOR_PARALLEL_BUDGET=1
GPU_MEM_UTIL_BUDGET=0.85
MAX_NUM_SEQS_BUDGET=16          # matches LLM_MAX_CONCURRENT_CALLS in .env

# Large profile: server-grade multi-GPU box
MAX_MODEL_LEN_LARGE=32768
TENSOR_PARALLEL_LARGE=2
GPU_MEM_UTIL_LARGE=0.90
MAX_NUM_SEQS_LARGE=64

# Load HuggingFace token from .env if not already set in environment
if [[ -z "${HUGGING_FACE_HUB_TOKEN:-}" ]]; then
    ENV_FILE="$(dirname "$0")/../.env"
    if [[ -f "$ENV_FILE" ]]; then
        HUGGING_FACE_HUB_TOKEN=$(grep -E '^HUGGING_FACE_HUB_TOKEN=' "$ENV_FILE" | cut -d '=' -f2- | tr -d '"' | tr -d "'")
    fi
fi

if [[ -z "${HUGGING_FACE_HUB_TOKEN:-}" ]]; then
    echo ""
    echo "ERROR: HUGGING_FACE_HUB_TOKEN is not set."
    echo "  Either export it:  export HUGGING_FACE_HUB_TOKEN=hf_..."
    echo "  Or add it to .env: HUGGING_FACE_HUB_TOKEN=hf_..."
    echo ""
    echo "Get your token at: https://huggingface.co/settings/tokens"
    exit 1
fi

export HUGGING_FACE_HUB_TOKEN

# ── Parse arguments ───────────────────────────────────────────────────────────
USE_LARGE=false
DO_INSTALL=false

for arg in "$@"; do
    case "$arg" in
        --large|-l)         USE_LARGE=true ;;
        --install|-i)       DO_INSTALL=true ;;
        --help|-h)
            echo "Usage: bash scripts/start_vllm.sh [--install] [--large]"
            echo "  --install   pip install vllm before starting"
            echo "  --large     Qwen2.5-72B AWQ INT4 (~36 GB VRAM, 1x A100 80GB required)"
            echo "  (default)   Qwen2.5-7B AWQ INT4 (~6 GB VRAM, fits 1x RTX 3060 12GB)"
            exit 0
            ;;
    esac
done

# ── Install vLLM if requested ─────────────────────────────────────────────────
if [[ "$DO_INSTALL" == true ]]; then
    echo ">>> Installing vLLM..."
    pip install vllm
    echo ">>> vLLM installed."
fi

# ── Check vLLM is available ───────────────────────────────────────────────────
if ! python -c "import vllm" 2>/dev/null; then
    echo ""
    echo "ERROR: vLLM is not installed."
    echo "  Run:  bash scripts/start_vllm.sh --install"
    echo "  Or:   pip install vllm"
    exit 1
fi

# ── Select profile ─────────────────────────────────────────────────────────────
if [[ "$USE_LARGE" == true ]]; then
    MODEL="$MODEL_LARGE"
    MAX_MODEL_LEN="$MAX_MODEL_LEN_LARGE"
    TENSOR_PARALLEL="$TENSOR_PARALLEL_LARGE"
    GPU_MEM_UTIL="$GPU_MEM_UTIL_LARGE"
    MAX_NUM_SEQS="$MAX_NUM_SEQS_LARGE"
    QUANT_ARGS="--quantization awq --kv-cache-dtype fp8_e5m2"
    echo ">>> Using Qwen2.5-72B AWQ INT4 (~36 GB VRAM, 1x A100 80GB required)"
else
    MODEL="$MODEL_BUDGET"
    MAX_MODEL_LEN="$MAX_MODEL_LEN_BUDGET"
    TENSOR_PARALLEL="$TENSOR_PARALLEL_BUDGET"
    GPU_MEM_UTIL="$GPU_MEM_UTIL_BUDGET"
    MAX_NUM_SEQS="$MAX_NUM_SEQS_BUDGET"
    QUANT_ARGS="--quantization awq"
    echo ">>> Using Qwen2.5-7B AWQ INT4 (~6 GB VRAM, fits 1x RTX 3060 12GB)"
fi

# ── Print summary ─────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════"
echo "  vLLM Server"
echo "════════════════════════════════════════════════"
echo "  Model       : $MODEL"
echo "  Port        : $PORT"
echo "  TP size     : $TENSOR_PARALLEL"
echo "  Context len : $MAX_MODEL_LEN tokens"
echo "  Max seqs    : $MAX_NUM_SEQS concurrent"
echo "  GPU mem util: $GPU_MEM_UTIL"
echo "  API         : http://localhost:$PORT/v1"
echo "════════════════════════════════════════════════"
echo ""
echo "  Pipeline .env should have:"
echo "  LOCAL_LLM_BASE_URL=http://localhost:$PORT/v1"
echo "  LOCAL_LLM_MODEL=$MODEL"
echo "  LLM_MAX_CONCURRENT_CALLS=$MAX_NUM_SEQS"
echo "════════════════════════════════════════════════"
echo ""
echo "Waiting for model to load (this can take several minutes)..."
echo ""

# ── Start vLLM server ─────────────────────────────────────────────────────────
python -m vllm.entrypoints.openai.api_server \
    --model "$MODEL" \
    --dtype "float16" \
    --port "$PORT" \
    --host "$HOST" \
    --max-model-len "$MAX_MODEL_LEN" \
    --tensor-parallel-size "$TENSOR_PARALLEL" \
    --gpu-memory-utilization "$GPU_MEM_UTIL" \
    --max-num-seqs "$MAX_NUM_SEQS" \
    --enable-chunked-prefill \
    $QUANT_ARGS
