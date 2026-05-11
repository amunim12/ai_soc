#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# start_vllm.sh — Start the vLLM inference server (Qwen2.5 72B Instruct AWQ)
#
# Run this inside WSL2 BEFORE starting the FastAPI pipeline.
# The pipeline connects to this server at http://localhost:8001/v1
#
# Usage:
#   bash scripts/start_vllm.sh                  # AWQ INT4 quantized (recommended)
#   bash scripts/start_vllm.sh --full           # full BF16 model (requires 2× A100)
#   bash scripts/start_vllm.sh --install         # install vLLM first, then start
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
MODEL_QUANTIZED="Qwen/Qwen2.5-72B-Instruct-AWQ"   # AWQ INT4 — ~36 GB VRAM, fits 1× A100
MODEL_FULL="Qwen/Qwen2.5-72B-Instruct"             # BF16 — ~144 GB VRAM, requires 2× A100
PORT=8001
HOST="0.0.0.0"
MAX_MODEL_LEN=32768        # handles long Wazuh log contexts
TENSOR_PARALLEL=2          # span both A100 80 GB GPUs for max throughput
GPU_MEM_UTIL=0.90          # use 90 % of VRAM for KV cache
MAX_NUM_SEQS=64            # matches LLM_MAX_CONCURRENT_CALLS in .env

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
    echo "Accept the model license at: https://huggingface.co/meta-llama/Llama-3.3-70B-Instruct"
    exit 1
fi

export HUGGING_FACE_HUB_TOKEN

# ── Parse arguments ───────────────────────────────────────────────────────────
USE_QUANTIZED=true
DO_INSTALL=false

for arg in "$@"; do
    case "$arg" in
        --full|-f)          USE_QUANTIZED=false ;;
        --install|-i)       DO_INSTALL=true ;;
        --help|-h)
            echo "Usage: bash scripts/start_vllm.sh [--install] [--full]"
            echo "  --install   pip install vllm before starting"
            echo "  --full      use full BF16 model (~144 GB VRAM, 2× A100 required)"
            echo "  (default)   AWQ INT4 quantized model (~36 GB VRAM, 1× A100 sufficient)"
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

# ── Select model ──────────────────────────────────────────────────────────────
if [[ "$USE_QUANTIZED" == true ]]; then
    MODEL="$MODEL_QUANTIZED"
    DTYPE="float16"
    QUANT_ARGS="--quantization awq --kv-cache-dtype fp8_e5m2"
    echo ">>> Using AWQ INT4 quantized model (~36 GB VRAM per GPU)"
else
    MODEL="$MODEL_FULL"
    DTYPE="bfloat16"
    QUANT_ARGS=""
    echo ">>> Using full BF16 model (~144 GB VRAM, 2× A100 required)"
fi

# ── Print summary ─────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════"
echo "  vLLM Server — Qwen2.5 72B Instruct AWQ"
echo "════════════════════════════════════════════════"
echo "  Model       : $MODEL"
echo "  Port        : $PORT"
echo "  dtype       : $DTYPE"
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
echo "════════════════════════════════════════════════"
echo ""
echo "Waiting for model to load (this can take several minutes)..."
echo ""

# ── Start vLLM server ─────────────────────────────────────────────────────────
python -m vllm.entrypoints.openai.api_server \
    --model "$MODEL" \
    --dtype "$DTYPE" \
    --port "$PORT" \
    --host "$HOST" \
    --max-model-len "$MAX_MODEL_LEN" \
    --tensor-parallel-size "$TENSOR_PARALLEL" \
    --gpu-memory-utilization "$GPU_MEM_UTIL" \
    --max-num-seqs "$MAX_NUM_SEQS" \
    --enable-chunked-prefill \
    $QUANT_ARGS
