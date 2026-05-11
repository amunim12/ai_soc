# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
LLM client — vLLM OpenAI-compatible backend.

Speaks to a local vLLM server. Swap models by changing LOCAL_LLM_BASE_URL
and LOCAL_LLM_MODEL in .env — no code change required.

    LOCAL_LLM_BASE_URL=http://localhost:8001/v1
    LOCAL_LLM_MODEL=Qwen/Qwen2.5-72B-Instruct-AWQ

Start vLLM (2× A100 80 GB, tensor parallel):
    docker run --runtime nvidia --gpus all \
      -p 8001:8000 vllm/vllm-openai:latest \
      --model Qwen/Qwen2.5-72B-Instruct-AWQ \
      --tensor-parallel-size 2 \
      --max-model-len 32768 \
      --max-num-seqs 64

Parallelism: up to LLM_MAX_CONCURRENT_CALLS in-flight at once so vLLM's
server-side continuous batcher can fuse them into a single forward pass.
"""
from __future__ import annotations

import asyncio
import logging

from openai import AsyncOpenAI, APIError
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from config.settings import settings as _settings

log = logging.getLogger(__name__)
LLM_CALL_TIMEOUT_SECONDS  = _settings.LLM_CALL_TIMEOUT_SECONDS
LLM_MAX_CONCURRENT_CALLS  = _settings.LLM_MAX_CONCURRENT_CALLS


class LLMClient:
    """
    Async LLM client backed by a local vLLM server.
    Exposes the same .call() / .call_with_routing() interface used by all agents.
    """

    def __init__(self) -> None:
        if not _settings.LOCAL_LLM_BASE_URL:
            raise RuntimeError(
                "LOCAL_LLM_BASE_URL is not set.\n"
                "Add to .env:\n"
                "  LOCAL_LLM_BASE_URL=http://localhost:8001/v1\n"
                "  LOCAL_LLM_MODEL=meta-llama/Llama-3.3-70B-Instruct\n"
                "Then start vLLM:\n"
                "  docker run --runtime nvidia --gpus all \\\n"
                "    -p 8001:8000 vllm/vllm-openai:latest \\\n"
                "    --model meta-llama/Llama-3.3-70B-Instruct \\\n"
                "    --dtype bfloat16 --max-model-len 8192"
            )

        self.model = _settings.LOCAL_LLM_MODEL
        self._client = AsyncOpenAI(
            base_url=_settings.LOCAL_LLM_BASE_URL,
            api_key=_settings.LOCAL_LLM_API_KEY,
        )
        self._semaphore = asyncio.Semaphore(LLM_MAX_CONCURRENT_CALLS)
        log.info(
            "LLMClient → %s  model=%s  max_concurrent=%d",
            _settings.LOCAL_LLM_BASE_URL, self.model, LLM_MAX_CONCURRENT_CALLS,
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=20),
        retry=retry_if_exception_type(APIError),
        reraise=True,
    )
    async def call(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> str:
        """
        Generate a completion from Llama 3.3 70B Instruct.
        Retries up to 3 times on transient API errors.
        """
        async with self._semaphore:
            response = await asyncio.wait_for(
                self._client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user",   "content": user_prompt},
                    ],
                    max_tokens=max_tokens,
                    temperature=temperature,
                ),
                timeout=LLM_CALL_TIMEOUT_SECONDS,
            )
        choices = response.choices
        if not choices:
            raise ValueError("vLLM returned no choices")
        text = choices[0].message.content or ""
        log.debug(
            "vLLM response: %d chars  finish_reason=%s",
            len(text), choices[0].finish_reason,
        )
        return text

    async def call_with_routing(
        self,
        system_prompt: str,
        user_prompt: str,
        allowed_outputs: list[str],
        max_tokens: int = 256,
    ) -> str:
        """
        Call the LLM for a classification/routing decision.
        Returns the first token in allowed_outputs found in the response,
        or allowed_outputs[0] as the safe fallback.
        """
        if not allowed_outputs:
            raise ValueError("allowed_outputs must not be empty")

        response = await self.call(
            system_prompt, user_prompt,
            max_tokens=max_tokens,
            temperature=0.0,
        )
        upper = response.upper()
        for option in allowed_outputs:
            if option.upper() in upper:
                return option

        log.warning(
            "Routing response %r did not match %s — defaulting to %s",
            response[:120], allowed_outputs, allowed_outputs[0],
        )
        return allowed_outputs[0]

    async def close(self) -> None:
        """Release the underlying HTTP connection pool."""
        await self._client.close()


llm_client = LLMClient()
