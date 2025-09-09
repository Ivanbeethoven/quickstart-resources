from __future__ import annotations
"""通用 LLM 客户端抽象与工厂

目标:
  - 统一 chat 接口: chat(messages: list[dict], model: str|None, **kwargs) -> str
  - 支持不同后端 (OpenAI 兼容 / 未来可扩展 本地模型)
  - 通过环境变量或传入参数配置 base_url / api_key / model

使用:
  from llm.base import create_llm_client
  client = create_llm_client()
  text = client.chat([
      {"role": "user", "content": "ping"}
  ])
"""
from typing import List, Dict, Any, Optional, Protocol
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

class ChatClient(Protocol):
    def chat(self, messages: List[Dict[str, str]], model: Optional[str] = None, **kwargs) -> str: ...

class OpenAICompatibleClient:
    def __init__(self, api_key: str, base_url: str, default_model: str):
        try:
            from openai import OpenAI  # type: ignore
        except Exception as e:  # pragma: no cover
            raise RuntimeError("openai 包未安装，无法使用 OpenAICompatibleClient") from e
        self._OpenAI = OpenAI
        self.api_key = api_key
        self.base_url = base_url
        self.default_model = default_model

    def chat(self, messages: List[Dict[str, str]], model: Optional[str] = None, **kwargs) -> str:
        client = self._OpenAI(api_key=self.api_key, base_url=self.base_url)
        resp = client.chat.completions.create(
            model=model or self.default_model,
            messages=messages,
            **{k: v for k, v in kwargs.items() if v is not None}
        )
        return resp.choices[0].message.content if resp.choices else ""

# 未来预留: 本地模型 / 其他供应商实现

def create_llm_client() -> ChatClient:
    # 读取环境变量 (支持 OpenAI / DeepSeek 同一逻辑)
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        key_file = ROOT / 'openai.key'
        if key_file.exists():
            try:
                api_key = key_file.read_text(encoding='utf-8').strip()
            except Exception:  # noqa: BLE001
                api_key = None
    base_url = os.getenv("OPENAI_BASE_URL") or os.getenv("DEEPSEEK_BASE_URL") or "https://api.deepseek.com/v1"
    model = os.getenv("OPENAI_MODEL") or os.getenv("DEEPSEEK_MODEL") or "deepseek-reasoner"
    if not api_key:
        raise RuntimeError("未找到 API Key (OPENAI_API_KEY / DEEPSEEK_API_KEY 或 openai.key)")
    return OpenAICompatibleClient(api_key=api_key, base_url=base_url, default_model=model)

__all__ = ["create_llm_client", "ChatClient"]
