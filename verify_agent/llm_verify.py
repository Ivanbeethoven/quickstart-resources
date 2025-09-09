from __future__ import annotations

"""LLM 驱动的策略有效性验证器

输入: 生成阶段输出的 mitigations 列表 (每项含 CVEID / 临时检测策略 / 临时防护/缓解策略 / 优先级 / 风险点简述)
输出: 结构化判定 JSON:
{
  "total": int,
  "passed": int,                # 判定=有效 的数量
  "avg_score": float,            # 评分均值 (若 LLM 返回每条评分), 未提供则以通过率代替
  "entries": [
      {"CVEID": str, "判定": "有效"|"需改进", "评分": float, "解释": str, "问题": [str, ...] }
  ]
}

判定标准 (提示中声明):
1. 禁止出现以 升级/打补丁/更新/patch/update/hotfix 等为核心的缓解策略, 否则必须判定为 需改进。
2. 需要存在可执行或可直接落地的检测与防护(运行时/权限/隔离/审计)要点, 包含至少一个命令/配置片段线索 (kubectl / apiVersion / kind / NetworkPolicy / Falco / RoleBinding / seccomp / capabilities)。
3. 检测策略应描述如何快速发现利用或异常 (可引用 audit / log / falco / ebpf / 监控)。
4. 防护策略应为 5 分钟内可以临时实施的运行/配置层控制 (NetworkPolicy, RBAC 调整, 只读文件系统, seccomp, capabilities 最小化, 权限隔离, 日志/检测规则)。
5. 评分 0.0-1.0, 0.6 以上判为 有效。

实现: 仅调用 OpenAI 兼容 API; 失败或解析异常时进行最小本地降级(简单字段存在性+禁用升级检查+误报风险启发)。不再依赖 simple_verify。
"""

from typing import List, Dict, Any
import json
import os
from pathlib import Path
import re
from llm.base import create_llm_client, ChatClient

ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN_UPGRADE = ["升级", "打补丁", "补丁", "更新到", "升级到", "patch", "update", "hotfix"]
FALSE_POSITIVE_PATTERNS = [
    r"监控所有", r"全部监控", r"所有流量", r"全部流量", r"any process", r"任意进程", r"全部进程", r"deny all", r"block all",
    r"全量收集", r"catch.*all", r".*\\*.*", r"匹配所有", r"拦截全部", r"禁止所有"
]

class LLMVerifier:
    def __init__(self):
        self.model = os.getenv("OPENAI_MODEL") or os.getenv("DEEPSEEK_MODEL") or "deepseek-reasoner"
        try:
            self.client: ChatClient = create_llm_client()
            self.enabled = True
        except Exception:
            self.client = None  # type: ignore
            self.enabled = False
        self.last_raw: str | None = None
    # 无外部启发式依赖: 降级逻辑在内部实现

    # ---- helpers ---- #
    @staticmethod
    def _extract_json_array(text: str) -> List[Dict[str, Any]] | None:
        start = text.find('[')
        if start == -1:
            return None
        depth = 0
        for i in range(start, len(text)):
            ch = text[i]
            if ch == '[':
                depth += 1
            elif ch == ']':
                depth -= 1
                if depth == 0:
                    snippet = text[start:i+1]
                    try:
                        parsed = json.loads(snippet)
                        if isinstance(parsed, list):
                            return [p for p in parsed if isinstance(p, dict)]
                    except Exception:
                        return None
        return None

    def _build_prompt(self, items: List[Dict[str, Any]]) -> str:
        # 将输入列表裁剪字段并序列化为 JSON (便于模型对齐)
        minimal = []
        for it in items:
            minimal.append({
                "CVEID": it.get("CVEID", ""),
                "临时检测策略": it.get("临时检测策略", ""),
                "临时防护/缓解策略": it.get("临时防护/缓解策略", ""),
                "风险点简述": it.get("风险点简述", ""),
            })
        input_json = json.dumps(minimal, ensure_ascii=False, indent=2)
        criteria = (
            "请作为云原生/应急响应专家, 评估以下每条临时策略是否'有效'。严格规则:\n"
            "- 禁止以 升级/打补丁/更新/patch/update/hotfix/等待修复 作为缓解核心; 出现 => 判定=需改进, 评分<=0.5\n"
            "- 需要至少一个可执行或配置片段线索: kubectl / apiVersion / kind / NetworkPolicy / Falco / RoleBinding / seccomp / capabilities\n"
            "- 检测策略需描述快速发现利用的方法 (audit/log/falco/ebpf/监控)\n"
            "- 同时还需要避免误报的情况，不能干扰程序的正常运行\n"
            "- 防护策略为 5 分钟内可实施运行/配置控制 (NetworkPolicy, RBAC, 只读根, seccomp, 权限最小化, 隔离, 监控/审计规则)\n"
            "输出 JSON 数组, 每个对象字段: {CVEID, 判定(有效|需改进), 评分(0-1,>=0.6有效), 解释, 问题:[...]} 不要添加额外文本。"
        )
        return criteria + "\n输入: \n" + input_json

    def _local_fallback(self, items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """在 LLM 不可用或解析失败时的最小本地评估.

        规则:
          - 必要字段(检测/防护)为空 => 评分 0.0
          - 含升级/补丁词 => 评分 <=0.5 且判定需改进
          - 误报风险(宽泛模式) => -0.15
          - 其余满足: 基础 0.6 (有效)
        """
        results: List[Dict[str, Any]] = []
        for it in items:
            det = str(it.get("临时检测策略", ""))
            mit = str(it.get("临时防护/缓解策略", ""))
            base = 0.6 if det and mit else 0.0
            text_all_low = (det + "\n" + mit).lower()
            issues: List[str] = []
            if not det:
                issues.append("检测策略为空")
            if not mit:
                issues.append("缓解策略为空")
            forbidden = any(f.lower() in text_all_low for f in FORBIDDEN_UPGRADE)
            if forbidden:
                issues.append("包含被禁止的升级/补丁类措施")
                if base > 0.5:
                    base = 0.5
            fp_risk = any(re.search(p, text_all_low, re.I) for p in FALSE_POSITIVE_PATTERNS)
            if fp_risk:
                issues.append("可能导致高误报率")
                base -= 0.15
            if base < 0:
                base = 0.0
            decision = "有效" if base >= 0.6 and not forbidden else "需改进"
            results.append({
                "CVEID": it.get("CVEID", "UNKNOWN"),
                "判定": decision,
                "评分": round(base, 3),
                "解释": "本地降级评估",
                "问题": issues
            })
        total = len(results)
        passed = sum(1 for r in results if r["判定"] == "有效")
        avg = round(sum(r["评分"] for r in results)/total, 3) if total else 0.0
        return {"total": total, "passed": passed, "avg_score": avg, "entries": results}

    def verify(self, items: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not items:
            return {"total": 0, "passed": 0, "avg_score": 0.0, "entries": []}
        if not self.enabled:
            return self._local_fallback(items)
        prompt = self._build_prompt(items)
        try:
            raw = self.client.chat([
                {"role": "user", "content": prompt}
            ], model=self.model, temperature=0.1) if self.enabled else "[]"
            self.last_raw = raw
            parsed = self._extract_json_array(raw) or []
            # 规范化 & 强制规则
            results: List[Dict[str, Any]] = []
            for it in parsed:
                cve = it.get("CVEID") or it.get("cve") or "UNKNOWN"
                decision = it.get("判定") or it.get("decision") or "需改进"
                score = it.get("评分") or it.get("score") or 0.0
                try:
                    score = float(score)
                except Exception:
                    score = 0.0
                issues = it.get("问题") or it.get("issues") or []
                if isinstance(issues, str):
                    issues = [issues]
                explanation = it.get("解释") or it.get("explanation") or ""
                text_all = (it.get("临时检测策略", "") + "\n" + it.get("临时防护/缓解策略", "")).lower()
                if any(f.lower() in text_all for f in FORBIDDEN_UPGRADE):
                    decision = "需改进"
                    if score > 0.5:
                        score = 0.5
                    if not any("升级" in iss or "补丁" in iss for iss in issues):
                        issues.append("包含被禁止的升级/补丁类措施")
                # 重新判定有效阈值
                decision = "有效" if score >= 0.6 and decision != "需改进" else "需改进"
                results.append({
                    "CVEID": cve,
                    "判定": decision,
                    "评分": round(min(score, 1.0), 3),
                    "解释": explanation,
                    "问题": issues,
                })
            if not results:  # 模型未返回结构化, 使用本地降级
                return self._local_fallback(items)
            total = len(results)
            passed = sum(1 for r in results if r["判定"] == "有效")
            avg = round(sum(r["评分"] for r in results)/total, 3) if total else 0.0
            return {"total": total, "passed": passed, "avg_score": avg, "entries": results}
        except Exception:
            return self._local_fallback(items)

__all__ = ["LLMVerifier"]
