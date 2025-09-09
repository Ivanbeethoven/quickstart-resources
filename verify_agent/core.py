from __future__ import annotations

# Reuse original implementation
import json
import os
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

try:
    from openai import OpenAI  # type: ignore
except ImportError:  # pragma: no cover
    OpenAI = None  # type: ignore

@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str
    score: float

@dataclass
class VerificationReport:
    cve: str
    summary: str
    checks: List[CheckResult]
    llm_review: Optional[Dict[str, Any]] = None

    def to_json(self) -> str:
        return json.dumps({
            "cve": self.cve,
            "summary": self.summary,
            "checks": [asdict(c) for c in self.checks],
            "llm_review": self.llm_review
        }, ensure_ascii=False, indent=2)

class StrategyVerifier:
    def __init__(self, enable_llm: bool = True):
        self.enable_llm = enable_llm

    def _check_has_required_artifacts(self, data: Dict[str, Any]) -> CheckResult:
        art = data.get("artifacts", {})
        count = sum(len(v) for v in art.values() if isinstance(v, list))
        passed = count > 0
        return CheckResult("artifacts_presence", passed, f"total items={count}", 0.9 if passed else 0.2)

    def _check_ir_completeness(self, data: Dict[str, Any]) -> CheckResult:
        ir = data.get("defense_ir", {})
        required = ["vuln_type", "attack_path", "mitigation_intent", "policy_targets", "asset_scope"]
        missing = [k for k in required if k not in ir or not ir.get(k)]
        passed = not missing
        return CheckResult("defense_ir_completeness", passed, "missing=" + ",".join(missing) if missing else "ok", 1.0 if passed else 0.3)

    def _check_policy_target_alignment(self, data: Dict[str, Any]) -> CheckResult:
        ir = data.get("defense_ir", {})
        targets: List[str] = ir.get("policy_targets", [])
        art = data.get("artifacts", {})
        mapping = {
            "rbacPatch": len(art.get("patches", [])) > 0,
            "networkPolicy": any(p.get("kind") == "NetworkPolicy" for p in art.get("patches", [])),
            "podPatch": any(p.get("kind") == "Deployment" for p in art.get("patches", [])),
            "falco": len(art.get("falco_rules", [])) > 0,
        }
        missing = [t for t in targets if not mapping.get(t)]
        passed = not missing
        return CheckResult("target_alignment", passed, "missing=" + ",".join(missing) if missing else "ok", 0.85 if passed else 0.4)

    def _llm_review(self, strategy_json: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.enable_llm:
            return None
        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key or OpenAI is None:
            return None
        client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com/v1")
        prompt = (
            "你是资深容器与Kubernetes防护专家。请审阅下面的策略 JSON 并给出: "
            "1) 主要优点, 2) 主要缺陷/缺失点, 3) 额外的临时缓解建议(<=3条). 直接输出 JSON: {review:..., suggestions:[...]}.\n" +
            json.dumps(strategy_json, ensure_ascii=False)[:6000]
        )
        try:
            resp = client.chat.completions.create(
                model=os.getenv("DEEPSEEK_MODEL", "deepseek-reasoner"),
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2
            )
            content = resp.choices[0].message.content if resp.choices else ""
            return {"raw": content}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def verify(self, strategy_data: Dict[str, Any]) -> VerificationReport:
        checks = [
            self._check_has_required_artifacts(strategy_data),
            self._check_ir_completeness(strategy_data),
            self._check_policy_target_alignment(strategy_data),
        ]
        llm_review = self._llm_review(strategy_data)
        return VerificationReport(
            cve=strategy_data.get("vuln", {}).get("cve", "UNKNOWN"),
            summary=f"total_checks={len(checks)} passed={sum(1 for c in checks if c.passed)}",
            checks=checks,
            llm_review=llm_review
        )

def run_verification(strategy_file: str, out_file: Optional[str] = None, enable_llm: bool = True) -> str:
    with open(strategy_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    verifier = StrategyVerifier(enable_llm=enable_llm)
    report = verifier.verify(data)
    if not out_file:
        out_file = strategy_file.replace(".strategy.json", ".verify.json")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(report.to_json())
    return out_file
