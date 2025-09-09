"""大模型驱动的漏洞防控策略生成 (LangGraph 版)

说明：
 仅实现 README 中描述的“【大模型驱动的安全策略生成】”这一部分：
	 输入：漏洞描述 JSON + 运行上下文 JSON
	 输出：DefenseIR (推理结果) + 多策略工件（Falco 规则 / RBAC Patch / NetworkPolicy / Pod 安全补丁…）

 不包含：CVE 订阅、分类流水线、发布/回滚、验证执行、指标存储。
 本文件聚焦“LLM → DefenseIR → 策略生成”核心最小链路，其他交付后续独立模块接入。

 低依赖：仅标准库。LLM 调用以接口抽象（可插入真实模型），默认使用基于规则+模板的模拟推理。

 用法：
	python kube4sagent.py generate --vuln-file examples/cve_calico.json --context-file examples/context_calico.json --out artifacts/

 输入示例（vuln-file）：
 {
	 "cve": "CVE-2024-33522",
	 "component": "Calico",
	 "description": "Privilege escalation due to over-privileged ClusterRole granting create/delete verbs.",
	 "severity": "HIGH"
 }

 输入示例（context-file）：
 {
	 "namespace": "kube-system",
	 "service_accounts": ["calico-node"],
	 "roles": {"calico-node": {"rules": [{"resources":["pods"],"verbs":["get","list","watch","create"]}]}},
	 "deployments": {"calico-node": {"spec": {"template": {"spec": {"containers": [{"name":"calico","image":"calico:v1"}]}}}}}
 }

 输出：生成目录下 <CVE>.strategy.json
 {
	 "defense_ir": {...},
	 "artifacts": {"falco_rules": [...], "patches": [...]}
 }

 重构：使用 LangGraph 统一表达多步工作流及按漏洞类型的智能策略目标路由。
 工作流节点：LOAD → CLASSIFY → BUILD_IR → ROUTE → DISPATCH ⇄ (GEN_*) → ASSEMBLE → END
 智能路由：动态决定后续需要的策略生成节点顺序（rbacPatch / networkPolicy / podPatch / falco）。
 中间表示：DefenseIR（提供 JSON Schema，schema_ref=DefenseIR@v1）。
 输出：包含 trace（可解释）、defense_ir（规范化）、artifacts（分策略工件）。
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

# 依赖: langgraph (通过 uv 安装)。若未安装请运行: uv add langgraph
from langgraph.graph import StateGraph, END
try:  # 支持包名
	from verify_agent.core import run_verification  # type: ignore
except ImportError:  # pragma: no cover
	def run_verification(*args, **kwargs):  # type: ignore
		return "__verify_unavailable__"


# ============================= Data Models ============================= #

VULN_TYPES = ["T1","T2","T3","T4","T5","T6","T7"]  # 与 README 分类一致

VULN_KEYWORD_RULES: Dict[str, List[re.Pattern]] = {
	"T1": [re.compile(p, re.I) for p in [r"over-?privilege", r"cluster-admin", r"rbac", r"excessive permissions", r"rolebinding"]],
	"T2": [re.compile(p, re.I) for p in [r"auth(entication|orization) bypass", r"improper auth", r"logic flaw", r"authorization issue", r"bypass"]],
	"T3": [re.compile(p, re.I) for p in [r"remote code execution", r"rce", r"code injection", r"command injection", r"arbitrary command"]],
	"T4": [re.compile(p, re.I) for p in [r"secret", r"credential", r"token leak", r"information disclosure", r"leakage"]],
	"T5": [re.compile(p, re.I) for p in [r"path traversal", r"directory traversal", r"file read", r"arbitrary file", r"../"]],
	"T6": [re.compile(p, re.I) for p in [r"network", r"unrestricted access", r"missing auth between services", r"lateral movement"]],
	"T7": [re.compile(p, re.I) for p in [r"privileged", r"capabilities", r"cap_", r"runtime escape", r"container escape"]],
}


@dataclass
class VulnerabilityInput:
	cve: str
	component: str
	description: str
	severity: str = "HIGH"
	metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ContextInput:
	namespace: str
	service_accounts: List[str] = field(default_factory=list)
	roles: Dict[str, Dict[str, Any]] = field(default_factory=dict)
	deployments: Dict[str, Dict[str, Any]] = field(default_factory=dict)
	network_policies: Dict[str, Dict[str, Any]] = field(default_factory=dict)
	raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DefenseIR:
	vuln_type: str
	attack_path: List[str]
	mitigation_intent: List[str]
	policy_targets: List[str]
	asset_scope: Dict[str, Any]
	evidence: List[str]
	confidence: float


# ---------------------- DefenseIR JSON Schema (Formal Spec) ---------------------- #
DEFENSE_IR_SCHEMA: Dict[str, Any] = {
	"$schema": "http://json-schema.org/draft-07/schema#",
	"title": "DefenseIR",
	"type": "object",
	"required": [
		"vuln_type", "attack_path", "mitigation_intent", "policy_targets",
		"asset_scope", "evidence", "confidence"
	],
	"properties": {
		"vuln_type": {"type": "string", "enum": ["T1","T2","T3","T4","T5","T6","T7"]},
		"attack_path": {"type": "array", "items": {"type": "string"}},
		"mitigation_intent": {"type": "array", "items": {"type": "string"}},
		"policy_targets": {"type": "array", "items": {"type": "string"}},
		"asset_scope": {"type": "object"},
		"evidence": {"type": "array", "items": {"type": "string"}},
		"confidence": {"type": "number", "minimum": 0, "maximum": 1}
	},
	"additionalProperties": False
}


@dataclass
class StrategyArtifacts:
	falco_rules: List[str] = field(default_factory=list)
	patches: List[Dict[str, Any]] = field(default_factory=list)
	notes: List[str] = field(default_factory=list)

	def as_dict(self) -> Dict[str, Any]:
		return {"falco_rules": self.falco_rules, "patches": self.patches, "notes": self.notes}


# ============================= Components ============================= #

class InputLoader:
	def load_vuln(self, path: str) -> VulnerabilityInput:
		with open(path, "r", encoding="utf-8") as f:
			d = json.load(f)
		return VulnerabilityInput(
			cve=d["cve"],
			component=d.get("component", "Unknown"),
			description=d.get("description", ""),
			severity=d.get("severity", "HIGH"),
			metadata={k: v for k, v in d.items() if k not in {"cve","component","description","severity"}},
		)

	def load_context(self, path: str) -> ContextInput:
		with open(path, "r", encoding="utf-8") as f:
			d = json.load(f)
		return ContextInput(
			namespace=d.get("namespace", "default"),
			service_accounts=d.get("service_accounts", []),
			roles=d.get("roles", {}),
			deployments=d.get("deployments", {}),
			network_policies=d.get("network_policies", {}),
			raw=d,
		)


class StrategyGenerator:
	"""面向不同策略目标的原子生成器集合。GEN_* 节点调用具体方法。"""

	def gen_rbac_patch(self, vuln: VulnerabilityInput, ctx: ContextInput, ir: DefenseIR) -> StrategyArtifacts:
		art = StrategyArtifacts()
		art.notes.append("rbac-min-verb applied")
		art.patches.extend(self._rbac_min_verb_patch(ctx))
		# 若仍需 Falco kubectl 规则由独立 falco 节点生成
		return art

	def gen_network_policy(self, vuln: VulnerabilityInput, ctx: ContextInput, ir: DefenseIR) -> StrategyArtifacts:
		art = StrategyArtifacts()
		art.notes.append("networkpolicy tight ingress/egress")
		if ir.vuln_type == "T2":
			art.patches.append(self._networkpolicy_tight(ctx.namespace))
		else:  # T6
			art.patches.append(self._networkpolicy_deny_egress(ctx.namespace))
		return art

	def gen_pod_patch(self, vuln: VulnerabilityInput, ctx: ContextInput, ir: DefenseIR) -> StrategyArtifacts:
		art = StrategyArtifacts()
		art.notes.append("pod hardening patches")
		if ir.vuln_type == "T3":
			art.patches.extend(self._deployment_readonly_fs_patch(ctx))
		if ir.vuln_type == "T7":
			art.patches.extend(self._deployment_drop_caps_patch(ctx))
			art.patches.extend(self._deployment_seccomp_patch(ctx))
		return art

	def gen_falco(self, vuln: VulnerabilityInput, ctx: ContextInput, ir: DefenseIR) -> StrategyArtifacts:
		art = StrategyArtifacts()
		sa = ctx.service_accounts[0] if ctx.service_accounts else "default"
		ns = ctx.namespace
		cve = vuln.cve
		if ir.vuln_type == "T1":
			art.falco_rules.append(self._falco_kubectl_restrict_rule(sa, ns, cve))
		if ir.vuln_type == "T2":
			art.falco_rules.append(self._falco_abnormal_verb_rule(cve))
		if ir.vuln_type == "T3":
			art.falco_rules.append(self._falco_shell_spawn_rule(cve))
		if ir.vuln_type == "T4":
			art.falco_rules.append(self._falco_secret_scan_rule(cve))
		if ir.vuln_type == "T5":
			art.falco_rules.append(self._falco_path_traversal_rule(cve))
		# T6 (网络) 暂不生成 Falco
		if ir.vuln_type == "T7":
			# 可选择性添加特权 syscall 监控（占位）
			art.falco_rules.append(
				f"rule: Privilege Syscall Monitor {cve}\ncondition: evt.type in (capset)\noutput: Capability change {cve} user=%user.name\npriority: NOTICE\ntags: [k8s, privilege, {cve}]"
			)
		return art

	# ================= Helper methods migrated from workflow (self-contained) ================= #
	def _rbac_min_verb_patch(self, ctx: ContextInput) -> List[Dict[str, Any]]:
		patches = []
		high_risk = {"create", "update", "delete", "patch", "impersonate", "escalate"}
		for role_name, spec in ctx.roles.items():
			new_rules = []
			changed = False
			for rule in spec.get("rules", []):
				verbs = rule.get("verbs", [])
				filtered = [v for v in verbs if v not in high_risk]
				if len(filtered) != len(verbs):
					changed = True
				new_rules.append({**rule, "verbs": filtered})
			if changed:
				patches.append({
					"kind": "ClusterRole",
					"name": role_name,
					"patch": {"rules": new_rules},
					"note": "removed high-risk verbs"
				})
		return patches

	def _networkpolicy_tight(self, namespace: str) -> Dict[str, Any]:
		return {
			"kind": "NetworkPolicy",
			"name": "restrict-ingress-temp",
			"namespace": namespace,
			"spec": {
				"podSelector": {},
				"policyTypes": ["Ingress"],
				"ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}}}]}],
			},
			"note": "Tight ingress during mitigation window"
		}

	def _networkpolicy_deny_egress(self, namespace: str) -> Dict[str, Any]:
		return {
			"kind": "NetworkPolicy",
			"name": "deny-egress-temp",
			"namespace": namespace,
			"spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": []},
			"note": "deny all egress temporary"
		}

	def _deployment_readonly_fs_patch(self, ctx: ContextInput) -> List[Dict[str, Any]]:
		patches = []
		for name, dep in ctx.deployments.items():
			containers = dep.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
			need_patch = any(not (c.get("securityContext", {}).get("readOnlyRootFilesystem")) for c in containers)
			if need_patch:
				patches.append({
					"kind": "Deployment",
					"name": name,
					"patch": {"spec": {"template": {"spec": {"containers": [{"name": c.get("name"), "securityContext": {"readOnlyRootFilesystem": True}} for c in containers]}}}},
					"note": "enforce readOnlyRootFilesystem"
				})
		return patches

	def _deployment_drop_caps_patch(self, ctx: ContextInput) -> List[Dict[str, Any]]:
		patches = []
		for name, dep in ctx.deployments.items():
			containers = dep.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
			need_patch = False
			new_containers = []
			for c in containers:
				sec = c.get("securityContext", {})
				caps = sec.get("capabilities", {}).get("add", [])
				risky = [cap for cap in caps if cap.upper() in ("SYS_ADMIN", "NET_RAW")]
				if risky:
					need_patch = True
					safe_add = [cap for cap in caps if cap not in risky]
					new_sec = {**sec, "capabilities": {"add": safe_add, "drop": list(set(risky + ["ALL"]))}}
					new_containers.append({"name": c.get("name"), "securityContext": new_sec})
				else:
					new_containers.append({"name": c.get("name"), "securityContext": sec})
			if need_patch:
				patches.append({
					"kind": "Deployment",
					"name": name,
					"patch": {"spec": {"template": {"spec": {"containers": new_containers}}}},
					"note": "drop risky capabilities"
				})
		return patches

	def _deployment_seccomp_patch(self, ctx: ContextInput) -> List[Dict[str, Any]]:
		patches = []
		for name, dep in ctx.deployments.items():
			pod_spec = dep.get("spec", {}).get("template", {}).get("spec", {})
			if not pod_spec.get("securityContext", {}).get("seccompProfile"):
				patches.append({
					"kind": "Deployment",
					"name": name,
					"patch": {"spec": {"template": {"spec": {"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}}}}}},
					"note": "enforce seccomp RuntimeDefault"
				})
		return patches

	def _falco_kubectl_restrict_rule(self, sa: str, ns: str, cve: str) -> str:
		return (f"rule: Detect Suspicious Kubectl Exec via {sa}\n"
				f"condition: proc.name = kubectl and ka.user.name = {sa} and k8s.ns.name = {ns} and not ka.resource.verb in (get, list, watch)\n"
				f"output: PE Attempt {cve}: {sa} uses kubectl verb=%ka.resource.verb ns={ns}\n"
				f"priority: WARNING\n"
				f"tags: [k8s, privilege_escalation, {cve}]")

	def _falco_abnormal_verb_rule(self, cve: str) -> str:
		return (f"rule: K8s Abnormal Verb Pattern {cve}\n"
				f"condition: ka.resource.verb in (create,delete,patch,update) and not k8s.audited.verb_exists\n"
				f"output: Abnormal verb sequence {cve} user=%ka.user.name verb=%ka.resource.verb\n"
				f"priority: NOTICE\n"
				f"tags: [k8s, logic_flaw, {cve}]")

	def _falco_shell_spawn_rule(self, cve: str) -> str:
		return (f"rule: Suspicious Shell Spawn {cve}\n"
				f"condition: proc.name in (bash,sh) and container and not proc.pname in (entrypoint)\n"
				f"output: RCE suspect shell {cve} parent=%proc.pname cmd=%proc.cmdline\n"
				f"priority: WARNING\n"
				f"tags: [k8s, rce, {cve}]")

	def _falco_secret_scan_rule(self, cve: str) -> str:
		return (f"rule: Secret Access Burst {cve}\n"
				f"condition: ka.resource = secrets and evt.count > 5\n"
				f"output: Possible secret enumeration {cve} user=%ka.user.name count=%evt.count\n"
				f"priority: NOTICE\n"
				f"tags: [k8s, secret, {cve}]")

	def _falco_path_traversal_rule(self, cve: str) -> str:
		return (f"rule: Path Traversal Attempt {cve}\n"
				f"condition: evt.type in (open,openat) and fd.name contains ../ and not proc.name in (trusted)\n"
				f"output: Potential path traversal {cve} file=%fd.name proc=%proc.name\n"
				f"priority: WARNING\n"
				f"tags: [k8s, path_traversal, {cve}]")


# ---------------------- Strategy Router (智能路由) ---------------------- #

class StrategyRouter:
	def __init__(self):
		self.base_routes: Dict[str, List[str]] = {
			"T1": ["rbacPatch", "falco"],
			"T2": ["networkPolicy", "falco"],
			"T3": ["falco", "podPatch"],
			"T4": ["rbacPatch", "falco"],
			"T5": ["falco"],
			"T6": ["networkPolicy"],
			"T7": ["podPatch"],
		}

	def route(self, ir: DefenseIR) -> Dict[str, Any]:
		targets = self.base_routes.get(ir.vuln_type, ["rbacPatch"])
		return {"targets": targets, "remaining": list(targets), "explain": f"Route {ir.vuln_type} -> {','.join(targets)}"}


# ---------------------- Workflow Engine ---------------------- #

@dataclass
class WorkflowStepResult:
	name: str
	status: str  # success|skip|fail
	detail: str
	data: Dict[str, Any] = field(default_factory=dict)


class StrategyWorkflow:
	"""LangGraph 工作流封装。"""

	def __init__(self, loader: InputLoader, llm: 'LLMBackend', router: StrategyRouter, generator: StrategyGenerator):
		self.loader = loader
		self.llm = llm
		self.router = router
		self.generator = generator
		self.graph = self._build_graph()

	# ---- Graph Node Implementations ---- #
	def _n_load(self, state: Dict[str, Any]) -> Dict[str, Any]:
		vuln = self.loader.load_vuln(state['config']['vuln_file'])
		ctx = self.loader.load_context(state['config']['context_file'])
		trace = state['trace'] + [self._trace('LOAD', 'Loaded inputs', {'cve': vuln.cve, 'namespace': ctx.namespace})]
		return {**state, 'vuln': vuln, 'context': ctx, 'trace': trace}

	def _n_classify(self, state: Dict[str, Any]) -> Dict[str, Any]:
		vuln: VulnerabilityInput = state['vuln']
		result = self.llm.classify(vuln)
		trace = state['trace'] + [self._trace('CLASSIFY', f"Classified {result['vuln_type']}", result)]
		return {**state, 'classification': result, 'trace': trace}

	def _n_build_ir(self, state: Dict[str, Any]) -> Dict[str, Any]:
		vuln: VulnerabilityInput = state['vuln']
		ctx: ContextInput = state['context']
		ir = self.llm.generate_dir(vuln, ctx)
		trace = state['trace'] + [self._trace('BUILD_IR', 'DefenseIR built', {'vuln_type': ir.vuln_type, 'confidence': ir.confidence})]
		return {**state, 'defense_ir': ir, 'trace': trace}

	def _n_route(self, state: Dict[str, Any]) -> Dict[str, Any]:
		ir: DefenseIR = state['defense_ir']
		routing = self.router.route(ir)
		trace = state['trace'] + [self._trace('ROUTE', routing['explain'], routing)]
		return {**state, 'routing': routing, 'trace': trace}

	def _n_dispatch(self, state: Dict[str, Any]) -> Dict[str, Any]:
		return state

	def _n_gen_rbac(self, state: Dict[str, Any]) -> Dict[str, Any]:
		art = self.generator.gen_rbac_patch(state['vuln'], state['context'], state['defense_ir'])
		self._pop_target(state, 'rbacPatch')
		return self._merge_artifacts(state, art, 'GEN_RBAC')

	def _n_gen_network(self, state: Dict[str, Any]) -> Dict[str, Any]:
		art = self.generator.gen_network_policy(state['vuln'], state['context'], state['defense_ir'])
		self._pop_target(state, 'networkPolicy')
		return self._merge_artifacts(state, art, 'GEN_NETPOL')

	def _n_gen_pod(self, state: Dict[str, Any]) -> Dict[str, Any]:
		art = self.generator.gen_pod_patch(state['vuln'], state['context'], state['defense_ir'])
		self._pop_target(state, 'podPatch')
		return self._merge_artifacts(state, art, 'GEN_PODPATCH')

	def _n_gen_falco(self, state: Dict[str, Any]) -> Dict[str, Any]:
		art = self.generator.gen_falco(state['vuln'], state['context'], state['defense_ir'])
		self._pop_target(state, 'falco')
		return self._merge_artifacts(state, art, 'GEN_FALCO')

	def _n_assemble(self, state: Dict[str, Any]) -> Dict[str, Any]:
		ir: DefenseIR = state['defense_ir']
		vuln: VulnerabilityInput = state['vuln']
		artifacts: StrategyArtifacts = state['artifacts']
		trace = state['trace'] + [self._trace('ASSEMBLE', 'Assembled output', {})]
		output = {
			'vuln': {'cve': vuln.cve, 'component': vuln.component, 'severity': vuln.severity},
			'defense_ir': {
				'vuln_type': ir.vuln_type,
				'attack_path': ir.attack_path,
				'mitigation_intent': ir.mitigation_intent,
				'policy_targets': ir.policy_targets,
				'asset_scope': ir.asset_scope,
				'evidence': ir.evidence,
				'confidence': ir.confidence,
				'schema_ref': 'DefenseIR@v1'
			},
			'artifacts': artifacts.as_dict(),
			'workflow_trace': trace,
			'schemas': {'DefenseIR': DEFENSE_IR_SCHEMA},
		}
		temp_dir = state['config'].get('work_dir', 'artifacts')
		os.makedirs(temp_dir, exist_ok=True)
		strategy_tmp_path = os.path.join(temp_dir, f"{vuln.cve}.strategy.json")
		with open(strategy_tmp_path, 'w', encoding='utf-8') as f:
			json.dump(output, f, indent=2, ensure_ascii=False)
		trace.append(self._trace('ASSEMBLE_IO', 'Strategy written', {'path': strategy_tmp_path}))
		return {**state, 'output': output, '_strategy_path': strategy_tmp_path, 'trace': trace}

	def _n_verify(self, state: Dict[str, Any]) -> Dict[str, Any]:
		path = state.get('_strategy_path')
		verify_path = None
		if path and os.path.exists(path):
			try:
				verify_path = run_verification(path, enable_llm=False)
			except Exception as e:  # noqa: BLE001
				verify_path = f"__ERROR__:{e}"
		trace = state['trace'] + [self._trace('VERIFY', 'Verification executed', {'report': verify_path})]
		return {**state, 'verification_report': verify_path, 'trace': trace}

	# ---- Helpers ---- #
	def _trace(self, step: str, detail: str, data: Dict[str, Any]) -> Dict[str, Any]:
		return {"step": step, "detail": detail, "data": data}

	def _pop_target(self, state: Dict[str, Any], target: str):
		rem: List[str] = state['routing']['remaining']
		if rem and rem[0] == target:
			rem.pop(0)

	def _merge_artifacts(self, state: Dict[str, Any], new_art: StrategyArtifacts, step_name: str) -> Dict[str, Any]:
		existing: StrategyArtifacts = state.get('artifacts') or StrategyArtifacts()
		existing.falco_rules.extend(new_art.falco_rules)
		existing.patches.extend(new_art.patches)
		existing.notes.extend(new_art.notes)
		trace = state['trace'] + [self._trace(step_name, 'Generated artifacts fragment', {'falco_rules': len(new_art.falco_rules), 'patches': len(new_art.patches)})]
		return {**state, 'artifacts': existing, 'trace': trace}

	# ---- Conditional Routing ---- #
	def _dispatch_next(self, state: Dict[str, Any]) -> str:
		rem: List[str] = state['routing']['remaining']
		if not rem:
			return 'ASSEMBLE'
		mapping = {
			'rbacPatch': 'GEN_RBAC',
			'networkPolicy': 'GEN_NETPOL',
			'podPatch': 'GEN_POD',
			'falco': 'GEN_FALCO'
		}
		return mapping.get(rem[0], 'ASSEMBLE')

	def _build_graph(self):
		g = StateGraph(dict)
		g.add_node('LOAD', self._n_load)
		g.add_node('CLASSIFY', self._n_classify)
		g.add_node('BUILD_IR', self._n_build_ir)
		g.add_node('ROUTE', self._n_route)
		g.add_node('DISPATCH', self._n_dispatch)
		g.add_node('GEN_RBAC', self._n_gen_rbac)
		g.add_node('GEN_NETPOL', self._n_gen_network)
		g.add_node('GEN_POD', self._n_gen_pod)
		g.add_node('GEN_FALCO', self._n_gen_falco)
		g.add_node('ASSEMBLE', self._n_assemble)
		g.add_node('VERIFY', self._n_verify)

		g.set_entry_point('LOAD')
		g.add_edge('LOAD', 'CLASSIFY')
		g.add_edge('CLASSIFY', 'BUILD_IR')
		g.add_edge('BUILD_IR', 'ROUTE')
		g.add_edge('ROUTE', 'DISPATCH')

	# Conditional edges from DISPATCH / GEN_* back to DISPATCH or ASSEMBLE
		g.add_conditional_edges('DISPATCH', self._dispatch_next, {
			'GEN_RBAC': 'GEN_RBAC',
			'GEN_NETPOL': 'GEN_NETPOL',
			'GEN_POD': 'GEN_POD',
			'GEN_FALCO': 'GEN_FALCO',
			'ASSEMBLE': 'ASSEMBLE'
		})
		for gn in ['GEN_RBAC','GEN_NETPOL','GEN_POD','GEN_FALCO']:
			g.add_conditional_edges(gn, self._dispatch_next, {
				'GEN_RBAC': 'GEN_RBAC',
				'GEN_NETPOL': 'GEN_NETPOL',
				'GEN_POD': 'GEN_POD',
				'GEN_FALCO': 'GEN_FALCO',
				'ASSEMBLE': 'ASSEMBLE'
			})
		g.add_edge('ASSEMBLE', 'VERIFY')
		g.add_edge('VERIFY', END)
		return g.compile()

	def run(self, vuln_file: str, context_file: str) -> Dict[str, Any]:
		initial_state = {"config": {"vuln_file": vuln_file, "context_file": context_file}, "trace": []}
		final_state = self.graph.invoke(initial_state)
		return final_state['output']

	# ---- Template Helpers ---- #
	def _rbac_min_verb_patch(self, ctx: ContextInput) -> List[Dict[str, Any]]:
		patches = []
		high_risk = {"create", "update", "delete", "patch", "impersonate", "escalate"}
		for role_name, spec in ctx.roles.items():
			new_rules = []
			changed = False
			for rule in spec.get("rules", []):
				verbs = rule.get("verbs", [])
				filtered = [v for v in verbs if v not in high_risk]
				if len(filtered) != len(verbs):
					changed = True
				new_rules.append({**rule, "verbs": filtered})
			if changed:
				patches.append({
					"kind": "ClusterRole",  # 简化处理
					"name": role_name,
					"patch": {"rules": new_rules},
					"note": "removed high-risk verbs"
				})
		return patches

	def _falco_kubectl_restrict_rule(self, sa: str, ns: str, cve: str) -> str:
		return (
			f"rule: Detect Suspicious Kubectl Exec via {sa}\n"
			f"condition: proc.name = kubectl and ka.user.name = {sa} and k8s.ns.name = {ns} and not ka.resource.verb in (get, list, watch)\n"
			f"output: PE Attempt {cve}: {sa} uses kubectl verb=%ka.resource.verb ns={ns}\n"
			f"priority: WARNING\n"
			f"tags: [k8s, privilege_escalation, {cve}]"
		)

	def _networkpolicy_tight(self, namespace: str) -> Dict[str, Any]:
		return {
			"kind": "NetworkPolicy",
			"name": "restrict-ingress-temp",
			"namespace": namespace,
			"spec": {
				"podSelector": {},
				"policyTypes": ["Ingress"],
				"ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}}}]}],
			},
			"note": "Tight ingress during mitigation window"
		}

	def _falco_abnormal_verb_rule(self, cve: str) -> str:
		return (
			f"rule: K8s Abnormal Verb Pattern {cve}\n"
			f"condition: ka.resource.verb in (create,delete,patch,update) and not k8s.audited.verb_exists\n"
			f"output: Abnormal verb sequence {cve} user=%ka.user.name verb=%ka.resource.verb\n"
			f"priority: NOTICE\n"
			f"tags: [k8s, logic_flaw, {cve}]"
		)

	def _falco_shell_spawn_rule(self, cve: str) -> str:
		return (
			f"rule: Suspicious Shell Spawn {cve}\n"
			f"condition: proc.name in (bash,sh) and container and not proc.pname in (entrypoint)\n"
			f"output: RCE suspect shell {cve} parent=%proc.pname cmd=%proc.cmdline\n"
			f"priority: WARNING\n"
			f"tags: [k8s, rce, {cve}]"
		)

	def _deployment_readonly_fs_patch(self, ctx: ContextInput) -> List[Dict[str, Any]]:
		patches = []
		for name, dep in ctx.deployments.items():
			containers = dep.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
			need_patch = False
			for c in containers:
				security = c.get("securityContext", {})
				if not security.get("readOnlyRootFilesystem"):
					need_patch = True
			if need_patch:
				patches.append({
					"kind": "Deployment",
					"name": name,
					"patch": {"spec": {"template": {"spec": {"containers": [{"name": c.get("name"), "securityContext": {"readOnlyRootFilesystem": True}} for c in containers]}}}},
					"note": "enforce readOnlyRootFilesystem"
				})
		return patches

	def _rbac_secret_restrict_patch(self, ctx: ContextInput) -> List[Dict[str, Any]]:
		patches = []
		for role_name, spec in ctx.roles.items():
			new_rules = []
			changed = False
			for rule in spec.get("rules", []):
				resources = rule.get("resources", [])
				verbs = rule.get("verbs", [])
				if any(r in ("secrets",) for r in resources):
					filtered = [v for v in verbs if v in ("get",)]  # 强制仅保留 get（或再评估）
					if len(filtered) != len(verbs):
						changed = True
					new_rules.append({**rule, "verbs": filtered})
				else:
					new_rules.append(rule)
			if changed:
				patches.append({
					"kind": "ClusterRole",
					"name": role_name,
					"patch": {"rules": new_rules},
					"note": "restrict secret verbs"
				})
		return patches

	def _falco_secret_scan_rule(self, cve: str) -> str:
		return (
			f"rule: Secret Access Burst {cve}\n"
			f"condition: ka.resource = secrets and evt.count > 5\n"
			f"output: Possible secret enumeration {cve} user=%ka.user.name count=%evt.count\n"
			f"priority: NOTICE\n"
			f"tags: [k8s, secret, {cve}]"
		)

	def _falco_path_traversal_rule(self, cve: str) -> str:
		return (
			f"rule: Path Traversal Attempt {cve}\n"
			f"condition: evt.type in (open,openat) and fd.name contains ../ and not proc.name in (trusted)\n"
			f"output: Potential path traversal {cve} file=%fd.name proc=%proc.name\n"
			f"priority: WARNING\n"
			f"tags: [k8s, path_traversal, {cve}]"
		)

	def _networkpolicy_deny_egress(self, namespace: str) -> Dict[str, Any]:
		return {
			"kind": "NetworkPolicy",
			"name": "deny-egress-temp",
			"namespace": namespace,
			"spec": {
				"podSelector": {},
				"policyTypes": ["Egress"],
				"egress": [],  # 全拒绝，后续可白名单
			},
			"note": "deny all egress temporary"
		}

	def _deployment_drop_caps_patch(self, ctx: ContextInput) -> List[Dict[str, Any]]:
		patches = []
		for name, dep in ctx.deployments.items():
			containers = dep.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
			need_patch = False
			new_containers = []
			for c in containers:
				sec = c.get("securityContext", {})
				caps = sec.get("capabilities", {}).get("add", [])
				risky = [cap for cap in caps if cap.upper() in ("SYS_ADMIN", "NET_RAW")]
				if risky:
					need_patch = True
					# Remove risky adds (drop via allow-list approach)
					safe_add = [cap for cap in caps if cap not in risky]
					new_sec = {**sec, "capabilities": {"add": safe_add, "drop": list(set(risky + ["ALL"]))}}
					new_containers.append({"name": c.get("name"), "securityContext": new_sec})
				else:
					new_containers.append({"name": c.get("name"), "securityContext": sec})
			if need_patch:
				patches.append({
					"kind": "Deployment",
					"name": name,
					"patch": {"spec": {"template": {"spec": {"containers": new_containers}}}},
					"note": "drop risky capabilities"
				})
		return patches

	def _deployment_seccomp_patch(self, ctx: ContextInput) -> List[Dict[str, Any]]:
		patches = []
		for name, dep in ctx.deployments.items():
			pod_spec = dep.get("spec", {}).get("template", {}).get("spec", {})
			if not pod_spec.get("securityContext", {}).get("seccompProfile"):
				patches.append({
					"kind": "Deployment",
					"name": name,
					"patch": {"spec": {"template": {"spec": {"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}}}}}},
					"note": "enforce seccomp RuntimeDefault"
				})
		return patches


class LLMBackend:
	"""LLM 抽象接口 (此处用规则模拟)。"""

	def generate_dir(self, vuln: VulnerabilityInput, ctx: ContextInput) -> DefenseIR:
		text = vuln.description + " " + json.dumps(vuln.metadata, ensure_ascii=False)
		scores: Dict[str, int] = {}
		evidence_map: Dict[str, List[str]] = {k: [] for k in VULN_TYPES}
		for t, patterns in VULN_KEYWORD_RULES.items():
			for p in patterns:
				if p.search(text):
					scores[t] = scores.get(t, 0) + 1
					evidence_map[t].append(p.pattern)
		vuln_type = max(scores.items(), key=lambda x: x[1])[0] if scores else "T1"
		mitigation_map = {
			"T1": ["restrict rbac", "monitor kubectl exec"],
			"T2": ["tight ingress", "monitor abnormal verbs"],
			"T3": ["enforce readonly fs", "detect shell spawn"],
			"T4": ["minimize secret verbs", "detect secret burst"],
			"T5": ["detect path traversal"],
			"T6": ["deny egress temp"],
			"T7": ["drop capabilities", "enforce seccomp"],
		}
		policy_targets_map = {
			"T1": ["rbacPatch", "falco"],
			"T2": ["networkPolicy", "falco"],
			"T3": ["falco", "podPatch"],
			"T4": ["rbacPatch", "falco"],
			"T5": ["falco"],
			"T6": ["networkPolicy"],
			"T7": ["podPatch"],
		}
		return DefenseIR(
			vuln_type=vuln_type,
			attack_path=[f"SA:{ctx.service_accounts[0] if ctx.service_accounts else 'default'}"],
			mitigation_intent=mitigation_map.get(vuln_type, []),
			policy_targets=policy_targets_map.get(vuln_type, []),
			asset_scope={"namespace": ctx.namespace},
			evidence=evidence_map.get(vuln_type, []),
			confidence=0.75 if scores else 0.5,
		)

	# 单独暴露分类（工作流 CLASSIFY 步骤使用）
	def classify(self, vuln: VulnerabilityInput) -> Dict[str, Any]:
		text = vuln.description + " " + json.dumps(vuln.metadata, ensure_ascii=False)
		scores: Dict[str, int] = {}
		for t, patterns in VULN_KEYWORD_RULES.items():
			for p in patterns:
				if p.search(text):
					scores[t] = scores.get(t, 0) + 1
		vuln_type = max(scores.items(), key=lambda x: x[1])[0] if scores else "T1"
		return {"vuln_type": vuln_type, "score_raw": scores}


# ============================= Orchestrator / CLI ============================= #

class StrategyLLMAgent:
	def __init__(self, llm: Optional[LLMBackend] = None):
		self.loader = InputLoader()
		self.llm = llm or LLMBackend()
		self.router = StrategyRouter()
		self.generator = StrategyGenerator()
		self.workflow = StrategyWorkflow(self.loader, self.llm, self.router, self.generator)

	def generate(self, vuln_file: str, context_file: str) -> Dict[str, Any]:
		return self.workflow.run(vuln_file, context_file)


# ============================= File IO Helpers ============================= #

def _ensure_dir(path: str):
	os.makedirs(path, exist_ok=True)


# ============================= CLI ============================= #

def build_arg_parser() -> argparse.ArgumentParser:
	p = argparse.ArgumentParser(description="大模型驱动漏洞防控策略生成 (含工作流/路由)")
	p.add_argument("--vuln-file", required=True)
	p.add_argument("--context-file", required=True)
	p.add_argument("--out", default="artifacts")
	p.add_argument("--print-schema", action="store_true", help="仅输出 DefenseIR Schema")
	return p


def main(argv: Optional[List[str]] = None):
	args = build_arg_parser().parse_args(argv)
	if args.print_schema:
		print(json.dumps(DEFENSE_IR_SCHEMA, indent=2, ensure_ascii=False))
		return 0
	agent = StrategyLLMAgent()
	result = agent.generate(args.vuln_file, args.context_file)
	_ensure_dir(args.out)
	cve = result["vuln"]["cve"]
	out_path = os.path.join(args.out, f"{cve}.strategy.json")
	with open(out_path, "w", encoding="utf-8") as f:
		json.dump(result, f, indent=2, ensure_ascii=False)
	print(f"GENERATED_STRATEGY -> {out_path}")
	# 可选打印路由摘要
	route_step = next((s for s in result["workflow_trace"] if s["step"] == "ROUTE"), None)
	if route_step:
		print(f"ROUTE: {route_step['detail']}")
	return 0


if __name__ == "__main__":  # pragma: no cover
	raise SystemExit(main())

