#!/usr/bin/env python3
from __future__ import annotations

"""基于 LangGraph 的简易漏洞临时缓解策略生成 + 静态验证工作流

流程 (StateGraph):
	LOAD_CSV -> GENERATE(LLM) -> VERIFY -> OUTPUT

说明:
	- 读取根目录 raw_results.csv (列: CVEID, Summary, CVSS v3.x Score, Third-party Applications)
	- 仅支持 LLM 生成（需要 openai.key 或环境变量 OPENAI_API_KEY/DEEPSEEK_API_KEY）
  - 验证阶段调用 verify_agent 进行静态质量评估
  - 输出 JSON 文件: plain_output/mitigations.json & verification.json

运行:
	python plain/main.py --top 5
"""

import argparse
import csv
import json
import os
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Any

from langgraph.graph import StateGraph, END


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
	sys.path.insert(0, str(ROOT))
LLM_DIR = ROOT / 'llm'
if str(LLM_DIR) not in sys.path:
	sys.path.insert(0, str(LLM_DIR))
try:
	from llm.base import create_llm_client, ChatClient  # type: ignore
except Exception:  # pragma: no cover
	create_llm_client = None  # type: ignore
	ChatClient = object  # type: ignore
from verify_agent.llm_verify import LLMVerifier  # type: ignore


# ---------------- Data Models ---------------- #

@dataclass
class VulnRow:
	cve: str
	summary: str
	cvss: str
	app: str

	def as_prompt(self) -> str:
		return f"CVE: {self.cve}\nCVSS: {self.cvss}\nAPP: {self.app}\nSummary: {self.summary}"


# ---------------- LLM Wrapper ---------------- #


class SimpleLLM:
	"""基于通用 llm.base 客户端的策略生成封装."""

	def __init__(self):
		try:
			self.client: 'ChatClient' = create_llm_client()  # type: ignore
		except Exception:
			self.client = None  # type: ignore
		self.model = os.getenv("OPENAI_MODEL") or os.getenv("DEEPSEEK_MODEL") or "deepseek-reasoner"
		self.enabled = self.client is not None
		self.last_raw: str | None = None

	@staticmethod
	def _extract_json_array(text: str) -> List[Dict[str, Any]] | None:
		"""尝试从包含解释/思考的文本中抽取首个 JSON 数组.

		使用手动括号计数而非单纯正则, 减少嵌套干扰.
		"""
		start = text.find('[')
		if start == -1:
			return None
		depth = 0
		for idx in range(start, len(text)):
			ch = text[idx]
			if ch == '[':
				depth += 1
			elif ch == ']':
				depth -= 1
				if depth == 0:
					snippet = text[start:idx + 1]
					try:
						parsed = json.loads(snippet)
						if isinstance(parsed, list):
							# 仅接受元素为对象的列表
							return [p for p in parsed if isinstance(p, dict)]
					except Exception:  # noqa: BLE001
						return None
		return None

	@staticmethod
	def _extract_single_object(text: str) -> Dict[str, Any] | None:
		"""提取首个形似 JSON 对象的片段."""
		start = text.find('{')
		if start == -1:
			return None
		depth = 0
		for idx in range(start, len(text)):
			ch = text[idx]
			if ch == '{':
				depth += 1
			elif ch == '}':
				depth -= 1
				if depth == 0:
					snippet = text[start:idx + 1]
					try:
						obj = json.loads(snippet)
						if isinstance(obj, dict):
							return obj
					except Exception:  # noqa: BLE001
						return None
		return None

	def _chat(self, prompt: str, temperature: float = 0.25) -> str:
		if not self.enabled:
			raise RuntimeError("LLM disabled")
		return self.client.chat([
			{"role": "user", "content": prompt}
		], model=self.model, temperature=temperature)

	def _single_prompt(self, vuln: VulnRow) -> str:
		return (
			"你是资深应急响应工程师。针对以下单个漏洞生成一个 JSON 对象，字段: "
			"{CVEID, 临时检测策略, 临时防护/缓解策略, 优先级(高/中/低), 风险点简述}。策略需在5分钟内可实施 (命令/配置/规则 要点)，"
			"禁止出现任何 版本升级/打补丁/更新版本/等待修复/patch/update/hotfix 作为主要缓解；必须提供运行时或配置层面的临时防护(如: NetworkPolicy, RBAC, 只读根文件系统, seccomp, 限制权限, 审计/检测规则)。"
			"仅输出 JSON 对象，不要多余文本。输入:\n" + vuln.as_prompt()
		)

	def gen(self, batch: List[VulnRow]) -> List[Dict[str, Any]]:
		"""批量生成: 先尝试整体 JSON 数组, 失败则逐条回退生成.

		返回的每个元素保证包含至少 CVEID 字段.
		"""
		if not self.enabled:
			raise RuntimeError("LLM disabled")
		prompt_parts = [v.as_prompt() for v in batch]
		batch_prompt = (
			"你是资深应急响应与云原生安全专家。根据以下多个漏洞，生成 JSON 数组，每个元素: "
			"{CVEID, 临时检测策略, 临时防护/缓解策略, 优先级(高/中/低), 风险点简述}.\n"
			"严格禁止: 直接给出 '升级版本'、'打补丁'、'更新到X.Y.Z'、'等待官方修复'、patch/update/hotfix 等作为缓解核心。\n"
			"要求: \n"
			"1) 仅输出 JSON 数组; 2) 临时防护需聚焦运行时/访问/隔离/权限/监控控制(如 NetworkPolicy, RBAC, seccomp, capabilities 最小化, 只读根, eBPF/Falco 检测); 3) 每条含至少一个可执行指令或配置片段要点; 4) 不要附加解释; 5) 优先级=依据利用难度与影响。\n"
			"输入如下: \n" + "\n---\n".join(prompt_parts)
		)
		raw = self._chat(batch_prompt, temperature=0.25)
		self.last_raw = raw
		items = self._extract_json_array(raw)
		if items:
			# 规范化
			for it in items:
				if 'CVEID' not in it:
					it['CVEID'] = it.get('cve') or it.get('id') or ''
			return items
		# 尝试单对象 -> 视为单元素数组
		single = self._extract_single_object(raw)
		if single:
			single.setdefault('CVEID', single.get('cve') or '')
			return [single]
		# 回退: 逐漏洞单独生成
		fallback: List[Dict[str, Any]] = []
		for vuln in batch:
			try:
				resp = self._chat(self._single_prompt(vuln), temperature=0.1)
				obj = self._extract_single_object(resp) or {}
				if obj:
					obj.setdefault('CVEID', vuln.cve)
					fallback.append(obj)
				else:
					fallback.append({'CVEID': vuln.cve, '临时防护/缓解策略': '需人工补充', '临时检测策略': '', '优先级': '中', '风险点简述': vuln.summary[:120]})
			except Exception as e:  # noqa: BLE001
				fallback.append({'CVEID': vuln.cve, '临时防护/缓解策略': f'生成失败: {e}', '临时检测策略': '', '优先级': '中', '风险点简述': vuln.summary[:120]})
		return fallback

# ---------------- Graph Nodes ---------------- #

def n_load(state: Dict[str, Any]) -> Dict[str, Any]:
	csv_path: Path = state['config']['csv']
	top: int = state['config']['top']
	vulns: List[VulnRow] = []
	with csv_path.open(encoding='utf-8') as f:
		reader = csv.DictReader(f)
		headers = reader.fieldnames
		for row in reader:
			cve = (row.get('CVEID') or '').strip()
			if not cve:
				# 回退: 在所有字段中尝试匹配 CVE 号
				import re
				joined = ' '.join([str(v) for v in row.values()])
				m = re.search(r'CVE-\d{4}-\d{4,7}', joined)
				if not m:
					continue
				cve = m.group(0)
			summary_val = (row.get('Summary') or '').strip()
			if not summary_val:
				# 选取最长字段作为 summary 近似
				candidates = [str(v).strip() for v in row.values() if isinstance(v, str)]
				candidates = [c for c in candidates if len(c) > 10]
				if candidates:
					summary_val = max(candidates, key=len)[:1000]
			vulns.append(VulnRow(
				cve=cve,
				summary=summary_val,
				cvss=(row.get('CVSS v3.x Score') or '').strip(),
				app=(row.get('Third-party Applications') or '').strip()
			))

	return {**state, 'vulns': vulns, 'trace': state['trace'] + [{'step': 'LOAD_CSV', 'count': len(vulns), 'headers': headers}]}


def n_generate(state: Dict[str, Any]) -> Dict[str, Any]:
	vulns: List[VulnRow] = state['vulns']
	llm: SimpleLLM = state['llm']
	if not llm.enabled:
		raise RuntimeError('LLM 未启用: 请提供 openai.key 或设置 OPENAI_API_KEY/DEEPSEEK_API_KEY')
	mitigations = llm.gen(vulns)
	# debug: 写入原始响应
	if state['config'].get('debug') and llm.last_raw is not None:
		out_dir = Path(state['config']['out_dir'])
		out_dir.mkdir(parents=True, exist_ok=True)
		(out_dir / 'llm_raw.txt').write_text(llm.last_raw, encoding='utf-8')
	return {**state, 'mitigations': mitigations, 'trace': state['trace'] + [{'step': 'GENERATE', 'mode': 'llm', 'count': len(mitigations), 'fallback_used': llm.last_raw is not None and len(mitigations) == len(vulns)}]}


def n_verify(state: Dict[str, Any]) -> Dict[str, Any]:
	verifier: LLMVerifier = state['verifier']
	report = verifier.verify(state['mitigations'])
	return {**state, 'verification': report, 'trace': state['trace'] + [{'step': 'VERIFY', 'mode': 'llm', 'passed': report['passed'], 'avg': report['avg_score']}]}


def n_output(state: Dict[str, Any]) -> Dict[str, Any]:
	out_dir = Path(state['config']['out_dir'])
	out_dir.mkdir(parents=True, exist_ok=True)
	mit_path = out_dir / 'mitigations.json'
	ver_path = out_dir / 'verification.json'
	with mit_path.open('w', encoding='utf-8') as f:
		json.dump(state['mitigations'], f, ensure_ascii=False, indent=2)
	with ver_path.open('w', encoding='utf-8') as f:
		json.dump(state['verification'], f, ensure_ascii=False, indent=2)
	return {**state, 'trace': state['trace'] + [{'step': 'OUTPUT', 'mitigations': str(mit_path), 'verification': str(ver_path)}]}


def build_graph():
	g = StateGraph(dict)
	g.add_node('LOAD_CSV', n_load)
	g.add_node('GENERATE', n_generate)
	g.add_node('VERIFY', n_verify)
	g.add_node('OUTPUT', n_output)
	g.set_entry_point('LOAD_CSV')
	g.add_edge('LOAD_CSV', 'GENERATE')
	g.add_edge('GENERATE', 'VERIFY')
	g.add_edge('VERIFY', 'OUTPUT')
	g.add_edge('OUTPUT', END)
	return g.compile()


def run_flow(csv_path: Path, top: int, out_dir: str, debug: bool = False) -> Dict[str, Any]:
	graph = build_graph()
	state = {
		'config': {'csv': csv_path, 'top': top, 'out_dir': out_dir, 'debug': debug},
		'llm': SimpleLLM(),
		'verifier': LLMVerifier(),
		'trace': []
	}
	final_state = graph.invoke(state)
	return {
		'mitigations': final_state['mitigations'],
		'verification': final_state['verification'],
		'trace': final_state['trace']
	}


def parse_args():
	p = argparse.ArgumentParser(description='生成并静态验证临时缓解策略 (LLM only)')
	p.add_argument('--csv', type=Path, default=Path(__file__).resolve().parent.parent / 'raw_results.csv')
	p.add_argument('--top', type=int, default=-1)
	p.add_argument('--out-dir', default='plain_output')
	p.add_argument('--debug', action='store_true', help='输出原始 LLM 响应到 out-dir/llm_raw.txt')
	return p.parse_args()


def main():
	args = parse_args()
	if not args.csv.exists():
		raise SystemExit(f'CSV 不存在: {args.csv}')
	result = run_flow(args.csv, args.top, args.out_dir, debug=args.debug)
	print(json.dumps({
		'verification_summary': {k: v for k, v in result['verification'].items() if k in ('total','passed','avg_score')},
		'trace_tail': result['trace'][-3:]
	}, ensure_ascii=False, indent=2))


if __name__ == '__main__':  # pragma: no cover
	main()

