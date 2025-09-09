# （简化版）K8s 第三方应用高危漏洞防控工具规划
本简化规划替代下方详版的通用“大而全”方案，只聚焦：Kubernetes 第三方应用 高危（High / Critical） 权限提升相关漏洞的快速防控。目标：不同漏洞类型 → 输出差异化、最小集策略组合。核心只做四件事：采集、分类、匹配模板、生成+验证策略。

## 1. 适用范围与非目标
仅覆盖：已公开或实时订阅的第三方应用（如 Istio / Cilium / Calico / KubeVirt 等）高危 CVE，聚焦可导致权限提升或放大攻击面的配置/逻辑/运行时风险。
不做：全面代码审计、镜像逆向、通用攻击检测平台；不处理低危/信息泄露级别（除非其直接可链入 PE）。

## 2. 漏洞类型分类（精简 7 类）
| 类型编码 | 名称 | 判定关键特征（输入信号） | 核心防控输出（策略集合最小化） |
|----------|------|--------------------------|--------------------------------|
| T1 | RBAC 过度权限 / 配置错误 | CVE 中包含 verbs over-privileged / rolebinding 误指向 cluster-admin | RBAC Patch + Admission 限制（可选） + Falco 行为监测（可疑 kubectl/exec） |
| T2 | 安全逻辑缺陷（鉴权/越权） | 描述含 bypass / improper auth / logic flaw | 临时 NetworkPolicy 限制入口面 + Falco 规则监控异常调用参数 + 受影响组件隔离降权 |
| T3 | 代码注入 / RCE | 描述含 command injection / RCE / arbitrary command | Falco 进程/系统调用规则 + 限制容器可执行目录挂载 + 强制只读 FS（Patch Deployment） |
| T4 | 敏感信息泄露助推 PE | 可读取 Secret / token / credentials | Secret Rotation + RBAC 限制 get secrets + Falco 规则监控大规模 secret 列举 |
| T5 | 路径遍历 / 文件系统逃逸 | path traversal / arbitrary file read/write | Pod Security（只读 rootfs）+ Volume 挂载白名单 + Falco 文件访问规则 |
| T6 | 网络隔离/信任边界缺陷 | unrestricted access / missing auth between services | 临时 NetworkPolicy 白→灰收紧 + ServiceAccount 分离 + 流量异常监控 |
| T7 | 容器运行时 / 特权能力滥用 | privileged / CAP_* 提升 / runtime escape | 去特权补丁（drop capabilities）+ Seccomp/PSA 配置 + Falco 监控特权 Syscall |

## 3. 端到端最小流程
1) CVE 采集：订阅 NVD / GitHub Advisory / CNCF 项目 Release Note（正则抓取组件名+版本范围+描述）。
2) 分类：规则优先 + 轻量 LLM 回退（Prompt 输出 {type:Tx, evidence:[...]}）。
3) 上下文收集：只拉取与该组件有关的命名空间内：Deployments、ServiceAccounts、Roles、NetworkPolicy（选择性）。
4) 模板匹配：按类型选中策略模板集合（见下）。
5) 实例化：填充占位符（namespace / sa / role / selectors）。
6) 静态校验：YAML 语法、RBAC verbs 只减不增、NetworkPolicy label 存在、Falco 规则 lint。
7) 影子验证：server-side dry-run；可选：对测试命名空间 replay 合成事件。
8) 发布策略：标记为 staged（人工快速眼审 <5 分钟）→ active；记录版本号 + 回滚指针。
9) 反馈：采集命中事件频率、失败调用、用户回滚标记→ 更新分类或模板权重。

## 4. 策略模板最小集合（每类最多 3 个）
| 类型 | 模板代号 | 描述 | 触发条件 | 可回滚标记 |
|------|----------|------|----------|------------|
| T1 | rbac-min-verb | 去除未观测高危动词 (create/update/delete/patch) | verbs 差集非空 | yes |
| T1 | falco-kubectl-restrict | 监控高危 SA 调用 kubectl exec/apply | SA 属于风险角色 | yes |
| T2 | netpolicy-tight-ingress | 限制到受影响 Pod 的源（同 ns label + 必需组件） | 无现有 NetworkPolicy 或过宽 | yes |
| T2 | falco-abnormal-verb | 监控异常资源动词组合 | 日志出现未声明动词 | yes |
| T3 | falco-shell-spawn | 监控 /bin/sh /bash 异常启动 | 进程树包含注入向量 | yes |
| T3 | pod-readonlyfs-patch | 将 Deployment 设置 readOnlyRootFilesystem=true | 当前为 false | yes |
| T4 | rbac-secret-restrict | 移除 list/get secrets 动词（保留必要） | verbs 含 get/list secrets | yes |
| T4 | falco-secret-scan | 检测短时间内多次 secret 访问 | 访问频率阈值 | yes |
| T5 | falco-path-traversal | 匹配可疑访问 .. / etc/passwd 等 | 捕获文件路径模式 | yes |
| T5 | volume-whitelist | 限制 Deployment volumes 指定列表 | 非核心 volume 挂载 | yes |
| T6 | netpolicy-deny-egress | 默认拒绝 egress + 允许白名单 | Pod 现为全开放 | yes |
| T6 | sa-split | 将共享 SA 拆分为独立最小 SA | SA 绑定多 Deployment | partial |
| T7 | drop-capabilities | 移除 NET_RAW / SYS_ADMIN 等 | Pod spec 有过多 capabilities | yes |
| T7 | seccomp-enforce | 应用 runtime/default 或自定义 seccomp | 未设 seccompProfile | yes |

## 5. 轻量 JSON 输出格式
```json
{
	"cve": "CVE-2024-33522",
	"component": "Calico",
	"type": "T1",
	"risk_level": "HIGH",
	"evidence": ["description: privilege escalation", "rolebinding->cluster-admin"],
	"selected_templates": ["rbac-min-verb", "falco-kubectl-restrict"],
	"patches": [{"kind":"ClusterRole","name":"calico-node","patch":"...jsonpatch..."}],
	"falco_rules": ["rule: Detect Calico Node Kubectl Exec ..."],
	"dry_run_result": "pass",
	"next_actions": ["apply_staged"],
	"rollback_id": "2025-09-06T10:12:33Z-uuid"
}
```

## 6. 组件（极简）
- CVEIngestor：拉取 + 去重。
- VulnClassifier：规则 > LLM 回退。
- ContextFetcher：按组件 label 过滤。
- TemplateEngine：模板 + 占位符填充。
- PolicyValidator：静态 + dry-run。
- Publisher：staged / active / rollback。
- MetricsStore：记录触发与误报。

## 7. 简化实现优先级（2 周节奏）
| 周 | 目标 | 可交付 |
|----|------|--------|
| 1 上 | 分类规则 + 5 个模板 + RBAC diff 逻辑 | CLI 原型 |
| 1 下 | Falco 规则生成 + dry-run 验证 | 示例策略集 |
| 2 上 | NetworkPolicy / Capability Patch | 扩展模板 |
| 2 下 | Staged→Active 发布 + 回滚 | Demo 演示 |

## 8. 快速 CLI 设想
```
pe-guard classify --cve ./data/cve_calico.json
pe-guard generate --profile out/profile.json --context kubeconfig --output artifacts/
pe-guard validate artifacts/ --dry-run
pe-guard publish artifacts/ --mode staged
pe-guard rollback <rollback_id>
```

## 9. 与详版关系
本简化方案 = 详版的子集，仅保留“CVE→分类→模板→策略”主链路。后续若需引入 RAG、置信度模型、闭环学习，再迁移到下方“详版”架构。

---

# KubeAgent4PE 工具实现规划：大模型驱动的权限提升防护策略生成器

本文档基于前述“Kubernetes 应用权限提升风险动态防控技术研究”总体框架，对其中一个核心工具——“大模型驱动的权限提升防护策略生成器”进行工程化实现规划。该工具聚焦最新披露且可能暂未完全修复的高危权限提升（Privilege Escalation, PE）漏洞场景，自动生成、验证并发布多形态（Falco 规则 / RBAC 最小化补丁 / NetworkPolicy / Secret 访问白名单）的防护策略，实现快速、可解释、可闭环迭代的动态防控。 

## 1. 工具定位与范围
目标：输入“漏洞 + 集群上下文 + 第三方应用语义”→ 输出“可执行并已验证的多策略组合”，并形成持续优化反馈。

核心价值：
1. 缩短高危权限提升漏洞披露到有效缓解的窗口时间（MTTM）。
2. 将非结构化安全情报与运行态语义（Pods / ServiceAccounts / eBPF 事件）统一为可机读特征。
3. 以“防护中间代码（Defense IR, DIR）”抽象解耦 LLM 生成与最终策略格式，提升一致性与可审计性。
4. 提供静态 + 动态双阶段验证，降低误报 / 破坏业务风险。

不做：
- 不直接负责 eBPF 探针事件采集实现（依赖现有 Falco / 自研采集侧）。
- 不执行镜像逆向分析（仅消费其结果摘要）。
- 不提供漏洞扫描功能（消费外部扫描器或情报源的 CVE 数据）。

## 2. 总体架构
```
┌────────────────────────────────────────────────────────────────┐
│                大模型驱动权限提升防护策略生成器                 │
├───────────────┬───────────────────────────────┬───────────────┤
│  A. 数据采集层 │ B. 语义与知识检索层            │ C. 生成与验证层 │
├───────────────┼───────────────────────────────┼───────────────┤
│ - CVE Feed     │ - 向量检索(Embedding)          │ 1) DIR 生成     │
│ - 集群 RBAC    │ - 结构化图谱(Risk Graph)       │ 2) 策略多模生成 │
│ - Falco 事件   │ - 规则/策略历史库              │ 3) 静态校验     │
│ - 镜像元信息   │ - 失败样本 & 反馈缓存          │ 4) 动态模拟     │
│ - Git 应用代码 │                               │ 5) 置信度评估   │
├───────────────┴───────────────────────────────┴───────────────┤
│                         D. 发布与闭环层                           │
│  - 策略分发控制  - 回滚快照  - 运行指标指标采集  - 在线反馈回注入 │
└────────────────────────────────────────────────────────────────┘
```

## 3. 关键数据与中间表示
### 3.1 Defense IR（DIR）规范（示例 JSON）
```json
{
	"vuln_id": "CVE-2024-33522",
	"threat_class": "PrivilegeEscalation/OverPrivilegedRBAC",
	"attack_path": ["ServiceAccount:calico-node", "ClusterRole:cluster-admin"],
	"required_capabilities": ["get","list","watch"],
	"risky_capabilities": ["create","update","delete"],
	"observed_events": [{"syscall":"execve","proc":"kubectl","sa":"calico-node"}],
	"mitigation_intent": ["restrict rbac", "falco detect exec of kubectl", "deny secret read"],
	"asset_scope": {"namespace":"kube-system","sa":"calico-node"},
	"confidence": {"score":0.82,"evidence":["rbac_diff","falco_pattern"]},
	"policy_targets": ["falco","rbacPatch","networkPolicy"],
	"validation_requirements": ["no forbidden verbs post-patch","falco rule passes syntax"]
}
```
说明：
- 将多源上下文映射为统一威胁语义；
- 仅当策略变更穿透生产前，才落盘/版本化；
- 可由多次检索 + 多轮 LLM 推理增量完善。

### 3.2 图谱 & 索引
- Risk Graph：节点（Workload / SA / Role / RoleBinding / Secret / CVE / Image / SyscallPattern），边（uses、binds、owns、triggers、exposes）。
- 向量库字段：chunk_id, type(code|doc|cve|event), embedding, source_ref, updated_at。
- 策略版本：policy_id, dir_hash, kind(falco|rbac|np|secret), yaml, status(draft|validated|staged|active|rolledback), metrics(hit,fp,tp,latency)。

## 4. 模块设计
| 模块 | 功能 | 关键点 |
|------|------|--------|
| IngestionCollector | 订阅/抓取 CVE、RBAC、Falco 事件、镜像元信息 | 去重、节流、增量标签 |
| Normalizer | 解析并结构化安全与运行态数据 | 统一字段 + 脱敏 |
| EmbeddingIndexer | 生成嵌入 & 建立向量索引 | 支持重建 / 软删除 |
| RetrievalOrchestrator | 基于查询意图（漏洞/策略补丁）进行多通道检索 | RAG 合并 & 置信度打分 |
| DIRBuilder (LLM Chain) | 多轮提示生成/补全 DIR | 审计日志保留中间思考摘要 |
| StrategyGenerator | DIR → 多策略实例化（Falco / RBAC Patch / NetworkPolicy / Secret 白名单） | 模版 + LLM 填充 + 规则规范化 |
| StaticValidator | YAML 语法 / 规则冲突 / RBAC 动作差集 | Policy Sandbox (离线 APIServer) |
| DynamicSimulator | kubectl dry-run / 假事件回放 / Falco 规则加载测试 | 支持超时/回滚 |
| ConfidenceScorer | 综合历史命中率、相似策略经验、静/动态测试结果 | Bayesian Update |
| Publisher | 分阶段发布 & 原子回滚 | GitOps / CRD 控制 |
| FeedbackLoop | 采集运行指标与误报反馈→ 回注 DIR | 形成经验记忆库 |

## 5. 生成链路（端到端流程）
1. 触发：新 CVE 或检测到异常事件模式（Falco 聚类阈值）。
2. 检索：构建查询向量（CVE 描述 + 相关组件 + 角色绑定差异），多路检索（向量库 + 图谱 + 历史策略相似度）。
3. 初始 DIR：LLM 依据检索上下文 + 规则模板生成首版 DIR（缺省字段标记 unknown）。
4. 完善：补充运行态证据（最近 24h 高风险 SA 行为），二次推理填补 unknown。
5. 策略生成：按 policy_targets 顺序生成；生成时写入约束（如：RBAC 动词只做减法）。
6. 静态验证：
	 - Falco 规则：语法 + 字段合法性。
	 - RBAC Patch：对比变更前后 diff，确认未授予新动词。
	 - NetworkPolicy：校验命名空间与 label 匹配集合非空。
7. 动态模拟：
	 - kubectl --dry-run=server 应用 Patch。
	 - 回放测试事件（内置基准 + CVE 特征合成）。
	 - 收集命中率 & 性能（触发延迟）。
8. 置信度计算：score = w1*静态通过 + w2*覆盖度 + w3*低误报预估 + w4*历史可信度。
9. 发布：阈值 >= 0.75 进入 staged；业务窗口人工（可选）批准后 active。
10. 运行反馈：实时指标进入反馈池；≥N 次误报 → 自动降级 / 触发再训练。

## 6. 核心算法要点
### 6.1 RBAC 最小化 Patch 生成
输入：当前 Role/ClusterRole YAML + DIR.risky_capabilities + observed_events。
步骤：
1. 解析 verbs 交集/差集；
2. 构建动词使用频率映射（事件日志）；
3. 移除低频 & 未观测高危动词（create/delete/patch/update/impersonate/escalate）；
4. 验证移除后是否破坏必需链路（模拟 get/list/watch）；
5. 输出 JSON Patch / StrategicMerge Patch。

### 6.2 Falco 规则模板化
模板示例（占位符 {proc} {sa} {ns}）：
```
rule: Detect Suspicious Kubectl Exec via High-Risk SA
condition: proc.name = kubectl and ka.user.name = {sa} and k8s.ns.name = {ns} and not ka.resource.verb in (get, list, watch)
output: "PE Attempt: {sa} exec kubectl with verb=%ka.resource.verb (ns={ns})"
priority: WARNING
tags: [k8s, privilege_escalation, {vuln_id}]
```
生成逻辑：
1. 由 DIR.attack_path 推断关键主体（SA / Role）。
2. 引入约束：不捕获噪声（白名单进程、CI 管道标签）。
3. 多候选生成 → 选择最小触发集合（启发式：平均历史触发/候选数量）。

### 6.3 置信度评分（示意）
```
score = 0.25*S_static + 0.30*S_dynamic + 0.20*S_coverage + 0.15*(1-FP_rate_pred) + 0.10*History_trust
```
FP_rate_pred：基于相似策略历史触发频率与基线业务时序特征的回归模型。

## 7. Prompt / Chain 设计（摘要）
- System Prompt：注入角色（安全策略专家 + K8s RBAC & Falco 规则专家），给出输出 JSON Schema（DIR）。
- Retrieval Context：Top-K 分块（CVE 摘要 + 角色绑定 + 近 24h 事件统计 + 相关历史策略 diff）。
- Self-Refine：第一轮生成 DIR；第二轮比对约束清单（必填字段 / 语义一致性）→ 修正。
- Guardrails：正则校验 JSON；关键信息缺失时强制返回 reason 字段，阻断后续生成。

## 8. API / 接口契约（初版）
```
POST /v1/dir/build { cve_id?, signals:{...}, mode:initial|refine }
GET  /v1/dir/{id}
POST /v1/strategy/generate { dir_id, targets:["falco","rbacPatch"] }
POST /v1/strategy/validate { strategy_id }
POST /v1/strategy/publish { strategy_id, stage:staged|active }
POST /v1/feedback/report { strategy_id, event_type, meta }
GET  /v1/strategy/{id}/metrics
```
鉴权：ServiceAccount + OIDC / 内部网关；审计：所有变更写入审计日志（不可变对象存储）。

## 9. 技术栈建议
- 语言：Python（策略生成、检索编排）、Go（高性能验证微服务，可复用 K8s 客户端生态）。
- 向量库：Qdrant / Milvus（支持过滤条件 + 相似度搜索）。
- 数据存储：PostgreSQL（关系 & 事务）、Redis（短期缓存与事件节流）。
- LLM 接入：可插拔（OpenAI / 本地 Qwen / Llama），统一抽象接口。
- 工作流：LangGraph / 自研有限状态机。
- K8s 交互：官方 Python client + server-side dry-run。
- 策略语法检测：Falco CLI / 自研 YAML Linter。
- 监控：Prometheus + Loki（策略命中日志流）。

## 10. 初始目录结构（建议）
```
strategy-engine/
	ingestion/
	retrieval/
	dir/
	generation/
	validation/{static,dynamic}/
	publish/
	feedback/
	api/
	scripts/
	tests/
	docs/
```

## 11. 迭代里程碑
| 版本 | 时间 | 范围 | 指标目标 |
|------|------|------|----------|
| v0 (PoC) | 第1月 | 手工注入 5 个 CVE → 生成 Falco 规则 + RBAC Patch | 生成成功率 ≥80% / 无语法错误 |
| v1 | 第2月 | 引入 DIR + 静态验证 + Dry-run | FP <25%（小样本评估） |
| v2 | 第3-4月 | 动态模拟 + 置信度评分 + 发布回滚 | 生成→上线 TAT < 30min |
| v3 | 第5-6月 | 多策略协同 + 反馈自适应 | 误报率下降 30% / 回滚率 <5% |
| v4 | 第7月+ | 模型自适应调优 + 多租户隔离 | 按业务域策略分层 |

## 12. 评估指标体系
- 策略生成质量：语法通过率、一次成功率、DIR 完整度。
- 防护覆盖：针对测试用 CVE 集合的攻击路径覆盖率（手工标注 Ground Truth）。
- 运行表现：平均策略生效延迟、监控开销（CPU / 内存 / 事件额外延迟）。
- 精准度：TP/FP/FN、Precision、Recall、F1。
- 自适应收益：反馈后误报下降幅度、策略迭代收敛轮次。
- 可解释性：自动生成解释文本长度 & 人审通过率。

## 13. 风险与缓解
| 风险 | 影响 | 缓解策略 |
|------|------|-----------|
| LLM 幻觉生成危险规则 | 生产环境中断 | 严格静态+动态双关；不达阈值不发布 |
| 向量检索召回不足 | 漏报策略 | 多通道（关键字+图谱补充）+ 召回监控 |
| RBAC Patch 误删关键动词 | 业务失败 | Dry-run + 影子流量模拟 + 回滚快照 |
| 高并发事件导致延迟 | 策略滞后 | 事件聚合窗口 / 胶囊队列优先级调度 |
| 模型上下文漂移 | 质量下降 | 周期性再评估 + 回放基准集 |

## 14. 安全与合规注意事项
- 对含敏感资源名称（Secret 名、内网域名）脱敏后再入向量库。
- 全量策略与审核日志写入 WORM（Write Once Read Many）存储，满足审计要求。
- 访问控制：策略发布 API 需二次确认（MFA / 审批流）。
- 限制 LLM 输出：对外链/命令执行类文本设正则黑名单。

## 15. 后续扩展方向（展望）
1. 引入因果链分析（Causal Graph）评估策略阻断效果边际收益。
2. 引入对运行态 eBPF 数据的在线特征抽取（如内核对象访问模式）增强 DIR 语义。
3. 策略多目标优化（覆盖 vs. 误报 vs. 性能）使用强化学习调参。
4. 与镜像供应链安全（SBOM / 签名）联动，按镜像风险分级生成策略强度。
5. 与 GitOps（ArgoCD / Flux）双向同步，实现策略漂移检测。

## 16. 最小可行版本（MVP）执行清单（v0）
1. 采集：手动导入 ≥5 个 CVE + 目标集群当前 RBAC YAML。
2. 检索：本地向量库（文本分块 + OpenAI Embedding / 替换为本地模型）。
3. 生成：单 Prompt 产出 DIR + Falco 规则 + RBAC Patch。
4. 验证：Falco 规则 lint + RBAC 语法 + verbs 差集检查。
5. 输出：将策略写入 `artifacts/` 目录并生成汇总报告 JSON。

---
本规划为后续代码实现、测试与评估提供工程蓝图，可直接据此拆分任务进入迭代。欢迎补充讨论具体实现优先级。

