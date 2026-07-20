# 核心领域模型

V3il 的领域模型围绕一条清晰关系展开：欺骗环境产生行为，相关行为进入 Incident，调查任务引用行为并形成证据，证据支撑分析，分析最终进入报告与知识库。

```mermaid
flowchart LR
  Environment["DeceptionEnvironment"] --> Behavior["BehaviorEvent"]
  Behavior --> Incident["ThreatIncident"]
  Incident --> Task["InvestigationTask"]
  Task --> Evidence["InvestigationEvidence"]
  Evidence --> Analysis["Analysis"]
  Analysis --> Report["IntelligenceReport"]
  Incident --> Revision["DeceptionRevision"]
  Revision --> Environment
```

## 运行资源

| 概念 | 作用 |
| --- | --- |
| System User | 表示平台操作者及其权限。 |
| Managed Host | 表示可承载环境和检测运行时的 Docker 主机。 |
| Sandbox Image | 定义环境的运行基线。 |
| Sandbox Container | 表示实际运行的环境或检测实例。 |
| Egress Proxy | 定义受控外联路径。 |

运行资源归控制平面管理，为欺骗环境提供可选择、可审计的基础设施。

## Agent 协作与执行

Agent 协作使用持久化层级，将操作者看到的工作空间、一次业务任务和一次具体执行清楚分开：

| 概念 | 产品含义 |
| --- | --- |
| Agent Session | 面向操作者的长期会话与运营范围。 |
| Agent Run | 一次已经接受的工作，包括用户请求、专家任务和后续恢复。 |
| Run Attempt | 对同一个 Run 的一次有所有权执行；恢复会在同一业务请求下产生新的 Attempt。 |
| Agent Context | 一个角色在 Session 内的持久工作记忆。 |
| Tool Invocation | 一次外部操作的意图、执行状态和结果记录。 |
| Durable Event | Agent Console、审计视图和重连客户端共同使用的有序历史。 |

Chat Session 由操作者创建；每个 Incident 和欺骗环境各自拥有唯一的范围化 Session。从不同页面进入同一业务对象时，操作者都会看到同一段协作历史。

主 Agent 维护核心上下文，并把边界明确的工作委派给专家 Run。父 Run 可以等待一个确定的子 Run 结果，或者一个确定的沙箱命令批次。精确的依赖关系会把完成结果送回所属调查任务。依赖完成后，它会作为原 Run 的新一阶段继续执行，保留原请求身份，并为每个阶段提供独立恢复边界。

Context Item 保留产生它的 Attempt。已经接受的工作持续可见；被中断 Attempt 的未完成内容可以单独回退，更早的会话历史保持完整。当上下文接近模型预算时，V3il 会用持久化摘要替代较早区间，同时保留决策、证据引用、工具结果和未解决问题。

外部操作在开始前进入运行日志。恢复时可以复用已经确认的结果；执行结果不确定的操作会进入明确恢复流程。这一原则覆盖容器操作、环境变更、调查记录和报告发布。

## 欺骗环境与版本

### DeceptionEnvironment

DeceptionEnvironment 表示一个持续运营的欺骗场景。它保存环境身份、业务背景、运行位置、网络策略、当前服务、适配模式和生命周期状态。

环境是调查中的长期对象。攻击者可见内容会随版本变化，环境身份和行为历史保持连续。

### DeceptionRevision

DeceptionRevision 表示一次环境设计或调整。每个版本记录目标、变化内容、触发原因、风险、执行状态和验证结果。

版本关系使团队能够回答：

- 当前环境为什么呈现这些服务和数据；
- 哪次调整由哪些行为或调查假设触发；
- 变更是否达到预期效果；
- 失败后环境回到了什么状态。

## 行为与检测

### BehaviorEvent

BehaviorEvent 表示一次规范化的攻击行为或环境活动。网络、进程、命令、文件、认证、服务、系统调用和外联信号使用共同结构进入时间线。

事件保留来源、环境、时间、原始上下文和完整性信息，用于实时关联和后续证据复核。

### Detection Policy and Decision

检测策略描述 Zeek 或行为层面的识别逻辑；检测结果记录策略对具体行为的判断。策略版本、部署状态和结果彼此关联，便于分析检测效果。

## ThreatIncident

ThreatIncident 表示一次需要持续跟踪的攻击活动。它可以关联多个环境和行为，维护观察时间、严重度、置信度、风险、摘要和生命周期。

Incident 是调查、动态诱导和报告的共同边界。环境提供观察面，行为提供事实，任务组织分析过程，报告固定最终结论。

## 调查任务与证据

### InvestigationTask

InvestigationTask 表示一个边界清楚的调查问题，包含负责人、优先级、行为范围、依赖关系和完成标准。

### InvestigationEvidence

InvestigationEvidence 将分析陈述与具体行为和任务连接起来。证据记录保持稳定，后续分析可以增加或修订，原始引用不会丢失。

任务和证据的关系使调查具备可分工、可复核和可追踪的结构。

## 分析与情报

V3il 维护以下分析对象：

| 分析对象 | 关注内容 |
| --- | --- |
| Intent Assessment | 攻击阶段、目标、可信度和后续动作假设。 |
| Attack Chain | 攻击步骤、因果关系、证据和缺口。 |
| Threat Indicator | 可检索和可用于响应的指标及其上下文。 |
| Attacker Profile | 目标偏好、能力、工具、行为模式和归因边界。 |
| Risk Assessment | 影响、紧迫度、停止条件、响应建议和残余风险。 |

分析采用版本化方式保存。当前版本用于运营决策，历史版本用于解释判断如何变化。

## 报告、知识与审计

### IntelligenceReport

IntelligenceReport 汇总 Incident 的关键分析、证据范围、响应建议和结论。报告引用确定的分析与证据版本，后续更新不会改变已发布内容。

### Knowledge

最终报告和研究资料可以进入 LightRAG，形成跨 Incident 的检索与知识关联。

### Audit Event

审计记录覆盖环境版本、Incident 状态、任务、证据、分析、智能体协作和报告发布等关键动作。它提供运营过程的时间线，而不承担业务事实本身。

## 建模原则

- 环境、Incident 和报告提供稳定的业务边界；
- 行为与证据保留原始来源；
- 分析和环境变化采用版本化记录；
- 关系对象保留事件、环境、任务和证据之间的来源信息；
- 当前状态服务运营视图，历史版本服务复核与审计；
- Session 保存协作历史，Run 与 Attempt 明确表达执行和恢复；
- 有业务范围的对象只复用一个权威 Agent Session；
- 等待中的工作明确指向唯一依赖，后续结果只交付给所属 Run 一次；
- 外部副作用先记录，结果不确定时进入明确恢复；
- 归档保留会话历史，退役结束长期资源的活动生命周期，移除用于处置运行实例；
- 敏感数据按照可信管理网络的安全要求处理。
