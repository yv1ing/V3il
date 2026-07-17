---
layout: home
pageClass: v3il-docs-home

hero:
  name: V3il
  text: 欺骗驱动的自主蓝队运营平台
  tagline: 将环境编排、行为观测、Incident 调查、动态诱导与情报交付放在同一条运营链路中。
  image:
    src: /v3il-logo.png
    alt: V3il
  actions:
    - theme: brand
      text: 快速开始
      link: /zh/guide/quick-start
    - theme: alt
      text: 产品架构
      link: /zh/guide/overview

features:
  - title: 欺骗环境
    details: 通过自然语言和参考资料设计攻击者可见环境，以版本化方式部署、验证和调整。
  - title: 行为与检测
    details: 汇聚多层行为遥测与 Zeek 信号，将相关活动组织为连续、可追溯的 Incident 时间线。
  - title: 多智能体调查
    details: 五个固定角色围绕任务、证据和复核协作，形成攻击意图、攻击链、画像与风险判断。
  - title: 情报交付
    details: 将调查结论沉淀为响应建议、报告、证据包和可检索知识。
---

## 核心链路

```mermaid
flowchart LR
  Environment["欺骗环境"] --> Behavior["行为与检测"]
  Behavior --> Incident["ThreatIncident"]
  Incident --> Team["五智能体调查"]
  Team --> Adapt["动态诱导"]
  Adapt --> Environment
  Team --> Output["情报、响应与报告"]
```

V3il 从攻击者与环境的真实互动出发。环境提供可控的观察面，行为与检测信号进入 Incident，智能体团队围绕证据开展调查，并根据判断调整环境或形成响应结论。

继续阅读[产品架构](/zh/guide/overview)、[端到端流程](/zh/guide/workflow)、[欺骗环境](/zh/guide/deception)和[调查与证据](/zh/guide/investigation)。
