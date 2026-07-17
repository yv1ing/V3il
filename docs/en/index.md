---
layout: home
pageClass: v3il-docs-home

hero:
  name: V3il
  text: Deception-led autonomous blue-team operations
  tagline: Connect environment orchestration, behavior observation, Incident investigation, adaptive engagement, and intelligence delivery.
  image:
    src: /v3il-logo.png
    alt: V3il
  actions:
    - theme: brand
      text: Get Started
      link: /en/guide/quick-start
    - theme: alt
      text: Product Architecture
      link: /en/guide/overview

features:
  - title: Deception Environments
    details: Design attacker-facing environments from natural-language goals and reference material, then deploy, verify, and adapt them through versioned changes.
  - title: Behavior And Detection
    details: Combine layered telemetry with Zeek signals and organize related activity in a continuous, traceable Incident timeline.
  - title: Multi-Agent Investigation
    details: Five fixed roles collaborate through scoped tasks, evidence, and review to develop intent, attack chains, profiles, and risk.
  - title: Intelligence Delivery
    details: Turn investigation results into response guidance, reports, evidence packages, and searchable knowledge.
---

## Core Workflow

```mermaid
flowchart LR
  Environment["Deception environment"] --> Behavior["Behavior and detection"]
  Behavior --> Incident["ThreatIncident"]
  Incident --> Team["Five-Agent investigation"]
  Team --> Adapt["Adaptive engagement"]
  Adapt --> Environment
  Team --> Output["Intelligence, response, and report"]
```

V3il begins with real interaction between an attacker and a controlled environment. The environment provides the observation surface, behavior and detection signals enter an Incident, and the Agent team uses evidence to investigate, adapt the environment, or reach a response decision.

Continue with [Product Architecture](/en/guide/overview), [End-to-End Workflow](/en/guide/workflow), [Deception Environments](/en/guide/deception), and [Investigation And Evidence](/en/guide/investigation).
