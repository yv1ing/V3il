# V3il

<p align="center">
  <img src="assets/v3il-logo.png" width="240" alt="V3il logo">
</p>

<p align="center"><strong>Hide the truth. Reveal the threat.</strong></p>

V3il is an autonomous blue-team operations platform for teams that need to observe, investigate, and respond to real attacker behavior. It uses programmable deception environments as the observation surface and connects behavior capture, Incident correlation, multi-Agent investigation, adaptive engagement, threat intelligence, and reporting in one operational workflow.

[中文说明](README_zh.md) | [Documentation](docs/en/index.md)

## Product Positioning

V3il treats deception as an active observation surface within a complete blue-team operating model. Environments, behavior, Incidents, investigation tasks, evidence, and analytical conclusions remain connected so the team can answer three questions throughout an operation:

- What is the attacker doing, and how are the actions related?
- Which environmental signals should change to test the next hypothesis?
- Which evidence supports the current conclusion, and is it ready for response or reporting?

V3il is designed for internal blue teams, threat research groups, and controlled security labs with explicit authorization, dedicated infrastructure, and a trusted management network.

## Core Workflow

```mermaid
flowchart LR
  Design["Design deception environment"] --> Deploy["Deploy and verify"]
  Deploy --> Observe["Capture attacker behavior"]
  Observe --> Correlate["Correlate ThreatIncident"]
  Correlate --> Investigate["Multi-Agent investigation"]
  Investigate --> Adapt["Adapt deception strategy"]
  Adapt --> Observe
  Investigate --> Decide["Intelligence and response decisions"]
  Decide --> Report["Report, evidence, and knowledge"]
```

The operator defines the environment objective, runtime location, image, egress policy, reference material, business surface, and expected interactions. Once the environment is live, V3il collects behavior and detection signals, groups related activity into a ThreatIncident, and coordinates five specialist roles around the investigation. Findings can lead to a risk decision, a report, or another environment change that tests a hypothesis and captures the attacker's next move.

## Core Capabilities

- **Deception orchestration:** Design services, identities, data, and interaction paths from natural-language goals and reference material, with versioned environment changes.
- **Behavior and detection:** Combine network, process, command, file, authentication, service, and egress activity with Zeek detections in a continuous timeline.
- **Incident correlation:** Organize related activity across environments while preserving source, time, and environment relationships.
- **Multi-Agent investigation:** Divide work across investigation, deception, intelligence, response, and coordination roles.
- **Evidence and audit:** Track task scope, evidence references, analytical versions, review decisions, and material state changes.
- **Intelligence and reporting:** Produce intent, attack-chain reconstruction, indicators, attacker profiles, risk assessments, response guidance, reports, and evidence packages.
- **Operational infrastructure:** Manage Docker hosts, runtime images, containers, egress proxies, terminals, files, and knowledge.

## Business Workspaces

V3il organizes operations around two durable business spaces:

- **Threat Incident:** The investigation space for correlated behavior, tasks, evidence, analysis, decisions, audit history, reporting, and knowledge publication.
- **Deception Environment:** The engagement space for attacker-facing services, environment versions, detection coverage, runtime state, observed behavior, and adaptive change.

Each business object owns one canonical Agent Session. Operators entering from the workspace, Agent Console, or Agent Operations return to the same collaboration history and current state.

## Architecture

```mermaid
flowchart TB
  Operator["Blue-team operator"] --> Workbench["Operations workbench"]
  Workbench --> Control["Control and orchestration"]
  Control --> Agent["Multi-Agent collaboration"]
  Control --> Runtime["Deception runtime"]
  Runtime --> Surface["Attacker-facing environment"]
  Runtime --> Telemetry["Behavior and detection signals"]
  Telemetry --> Incident["Incident and evidence"]
  Agent --> Incident
  Incident --> Intelligence["Intelligence, response, and report"]
  Intelligence --> Knowledge["LightRAG knowledge"]
  Control --> Data[("PostgreSQL")]
```

The architecture has five primary concerns:

1. The **operations workbench** presents environments, Incidents, detections, intelligence, Agent work, and infrastructure.
2. The **control and orchestration layer** manages identity, resource lifecycle, task state, and recovery.
3. The **deception runtime** hosts attacker-facing services in controlled Docker environments.
4. The **behavior and evidence layer** owns correlation, investigation scope, evidence, analytical versions, and audit history.
5. The **Agent collaboration layer** advances investigation, environment adaptation, and review through role-based work.

### Reliable Agent Execution

Agent collaboration follows one product model across chat, Threat Incident, and Deception Environment work:

| Concept | Product responsibility |
| --- | --- |
| Session | The durable workspace, business scope, and ordered collaboration history visible to operators. |
| Run | An accepted objective, including an operator request, specialist assignment, or continuation. |
| Attempt | One execution of a Run, with a clear recovery boundary when ownership or process state changes. |
| Context | Persistent working memory for one Agent role, with provenance for accepted decisions, evidence, and tool results. |

The main Run can delegate bounded questions to specialist Runs. A parent Run waiting for a specialist result or sandbox operation records that exact dependency and continues once when the expected result becomes available. Parallel work remains attached to the investigation branch that requested it.

Each specialist works in an isolated, persistent Context with clear provenance. Context compression retains decisions, evidence references, unresolved questions, confirmed tool outcomes, and recent work. An interrupted Attempt leaves accepted history intact and removes incomplete contribution from the next execution boundary.

External actions with a confirmed outcome can continue through the normal workflow. An uncertain tool invocation or Sandbox command enters the Agent Operations recovery queue for an explicit operator decision. The Session resumes only after that ambiguity has been resolved.

The durable event history is the authoritative Agent record. Live updates, reconnects, and historical review all project the same ordered Session state. Completed reports remain available while Knowledge Publication continues as durable follow-up work.

## Agent Defense Team

| Code | Name | Role | Primary responsibility |
| --- | --- | --- | --- |
| `cso` | V3il | Chief Security Officer | Set investigation scope and plans, coordinate specialists, review conclusions, and manage Incident progress. |
| `cth` | H4wk | Threat Investigation Engineer | Reconstruct behavior, timelines, attack paths, and intent while maintaining the evidence chain. |
| `cde` | Ph4ntom | Deception Defense Engineer | Design, deploy, and adapt deception environments and verify each change. |
| `cie` | L1ly | Cyber Threat Intelligence Engineer | Develop indicators, external context, attacker profiles, and intelligence assessments. |
| `cir` | J4ck | Security Response Engineer | Assess risk and stop conditions, then recommend response priorities and defensive improvements. |

## Quick Start

V3il requires Linux, Docker Compose, PostgreSQL, five OpenAI-compatible Agent model endpoints, and the model endpoints used by LightRAG.

```bash
cp .v3il/config.json.example .v3il/config.json
cd sandbox
./build.sh
cd ..
docker compose -f docker-compose.prod.yml up -d --build
```

Open `http://127.0.0.1:8000`, sign in with the bootstrap administrator, verify the Managed Host and Sandbox Image, and create the first deception environment.

See [Quick Start](docs/en/guide/quick-start.md) and [First Use](docs/en/guide/first-use.md) for the guided setup.

## Operational Boundary

V3il manages Docker hosts, model credentials, and attacker behavior data. Keep the control plane, database, configuration, Docker management interfaces, reports, and evidence inside a trusted management network. Isolate attacker-facing environments from management and production networks. Captured credentials, tokens, and other sensitive data should follow the organization's access, audit, and retention policies.
