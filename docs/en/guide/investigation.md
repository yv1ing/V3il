# Investigation And Evidence

A ThreatIncident is the investigative thread in V3il. It keeps related environments, behavior, detections, tasks, evidence, analysis, adaptive engagement, and reporting in one context so the team can understand how an attack is developing and whether the current conclusions support a response.

## Incident View

An Incident is expected to answer:

- Which environments and time periods are involved?
- How are the attacker actions related?
- Which questions have been investigated, and where are the gaps?
- What evidence supports the current intent, attack chain, and profile?
- What is the risk and response priority?
- Which environment changes have been made, and what happened afterward?
- Is the investigation ready for reporting and closure?

New material behavior can extend an active Incident or create a new one. An Incident can return from final review when new evidence arrives.

## Five-Agent Collaboration

| Code | Name | Investigation responsibility |
| --- | --- | --- |
| `cso` | V3il | Plan the investigation, coordinate specialists, resolve conflicts, review conclusions, and manage Incident progress. |
| `cth` | H4wk | Reconstruct behavior, timelines, attack paths, techniques, and intent. |
| `cde` | Ph4ntom | Evaluate and implement environment changes that can test a hypothesis. |
| `cie` | L1ly | Develop indicators, external context, attacker profiles, and attribution limits. |
| `cir` | J4ck | Assess risk, stop conditions, response priorities, and defensive improvements. |

V3il coordinates work across the roles. Specialists work through scoped tasks, which reduces duplicate analysis and unsupported conclusions.

## Investigation Plan

A task has four essential parts:

1. **Question:** The security question to answer.
2. **Scope:** The behavior and context relevant to that question.
3. **Owner:** The specialist role best placed to answer it.
4. **Completion criteria:** The required evidence, analysis, or decision.

Tasks can depend on one another. Behavior reconstruction may precede an intent assessment; target-data confirmation may precede an environment change. V3il coordinates these dependencies and reviews specialist submissions.

## Evidence Standard

Evidence connects source behavior, the investigation task, and the analytical statement. Useful evidence has:

- a clear source and time;
- direct relevance to the question;
- an explanation of the judgment it supports or weakens;
- explicit relationships to other evidence;
- enough original context for review;
- a path for another operator to verify it.

Behavior records include integrity context that can reveal missing, reordered, or replaced data. Evidence coverage and integrity contribute to task review and final-report checks.

## Analytical Outputs

The investigation maintains five main outputs:

- **Intent:** The attacker's current goal, stage, confidence, and likely next action.
- **Attack chain:** A temporal and causal sequence of behavior, evidence-backed steps, and known gaps.
- **Threat indicators:** Network, host, identity, or tool indicators useful for retrieval, detection, and response.
- **Attacker profile:** Objectives, capability, working style, tools, infrastructure, and attribution limits.
- **Risk assessment:** Impact, urgency, stop conditions, response guidance, defensive improvements, and residual risk.

A material revision creates a new version. The Incident workspace presents the current conclusion and preserves the history and reason for change.

## Review And Audit

V3il reviews specialist work for task scope, evidence coverage, consistency, and unresolved gaps. Operators can inspect task assignment, Agent work, environment changes, analytical versions, Incident state, and report publication.

The audit timeline answers who acted, when they acted, what supported the action, and how it affected the rest of the investigation.

## Reporting And Closure

Before reporting, V3il checks that:

- material behavior is covered by the investigation;
- critical tasks have passed review;
- intent, attack chain, profile, and risk are mutually consistent;
- supporting evidence is available and intact;
- active environment changes and specialist work have finished;
- the report references fixed analytical and evidence versions.

After publication, V3il can create an evidence package and publish the report to LightRAG. Closed Incidents retain their timeline, evidence, analysis, report, and audit history for later review and retrieval.
