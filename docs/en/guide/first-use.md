# First Use

This walkthrough uses a controlled test to verify the main V3il operational flow.

## 1. Review Command Center

After signing in, check Command Center for Managed Host, Sandbox Image, detection service, Agent model, and LightRAG health.

Resolve unavailable infrastructure in the relevant administration page before creating an environment.

## 2. Choose A Test Scenario

Start with a bounded scenario such as an internal administration site, file exchange service, or business application with an authentication flow. Write down:

- the business context presented to the attacker;
- the behavior and decisions you want to observe;
- the permitted network exposure and egress.

These points provide a common reference for environment design and investigative review.

## 3. Create A Deception Environment

In Deception Environments, select the Managed Host, Sandbox Image, egress policy, and adaptation mode, then attach any useful reference material.

Use the environment Agent Console to describe the service structure, identity relationships, data, user journeys, and observation goals. Ph4ntom proposes the environment design and completes deployment and verification.

## 4. Inspect The Environment

In the environment workspace, confirm that:

- services and ports are available;
- pages, APIs, identities, and data match the scenario;
- the environment version records the design;
- behavior observation and detection are healthy.

Access the environment from an isolated test network and perform expected interactions such as authentication attempts, path discovery, command execution, or file activity.

## 5. Review The Incident

When V3il correlates the activity into a ThreatIncident, open the Incident workspace and review:

- involved environments and observation window;
- behavior and detection timeline;
- active investigation tasks and owners;
- recorded evidence and analysis;
- Agent work and audit history.

If behavior enters the wrong Incident or no Incident, review detection policy, source relationships, and the observation window.

## 6. Observe Agent Collaboration

Review how V3il divides the investigation and how H4wk, Ph4ntom, L1ly, and J4ck contribute. Check that tasks cover the material behavior, evidence supports the analysis, and conclusions remain consistent.

Use the Incident Console to provide context, ask a focused question, or change investigation priority.

## 7. Test Adaptive Engagement

Choose a question that the environment can help answer, such as whether the attacker will pursue a certain data type or continue along a specific path.

In `manual_approval` mode, review the purpose, risk, and expected effect of Ph4ntom's change before approval. After deployment, verify that new behavior remains connected to the same investigation.

## 8. Produce A Report

Once critical tasks and analysis are complete, review intent, attack chain, indicators, profile, risk, and response guidance. Move the Incident into reporting, create the final report, and export the evidence package.

After knowledge publication, confirm that the report can be retrieved from Knowledge Base.

## 9. Run A Retrospective

For the first test, record:

- whether the environment was realistic enough;
- which signals contributed most to correlation and investigation;
- whether the Agent roles matched the team's workflow;
- which environment adaptations were useful;
- whether the report met internal delivery standards;
- whether network isolation, retention, or access controls need adjustment.
