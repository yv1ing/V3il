---
name: deception-observability
description: Build and verify attacker-facing deception services whose interactions remain visible to the V3il behavior sensor and evidence pipeline.
---

# Deception Observability

Use this skill when creating or adapting a deception service in the selected container.

## Required Properties

- Keep service files under `/opt/deception`, `/srv`, or `/var/www` so filesystem observation covers them.
- Run long-lived adaptive services through `start_observed_deception_workload`; its `strace` boundary records descendant process, command, file, and network system calls.
- Emit application-level interactions through `v3il-telemetry` over the protected Unix socket. Kernel observations establish activity; service telemetry supplies protocol meaning.
- Emit attacker-supplied request bodies, passwords, tokens, cookies, authorization headers, session identifiers, keys, and other payload material when they are part of the interaction. Preserve the accepted value exactly within the telemetry field limits.
- Include source address, source port, destination address, destination port, protocol, service name, action, outcome, and a bounded summary when they are available.
- Use stable non-secret fingerprints such as TLS, SSH public-key, or client-behavior fingerprints when the protocol supports them.
- Keep apply, verify, and rollback commands deterministic. Verification must exercise the real listening service or resulting artifact.

## Telemetry Submission

Submit one JSON event as the only argument to `v3il-telemetry`:

```sh
v3il-telemetry '{"category":"authentication","action":"login_attempt","direction":"inbound","outcome":"failure","source_ip":"192.0.2.10","source_port":51324,"destination_port":2222,"protocol":"ssh","service_name":"decoy-ssh","username":"operator","summary":"Password authentication rejected"}'
```

Use category-specific detail:

- `network`: at least an address, port, or protocol.
- `process`: process ID or process name.
- `command`: bounded command line with the observed arguments intact.
- `file`: concrete path.
- `authentication` and `service`: service name.

## Workflow

1. Tie the revision to its triggering BehaviorEvent and state the attacker behavior being answered.
2. Write service files only into observed roots and keep the protected sensor paths untouched.
3. Start adaptive long-running work through the observed-workload tool.
4. Verify actual reachability and response behavior with the installed `curl`, `openssl`, or `nc` utility appropriate to the protocol.
5. Confirm the service emits structured interaction telemetry and that the revision rollback stops the service and removes only revision-owned state.
6. Record the revision outcome and supporting behavior evidence before submitting the InvestigationTask for review.
