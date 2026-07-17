---
name: live-forensics
description: Collect bounded, reproducible host, process, file, and artifact facts inside a V3il deception container using only the installed blue-team utilities.
---

# Live Forensics

Use this skill when an investigation task requires direct validation of runtime state or an artifact in the selected deception container.

## Evidence Discipline

- Work only inside the selected container and the InvestigationTask behavior-event scope.
- Treat platform BehaviorEvents as the immutable source record. Do not edit `/var/lib/v3il`, `/run/v3il`, sensor journals, trace files, or control-plane state.
- Prefer read-only inspection. State every path, process ID, filter, and time assumption needed to reproduce a finding.
- Bound recursive searches by a known root and exclude virtual or protected filesystems.
- Preserve relevant attacker-supplied credentials, tokens, cookies, keys, payloads, and configuration values exactly when they establish behavior or intent. Keep platform control tokens and sensor-owned files unchanged so the evidence source remains verifiable.
- Convert a relevant finding into InvestigationEvidence by citing the BehaviorEvent IDs that caused and support the inspection. Command output alone is not evidence-chain provenance.

## Installed Utilities

- `find`, `stat`, `sha256sum`, `readlink`, and `file` for filesystem metadata and artifact identity.
- `rg` for bounded text and configuration searches.
- `jq` for structured JSON inspection.
- `openssl` for certificate, public-key, digest, and TLS metadata.
- `tar` and `unzip` for listing archives before selectively reading an entry.
- `/proc` for process identity, ancestry, command line, executable path, descriptors, and network namespace facts.

Do not assume tools absent from this list are installed. Do not install packages during an investigation.

## Workflow

1. Read the assigned BehaviorEvent scope and identify the exact fact that needs validation.
2. Inspect metadata before content: `stat`, `file`, `readlink`, and `sha256sum` establish identity and the exact object being examined.
3. Use `rg` or `jq` only against the smallest relevant files or directories.
4. For a process, inspect `/proc/<pid>/status`, `/proc/<pid>/cmdline`, `/proc/<pid>/exe`, `/proc/<pid>/fd`, and its parent relationship. A vanished PID is a finding, not permission to infer its state.
5. Report the command, bounded raw result, affected artifact or process, timestamp context, and supporting BehaviorEvent IDs. Do not replace captured values with masks or placeholders.
6. Record unexplained sensor gaps or inaccessible evidence as an investigation blocker or sensor-coverage finding.

## Output

Return concise facts and clearly separate observation from inference. Include hashes and identifiers where they improve reproducibility, but keep bulky raw output in sandbox command output files and page it through the provided output reader.
