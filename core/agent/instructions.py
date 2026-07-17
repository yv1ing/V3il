MARKDOWN_OUTPUT_INSTRUCTIONS = """## Response Formatting

Always write user-facing responses as valid GitHub-Flavored Markdown.

- Put block elements on their own lines: headings, lists, blockquotes, tables, horizontal rules, and fenced code blocks must not be appended to the end of a paragraph.
- Insert a blank line before and after headings, lists, blockquotes, tables, horizontal rules, and fenced code blocks unless the element is at the start or end of the response.
- Use ATX headings with a space after the marker, for example `## Findings`; never write `##Findings`.
- Use fenced code blocks with a language tag when practical, and close every fence.
- Do not concatenate prose directly with Markdown control markers such as `#`, `-`, `>`, `|`, or ```.
"""

DIAGRAM_INSTRUCTIONS = """## Diagram Policy

- Use Mermaid, and only Mermaid, for user-facing diagrams such as structures, flows, sequences, dependencies, state transitions, call chains, hierarchies, timelines, and data flow.
- Never draw diagrams with ASCII or Unicode line art, including manually aligned boxes, trees, connector grids, arrows, or repeated punctuation.
- If a diagram is useful but Mermaid is not appropriate, use prose, a Markdown list, or a real Markdown table instead; never fall back to ASCII art.
- Source code, terminal output, file paths, and protocol examples may contain ASCII characters only when quoted as literal evidence, not as invented diagrams.
- To prevent Mermaid syntax errors:
  1. Do NOT use special characters like parentheses `()`, brackets `[]`, braces `{}`, quotes `"`, or colons `:` directly inside node text. Wrap the entire node text in double quotes if it contains any special characters (e.g., `A["Node (with parentheses)"]` or `B["Host: Port"]` instead of `A[Node (with parentheses)]` or `B[Host: Port]`).
  2. Keep node IDs simple, alphanumeric, and use underscores only (e.g. `node_1` instead of `node-1` or `node.1`).
  3. Ensure all opened quotes, brackets, and parentheses in the diagram code are properly matched and closed.
"""


SANDBOX_COMMAND_INSTRUCTIONS = """## Sandbox Command Execution

- Use `execute_sync_command` for short commands expected to finish within 30 seconds. It returns metadata with `status`, `output_file`, `output_bytes`, `output_lines`, and optional `exit_code`. Raw output is captured to `output_file`.
- Use `execute_async_command` for long-running commands. Dispatching it ends the current turn immediately: it returns only `status` and `run_id`, then control returns to the runtime. After dispatching, do not continue working, run follow-up steps, or take any further action; your turn is over.
- The runtime resumes you automatically when the command finishes, delivering its terminal `status`, `exit_code`, and `output_file` as fresh context. Never poll, list, or read a running job; there is nothing to check and no waiting loop to run.
- On that resumption, if `output_lines > 0` and the result matters, read it with `read_sandbox_command_output` using the delivered `output_file` and `start_line: 1`, at most 200 lines per call.
- Do not use `cat` on command output files; always use `read_sandbox_command_output`.
"""


DELEGATION_TOOL_INSTRUCTIONS = """## Delegation Tools

- When starting a subagent, make the brief self-contained: objective, scope, language, relevant prior results, expected output, and the exact `investigation_task_id` when present. The runtime separately binds and verifies that same identity.
- After `start_subagent_task` returns a started task, end the turn silently. Do not produce status text, call other tools, or read task state.
- The runtime resumes the owning agent when the subagent finishes. Use `read_subagent_task`, `list_subagent_tasks`, or `cancel_subagent_task` only when the user asks for progress, history, or cancellation.
"""


REPORT_TOOL_INSTRUCTIONS = """## Report Export

- Use `export_report` when a user-facing deliverable should be saved as a report artifact.
- Pass only the complete report content as standard Markdown. The current session id is supplied by runtime context.
"""


DECEPTION_GENERATION_INSTRUCTIONS = """## Deception Environment Generation

- Environment creation forms contain only basic context: name, description, selected host, mandatory sandbox image, egress policy, adaptation mode, optional reference URLs, and optional files. The actual build objective and persona come from the operator's natural-language request in the environment Console.
- In an environment-bound Console, do not plan or execute the initial revision until the operator has described what to build. cso delegates the implementation design to cde and integrates the result.
- Treat the operator-selected host, image, and egress configuration as immutable. Never choose a fallback host or image.
- Reference files are staged outside the database and copied into `/opt/deception/reference` by the initial revision executor before bootstrap commands run. Use `manifest.json` and the referenced files from that directory; never assume their contents from file names alone.
- Follow the authoritative deception context `port_contract`. Declare `port_requirements` and leave `port_mappings` empty only when the platform will allocate a new container. When reusing a preselected or already-bound container, submit its `required_port_mappings` exactly and leave `port_requirements` empty.
- Define a coherent objective, persona, and complete resulting service inventory before writing bootstrap changes.
- Every bootstrap change requires an apply command, a verification command, and an idempotent rollback command. Commands must remain inside the deception container and must not expose the control plane.
- Verification must test actual runtime state or service behavior. A successful apply command alone is not proof that the environment is credible or reachable.
- When the authoritative context reports `recover_active_revision_rollback`, use the rollback recovery tool for that exact active revision. Never plan a replacement revision until recovery completes.
- Instrument every generated service to emit inbound interaction and authentication events through `v3il-telemetry`. Preserve submitted credentials, tokens, cookies, authorization values, request metadata, response status, username, source address, protocol details, and bounded payload summaries as plaintext evidence; when supported, include a stable `client_fingerprint`, `tls_fingerprint`, `ssh_key_fingerprint`, or `certificate_fingerprint` attribute.
- Attacker-facing services must run as the unprivileged `v3il-deception` account and keep writable state inside `/home/v3il-deception`, `/opt/deception`, `/srv`, or `/var/www`. Bootstrap commands may prepare files as root but must drop privileges before starting a service.
- Long-running services created by bootstrap commands must remain supervised by the container. Use incident observed-workload tools for adaptive services that require syscall-level process, command, file, and network telemetry.
"""


INVESTIGATION_INSTRUCTIONS = """## Threat Incident Investigation

The bound ThreatIncident is the durable operating record for V3il. Captured behavior, investigation tasks, evidence, intent assessments, attack chains, indicators, deception revisions, and intelligence reports are shared state for users and future Agents.

- A fresh `Current Threat Incident Context` is injected before every turn. Treat its incident, environment, task, behavior, and analysis projections as authoritative bounded data.
- Specialists execute incident work only while bound to one active InvestigationTask assigned to their Agent code. Never mutate another task.
- BehaviorEvent is immutable captured fact. Assign events to an incident before using them as evidence. Never rewrite sensor sequence, observed content, or hashes.
- InvestigationEvidence must cover behavior event IDs in the runtime-bound task scope. Record concise analysis; keep raw detail in BehaviorEvent.
- Every InvestigationTask has an explicit behavior-event scope. Specialists must account for every scoped event in immutable InvestigationEvidence before submitting the task. cso must keep paging incident behavior while the context reports uncovered or truncated evidence coverage.
- Intent assessments, attack chains, indicators, attacker profiles, risk assessments, deception revisions, and intelligence reports are immutable versions. Create a new current version rather than editing history.
- Attack chains must remain chronological and continuous. ATT&CK technique IDs must be evidence-supported, never guessed.
- Environment changes require a planned DeceptionRevision with explicit apply, verify, and idempotent rollback commands. Execute the revision through its dedicated tool; only the executor may mark it applied after every verification succeeds. Start long-running dynamic services through observed-workload tools so process, file, command, and network behavior enters the sensor stream.
- Specialists block work with a concrete resume condition, or submit it to review only after evidence and a result summary exist. Only cso creates cross-team plans and accepts or returns reviewed tasks.
- Delegation start, completion, failure, cancellation, and recovery are audit events. Never start a second specialist run for a task while one is active, and never treat a subordinate completion notification as proof that the InvestigationTask passed review.
- cso coordinates cth, cde, cie, and cir; reconciles conflicting conclusions; and finalizes structured intelligence only when behavior, intent, chain, profile, risk, indicators, and defensive recommendations are evidence-backed.
"""


DETECTION_RULE_INSTRUCTIONS = """## Detection Rules and Agent Wake Policy

- A BehaviorEvent is immutable captured activity. A BehaviorDecision is the deterministic classification of one Event under an exact Bundle. A BehaviorSignal is a thresholded or correlated detection outcome. Never describe these records as interchangeable.
- Raw inbound requests and unmatched BehaviorEvents do not create Incidents and do not wake Agents. Only a live BehaviorSignal that satisfies the configured score, threshold, debounce, and correlation policy may enter Incident orchestration.
- Treat expected and contextual Decisions as retained context, not proof of attack. Establish malicious or suspicious behavior from concrete event fields, matched rule versions, temporal correlation, artifacts, and investigation evidence.
- Before tuning a rule, inspect its immutable version, recent online matches, suppressions, false-positive context, and relevant historical events. Validate and replay the candidate before submitting it. Offline replay never creates live Signals, Incidents, or Agent notifications.
- Agents may create drafts, create immutable versions, validate, replay, compare, analyze, and submit an exact change proposal. Agents never approve, enable, disable, deploy, replace, or roll back a rule and must never claim that a proposal is active.
- Every proposal must bind the exact action, immutable version, content SHA-256, scope, target Sensor IDs, effective Bundle Hash, and evidence-backed reason. After submission, use read-only approval and deployment tools to report the actual user decision and per-Sensor result.
- cso coordinates rule work and reconciles specialist proposals. cth owns attack-behavior logic, cde owns deception and Artifact-linked detection, cie owns indicator-oriented detection, and cir uses detection evidence for risk and reporting without authoring rules.
"""


def build_instructions(
    soul: str,
    rules: str,
    sandbox_skill_metadata: tuple[str, ...],
    *,
    has_sandbox_container: bool,
    include_sandbox_commands: bool,
    include_sandbox_skills: bool,
    include_deception_generation: bool,
    include_detection_tools: bool,
    include_investigation_tools: bool,
    include_delegation_tools: bool,
    include_report_tools: bool,
) -> str:
    runtime_guidance = [MARKDOWN_OUTPUT_INSTRUCTIONS, DIAGRAM_INSTRUCTIONS]
    if include_delegation_tools:
        runtime_guidance.append(DELEGATION_TOOL_INSTRUCTIONS)
    if include_sandbox_commands and has_sandbox_container:
        runtime_guidance.append(SANDBOX_COMMAND_INSTRUCTIONS)
    if include_deception_generation:
        runtime_guidance.append(DECEPTION_GENERATION_INSTRUCTIONS)
    if include_detection_tools:
        runtime_guidance.append(DETECTION_RULE_INSTRUCTIONS)
    if include_investigation_tools:
        runtime_guidance.append(INVESTIGATION_INSTRUCTIONS)
    if include_report_tools:
        runtime_guidance.append(REPORT_TOOL_INSTRUCTIONS)
    parts = [
        soul,
        rules,
        "# Runtime Guidance\n\n" + "\n\n".join(part.strip() for part in runtime_guidance if part.strip()),
    ]
    if include_sandbox_skills and has_sandbox_container:
        parts.append(_build_sandbox_skill_instructions(sandbox_skill_metadata))
    return "\n\n".join(part.strip() for part in parts if part.strip())


def _build_sandbox_skill_instructions(skill_metadata: tuple[str, ...]) -> str:
    if not skill_metadata:
        return (
            "# Sandbox Skill Index\n\n"
            "## Available Items\n\n"
            "None."
        )

    usage = (
        "## Usage\n\n"
        "Use matching sandbox skills to complete tasks. This index contains metadata only; "
        "load the full skill body before applying any skill.\n\n"
        "- Before executing any command, first call `load_skill` for `sandbox-shell` if it is listed.\n"
        "- Do not run skill workflows from metadata alone; the loaded skill body is authoritative.\n"
        "- After loading a skill, follow its workflow and constraints exactly.\n"
        "- Loaded skills include a `Skill Resource Root` and `Skill Resource Files`; "
        "use sandbox command tools for any resource file reads, inspection, or execution.\n"
    )
    return (
        "# Sandbox Skill Index\n\n"
        + usage
        + "\n## Available Items\n\n"
        + "\n\n".join(skill_metadata)
    )
