import { Button, Select, TextArea } from "@douyinfe/semi-ui";
import {
  AlertTriangle,
  ArrowRight,
  Ban,
  Bot,
  Check,
  MessageSquareCode,
  Radio,
  RotateCcw,
  ShieldCheck,
  SquareTerminal,
  Wrench,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AGENT_CONSOLE_PATH, agentSessionPath } from "../../app/routePaths";
import {
  getAgentSession,
  listAgentSessions,
  listAgentToolInvocationRecoveries,
  listSandboxAsyncJobRecoveries,
  resolveAgentToolInvocation,
  resolveSandboxAsyncJob,
} from "../../shared/api/agentSessions";
import { listAgents } from "../../shared/api/agents";
import { showApiError } from "../../shared/api/feedback";
import {
  AGENT_TOOL_INVOCATION_RESOLUTION,
  FIELD_CONSTRAINTS,
  PAGINATION_MAXIMUM_PAGE_SIZE,
  SANDBOX_ASYNC_JOB_RESOLUTION,
} from "../../shared/api/generated/constants";
import type {
  AgentInfo,
  AgentSessionSummary,
  AgentToolInvocation,
  ResolveAgentToolInvocationRequest,
  SandboxAsyncJobSnapshot,
} from "../../shared/api/types";
import { AsyncContent } from "../../shared/components/AsyncContent";
import { MetricStrip } from "../../shared/components/ResourcePageShell";
import { useAdminResourceHeader } from "../../shared/hooks/useAdminResourceHeader";
import { formatDateTime } from "../../shared/lib/date";
import { formatEnumLabel } from "../../shared/lib/labels";
import { useAgentSessionContext } from "../playground/AgentSessionProvider";
import { EmptyOperationalState, OperationalSection, OperationalTag } from "../operations/OperationalUi";

type AgentOperationsData = { agents: AgentInfo[]; sessions: AgentSessionSummary[]; total: number };
type RecoveryData = { tools: AgentToolInvocation[]; sandboxJobs: SandboxAsyncJobSnapshot[] };
type ToolResolution = ResolveAgentToolInvocationRequest["resolution"];
type ResolutionDraft = {
  kind: "tool";
  id: string;
  note: string;
  output: string;
  resolution: ToolResolution;
} | {
  kind: "sandbox";
  id: string;
  note: string;
};

const EMPTY_RECOVERY_DATA: RecoveryData = { tools: [], sandboxJobs: [] };

export function AgentOperationsPage() {
  const navigate = useNavigate();
  const { selectSession, syncSessionSummaries } = useAgentSessionContext();
  const [data, setData] = useState<AgentOperationsData>({ agents: [], sessions: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const [recoverySessionId, setRecoverySessionId] = useState<string | null>(null);
  const [recoveries, setRecoveries] = useState<RecoveryData>(EMPTY_RECOVERY_DATA);
  const [recoveryLoading, setRecoveryLoading] = useState(false);
  const [resolutionDraft, setResolutionDraft] = useState<ResolutionDraft | null>(null);
  const [resolving, setResolving] = useState(false);
  const loadRequestIdRef = useRef(0);
  const recoveryRequestIdRef = useRef(0);
  const resolvingRef = useRef(false);

  const load = useCallback(async () => {
    const requestId = loadRequestIdRef.current + 1;
    loadRequestIdRef.current = requestId;
    setLoading(true);
    try {
      const [agentResponse, sessionResponse] = await Promise.all([
        listAgents(),
        listAgentSessions({ page: 1, size: PAGINATION_MAXIMUM_PAGE_SIZE, include_scoped: true }),
      ]);
      const nextData = {
        agents: agentResponse.items,
        sessions: sessionResponse.items,
        total: sessionResponse.total,
      };
      if (loadRequestIdRef.current !== requestId) return;
      setData(nextData);
      setRecoverySessionId((current) => (
        current && nextData.sessions.some((session) => session.id === current)
          ? current
          : nextData.sessions.find(hasRecovery)?.id ?? null
      ));
      syncSessionSummaries(sessionResponse.items);
    } catch (error) {
      if (loadRequestIdRef.current === requestId) showApiError(error);
    } finally {
      if (loadRequestIdRef.current === requestId) setLoading(false);
    }
  }, [syncSessionSummaries]);

  const loadRecoveries = useCallback(async (sessionId: string) => {
    const requestId = recoveryRequestIdRef.current + 1;
    recoveryRequestIdRef.current = requestId;
    setRecoveryLoading(true);
    try {
      const [toolResponse, sandboxResponse] = await Promise.all([
        listAgentToolInvocationRecoveries(sessionId),
        listSandboxAsyncJobRecoveries(sessionId),
      ]);
      if (recoveryRequestIdRef.current !== requestId) return;
      setRecoveries({
        tools: toolResponse.items ?? [],
        sandboxJobs: sandboxResponse.items ?? [],
      });
    } catch (error) {
      if (recoveryRequestIdRef.current === requestId) {
        setRecoveries(EMPTY_RECOVERY_DATA);
        showApiError(error);
      }
    } finally {
      if (recoveryRequestIdRef.current === requestId) setRecoveryLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    setResolutionDraft(null);
    if (recoverySessionId) void loadRecoveries(recoverySessionId);
    else setRecoveries(EMPTY_RECOVERY_DATA);
  }, [loadRecoveries, recoverySessionId]);

  useAdminResourceHeader({
    refreshLabel: "Refresh agent operations",
    loading,
    onRefresh: load,
    extraActions: <Button icon={<MessageSquareCode size={16} />} theme="solid" type="primary" onClick={() => { selectSession(null); navigate(AGENT_CONSOLE_PATH); }}>New chat</Button>,
  });

  const metrics = useMemo(() => [
    { label: "Expert Agents", value: data.agents.length },
    { label: "Running Sessions", value: data.sessions.filter((session) => Boolean(session.active_run)).length },
    { label: "Queued Runs", value: data.sessions.reduce((total, session) => total + session.queued_run_count, 0) },
    { label: "Recovery Queue", value: data.sessions.reduce((total, session) => total + recoveryCount(session), 0) },
  ], [data]);

  const selectedRecoverySession = data.sessions.find((session) => session.id === recoverySessionId) ?? null;
  const recoveryTotal = recoveries.tools.length + recoveries.sandboxJobs.length;
  const sessionOptions = data.sessions.map((session) => ({
    label: `${session.title || "Untitled session"} (${recoveryCount(session)})`,
    value: session.id,
  }));

  const openSession = (session: AgentSessionSummary) => {
    syncSessionSummaries([session]);
    selectSession(session.id);
    navigate(agentSessionPath(session.id));
  };

  const refreshResolvedSession = useCallback(async (sessionId: string) => {
    const [summary] = await Promise.all([
      getAgentSession(sessionId),
      loadRecoveries(sessionId),
    ]);
    syncSessionSummaries([summary]);
    setData((current) => ({
      ...current,
      sessions: current.sessions.map((session) => session.id === summary.id ? summary : session),
    }));
  }, [loadRecoveries, syncSessionSummaries]);

  const submitResolution = useCallback(async () => {
    const draft = resolutionDraft;
    const sessionId = recoverySessionId;
    if (!draft || !sessionId || !draft.note.trim() || resolvingRef.current) return;
    if (
      draft.kind === "tool"
      && draft.resolution === AGENT_TOOL_INVOCATION_RESOLUTION.CONFIRM_SUCCEEDED
      && !draft.output
    ) return;
    resolvingRef.current = true;
    setResolving(true);
    try {
      if (draft.kind === "tool") {
        await resolveAgentToolInvocation(sessionId, draft.id, {
          resolution: draft.resolution,
          note: draft.note.trim(),
          output: draft.resolution === AGENT_TOOL_INVOCATION_RESOLUTION.CONFIRM_SUCCEEDED
            ? draft.output
            : undefined,
        });
      } else {
        await resolveSandboxAsyncJob(sessionId, draft.id, {
          resolution: SANDBOX_ASYNC_JOB_RESOLUTION.CONFIRM_TERMINATED,
          note: draft.note.trim(),
        });
      }
      setResolutionDraft(null);
      await refreshResolvedSession(sessionId);
    } catch (error) {
      showApiError(error);
    } finally {
      resolvingRef.current = false;
      setResolving(false);
    }
  }, [recoverySessionId, refreshResolvedSession, resolutionDraft]);

  return (
    <section className="agent-operations-page">
      <MetricStrip metrics={metrics} />
      <OperationalSection title="Defense Team" count={data.agents.length}>
        <AsyncContent loading={loading} empty={data.agents.length === 0} emptyContent={<EmptyOperationalState icon={<Bot size={26} />} label="No agents registered" />}>
          <div className="agent-operation-grid">
            {data.agents.map((agent) => {
              const sessions = data.sessions.filter((session) => (session.active_run?.agent_code ?? session.primary_agent_code) === agent.code);
              const running = sessions.filter((session) => Boolean(session.active_run)).length;
              return (
                <article key={agent.code}>
                  <span className="agent-operation-avatar"><Bot size={22} /></span>
                  <div><small>{agent.code.toUpperCase()}</small><strong>{agent.name}</strong><p>{agent.description || "Security specialist"}</p></div>
                  <footer><span><Radio size={13} /> {running} running</span><span>{sessions.length} sessions</span></footer>
                </article>
              );
            })}
          </div>
        </AsyncContent>
      </OperationalSection>
      <OperationalSection title="Session Activity" count={data.total}>
        {data.sessions.length === 0 ? <EmptyOperationalState icon={<MessageSquareCode size={24} />} label="No agent sessions" /> : (
          <div className="session-operations-table">
            <div className="session-operations-row session-operations-head"><span>Session</span><span>Agent</span><span>Context</span><span>State</span><span>Recovery</span><span>Updated</span><span /></div>
            {data.sessions.map((session) => (
              <div className="session-operations-row" key={session.id}>
                <div><strong>{session.title || "Untitled session"}</strong><small>{session.id.slice(0, 12)}</small></div>
                <code>{(session.active_run?.agent_code ?? session.primary_agent_code).toUpperCase()}</code>
                <span>{session.incident_id
                  ? `Incident ${session.incident_id}`
                  : session.environment_id
                    ? `Environment ${session.environment_id}`
                    : "Operator chat"}</span>
                <span>{session.active_run ? <OperationalTag value={session.active_run.status} /> : <span className="session-idle"><ShieldCheck size={13} /> Idle</span>}</span>
                <button className="session-recovery-count" type="button" disabled={!hasRecovery(session)} onClick={() => setRecoverySessionId(session.id)}>
                  {hasRecovery(session) ? <AlertTriangle size={13} /> : <ShieldCheck size={13} />}
                  <span>{recoveryCount(session)}</span>
                </button>
                <small>{formatDateTime(session.updated_at)}</small>
                <Button icon={<ArrowRight size={14} />} theme="borderless" aria-label={`Open ${session.title || "session"}`} onClick={() => openSession(session)} />
              </div>
            ))}
          </div>
        )}
      </OperationalSection>
      <OperationalSection
        title="Recovery Queue"
        count={recoveryTotal}
        actions={(
          <Select
            className="agent-recovery-session-select"
            value={recoverySessionId ?? undefined}
            optionList={sessionOptions}
            placeholder="Select session"
            onChange={(value) => setRecoverySessionId(typeof value === "string" ? value : null)}
          />
        )}
      >
        <AsyncContent
          loading={recoveryLoading}
          empty={!selectedRecoverySession || recoveryTotal === 0}
          emptyContent={<EmptyOperationalState icon={<ShieldCheck size={24} />} label="No recovery decisions pending" />}
        >
          <div className="agent-recovery-list">
            {recoveries.tools.map((invocation) => (
              <ToolRecoveryRow
                key={invocation.id}
                invocation={invocation}
                draft={resolutionDraft?.kind === "tool" && resolutionDraft.id === invocation.id ? resolutionDraft : null}
                disabled={!selectedRecoverySession?.capabilities.can_resolve_tool_invocations || resolving}
                resolving={resolving}
                onDraft={setResolutionDraft}
                onSubmit={() => void submitResolution()}
              />
            ))}
            {recoveries.sandboxJobs.map((job) => (
              <SandboxRecoveryRow
                key={job.run_id}
                job={job}
                draft={resolutionDraft?.kind === "sandbox" && resolutionDraft.id === job.run_id ? resolutionDraft : null}
                disabled={!selectedRecoverySession?.capabilities.can_resolve_sandbox_jobs || resolving}
                resolving={resolving}
                onDraft={setResolutionDraft}
                onSubmit={() => void submitResolution()}
              />
            ))}
          </div>
        </AsyncContent>
      </OperationalSection>
    </section>
  );
}

function ToolRecoveryRow({ invocation, draft, disabled, resolving, onDraft, onSubmit }: {
  invocation: AgentToolInvocation;
  draft: Extract<ResolutionDraft, { kind: "tool" }> | null;
  disabled: boolean;
  resolving: boolean;
  onDraft: (draft: ResolutionDraft | null) => void;
  onSubmit: () => void;
}) {
  const valid = Boolean(
    draft?.note.trim()
    && (
      draft.resolution !== AGENT_TOOL_INVOCATION_RESOLUTION.CONFIRM_SUCCEEDED
      || draft.output
    ),
  );
  return (
    <article className="agent-recovery-row">
      <header>
        <span className="agent-recovery-icon"><Wrench size={16} /></span>
        <div><strong>{invocation.tool_name}</strong><small>Call {invocation.call_id} · Run {invocation.run_id.slice(0, 12)}</small></div>
        <OperationalTag value={invocation.status} />
        <small>{formatDateTime(invocation.started_at)}</small>
        <Button icon={<RotateCcw size={14} />} disabled={disabled} onClick={() => onDraft(draft ? null : newToolDraft(invocation.id))}>{draft ? "Close" : "Resolve"}</Button>
      </header>
      <div className="agent-recovery-details">
        <RecoveryFact label="Attempt" value={invocation.attempt_id.slice(0, 12)} />
        <RecoveryFact label="Context" value={invocation.context_id.slice(0, 12)} />
        <pre>{formatStructuredText(invocation.arguments)}</pre>
        {invocation.error_message ? <p className="agent-recovery-error">{invocation.error_message}</p> : null}
      </div>
      {draft ? (
        <div className="agent-recovery-resolution">
          <div className="agent-recovery-mode" role="group" aria-label="Tool invocation resolution">
            <Button
              icon={<Check size={14} />}
              theme={draft.resolution === AGENT_TOOL_INVOCATION_RESOLUTION.CONFIRM_SUCCEEDED ? "solid" : "light"}
              type={draft.resolution === AGENT_TOOL_INVOCATION_RESOLUTION.CONFIRM_SUCCEEDED ? "primary" : "tertiary"}
              onClick={() => onDraft({ ...draft, resolution: AGENT_TOOL_INVOCATION_RESOLUTION.CONFIRM_SUCCEEDED })}
            >Confirm succeeded</Button>
            <Button
              icon={<Ban size={14} />}
              theme={draft.resolution === AGENT_TOOL_INVOCATION_RESOLUTION.CONFIRM_NOT_APPLIED ? "solid" : "light"}
              type={draft.resolution === AGENT_TOOL_INVOCATION_RESOLUTION.CONFIRM_NOT_APPLIED ? "primary" : "tertiary"}
              onClick={() => onDraft({ ...draft, resolution: AGENT_TOOL_INVOCATION_RESOLUTION.CONFIRM_NOT_APPLIED, output: "" })}
            >Confirm not applied</Button>
          </div>
          <div className="agent-recovery-fields">
            {draft.resolution === AGENT_TOOL_INVOCATION_RESOLUTION.CONFIRM_SUCCEEDED ? (
              <label><span>Observed output</span><TextArea value={draft.output} rows={3} onChange={(output) => onDraft({ ...draft, output })} /></label>
            ) : null}
            <label><span>Resolution note</span><TextArea value={draft.note} rows={3} maxLength={FIELD_CONSTRAINTS.ResolveAgentToolInvocationRequest.note.maxLength} onChange={(note) => onDraft({ ...draft, note })} /></label>
          </div>
          <Button icon={<Check size={14} />} theme="solid" type="primary" disabled={!valid} loading={resolving} onClick={onSubmit}>Apply resolution</Button>
        </div>
      ) : null}
    </article>
  );
}

function SandboxRecoveryRow({ job, draft, disabled, resolving, onDraft, onSubmit }: {
  job: SandboxAsyncJobSnapshot;
  draft: Extract<ResolutionDraft, { kind: "sandbox" }> | null;
  disabled: boolean;
  resolving: boolean;
  onDraft: (draft: ResolutionDraft | null) => void;
  onSubmit: () => void;
}) {
  return (
    <article className="agent-recovery-row">
      <header>
        <span className="agent-recovery-icon"><SquareTerminal size={16} /></span>
        <div><strong>Sandbox command</strong><small>Container {job.sandbox_container_id} · Generation {job.sandbox_container_generation}</small></div>
        <OperationalTag value={job.status} />
        <small>{formatDateTime(job.started_at ?? job.created_at)}</small>
        <Button icon={<RotateCcw size={14} />} disabled={disabled} onClick={() => onDraft(draft ? null : { kind: "sandbox", id: job.run_id, note: "" })}>{draft ? "Close" : "Resolve"}</Button>
      </header>
      <div className="agent-recovery-details">
        <RecoveryFact label="Output file" value={job.output_file || "Not recorded"} />
        <RecoveryFact label="Attempt" value={job.attempt_id.slice(0, 12)} />
        <pre>{job.command}</pre>
        {job.error ? <p className="agent-recovery-error">{job.error}</p> : null}
      </div>
      {draft ? (
        <div className="agent-recovery-resolution agent-recovery-resolution-single">
          <div className="agent-recovery-fields">
            <label><span>Resolution note</span><TextArea value={draft.note} rows={3} maxLength={FIELD_CONSTRAINTS.ResolveSandboxAsyncJobRequest.note.maxLength} onChange={(note) => onDraft({ ...draft, note })} /></label>
          </div>
          <Button icon={<Check size={14} />} theme="solid" type="primary" disabled={!draft.note.trim()} loading={resolving} onClick={onSubmit}>Confirm terminated</Button>
        </div>
      ) : null}
    </article>
  );
}

function RecoveryFact({ label, value }: { label: string; value: string }) {
  return <span><small>{label}</small><code>{value}</code></span>;
}

function newToolDraft(id: string): Extract<ResolutionDraft, { kind: "tool" }> {
  return {
    kind: "tool",
    id,
    note: "",
    output: "",
    resolution: AGENT_TOOL_INVOCATION_RESOLUTION.CONFIRM_SUCCEEDED,
  };
}

function recoveryCount(session: AgentSessionSummary) {
  return session.tool_recovery_count + session.sandbox_recovery_count;
}

function hasRecovery(session: AgentSessionSummary) {
  return recoveryCount(session) > 0;
}

function formatStructuredText(value: string) {
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value || formatEnumLabel("not_recorded");
  }
}
