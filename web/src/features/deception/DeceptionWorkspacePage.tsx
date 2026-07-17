import { Button, Input, TabPane, Tabs, TextArea } from "@douyinfe/semi-ui";
import {
  ArrowLeft,
  Box,
  Check,
  CirclePause,
  ExternalLink,
  FileArchive,
  FileClock,
  MessageSquareCode,
  Network,
  Play,
  RadioTower,
  RefreshCcw,
  RotateCcw,
  ShieldOff,
  Workflow,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { listAgentSessions } from "../../shared/api/agentSessions";
import {
  approveDeceptionRevision,
  executeDeceptionRevision,
  getDeceptionEnvironment,
  getDeceptionReferences,
  listObservedWorkloads,
  pauseDeceptionEnvironment,
  queryBehaviorEvents,
  queryDeceptionRevisions,
  recoverDeceptionRevision,
  rejectDeceptionRevision,
  resumeDeceptionEnvironment,
  retireDeceptionEnvironment,
  stopObservedWorkload,
} from "../../shared/api/deceptionEnvironments";
import { showApiError, showApiSuccess } from "../../shared/api/feedback";
import {
  DECEPTION_ENVIRONMENT_STATUS,
  DECEPTION_REVISION_STATUS,
  OBSERVED_WORKLOAD_STATUS,
} from "../../shared/api/generated/constants";
import { collectAllPages } from "../../shared/api/pagination";
import type {
  BehaviorEvent,
  AgentSessionSummary,
  CommonResponsePayload,
  DeceptionEnvironment,
  DeceptionReferenceBundle,
  DeceptionRevision,
  ObservedWorkload,
} from "../../shared/api/types";
import { AsyncContent } from "../../shared/components/AsyncContent";
import { BehaviorEvidenceDetails } from "../../shared/components/BehaviorEvidenceDetails";
import { FormField } from "../../shared/components/FormField";
import { ResourceModal } from "../../shared/components/ResourceModal";
import { TabLabel } from "../../shared/components/TabLabel";
import { formatDateTime } from "../../shared/lib/date";
import { formatEnumLabel } from "../../shared/lib/labels";
import {
  EmptyOperationalState,
  OperationalSection,
  OperationalTag,
} from "../operations/OperationalUi";
import { useAgentSessionContext } from "../playground/AgentSessionProvider";

type WorkspaceData = {
  environment: DeceptionEnvironment;
  revisions: DeceptionRevision[];
  events: BehaviorEvent[];
  workloads: ObservedWorkload[];
  references: DeceptionReferenceBundle;
};

type DecisionState = { revision: DeceptionRevision; approve: boolean } | null;

export function DeceptionWorkspacePage() {
  const navigate = useNavigate();
  const { refreshSessions, selectSession } = useAgentSessionContext();
  const { environmentId } = useParams();
  const id = Number(environmentId);
  const validId = Number.isInteger(id) && id > 0 ? id : 0;
  const [data, setData] = useState<WorkspaceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [action, setAction] = useState<string | null>(null);
  const [decision, setDecision] = useState<DecisionState>(null);

  const load = useCallback(async () => {
    if (!validId) return;
    setLoading(true);
    try {
      const [environmentResponse, referenceResponse, revisions, events, workloadResponse] = await Promise.all([
        getDeceptionEnvironment(validId),
        getDeceptionReferences(validId),
        collectAllPages<DeceptionRevision>((page) => queryDeceptionRevisions(validId, { page, size: 100 })),
        collectAllPages<BehaviorEvent>((page) => queryBehaviorEvents(validId, { page, size: 100, keyword: "" })),
        listObservedWorkloads(validId),
      ]);
      if (!environmentResponse.data) {
        setData(null);
        return;
      }
      setData({
        environment: environmentResponse.data,
        references: referenceResponse.data ?? {
          environment_id: validId,
          reference_urls: environmentResponse.data.reference_urls,
          files: [],
        },
        revisions,
        events,
        workloads: workloadResponse.data?.items ?? [],
      });
    } catch (error) {
      showApiError(error);
    } finally {
      setLoading(false);
    }
  }, [validId]);

  useEffect(() => {
    void load();
  }, [load]);

  const openConsoleSession = useCallback(async (sessionId: string) => {
    await refreshSessions();
    selectSession(sessionId);
    navigate("/playground", { state: { sessionId } });
  }, [navigate, refreshSessions, selectSession]);

  const openEnvironmentConsole = useCallback(async () => {
    if (!validId || action) return;
    setAction("console");
    try {
      const sessions = await collectAllPages<AgentSessionSummary>(
        (page) => listAgentSessions({ page, size: 100 }),
      );
      const session = sessions.find((item) => item.environment_id === validId);
      if (!session) throw new Error("Environment Console session was not found");
      await openConsoleSession(session.session_id);
    } catch (error) {
      showApiError(error);
      setAction(null);
    }
  }, [action, openConsoleSession, validId]);

  const run = async (key: string, operation: () => Promise<CommonResponsePayload>) => {
    if (action) return;
    setAction(key);
    try {
      const response = await operation();
      showApiSuccess(response);
    } catch (error) {
      showApiError(error);
    } finally {
      await load();
      setAction(null);
    }
  };

  const environmentActions = useMemo(() => {
    if (!data) return [];
    const environment = data.environment;
    const activeRevisionId = environment.active_revision_id;
    if (environment.status === DECEPTION_ENVIRONMENT_STATUS.DRAFT) {
      return [
        { key: "retire", label: "Retire", icon: <ShieldOff size={15} />, operation: () => retireDeceptionEnvironment(environment.id) },
      ];
    }
    if (environment.status === DECEPTION_ENVIRONMENT_STATUS.ACTIVE) {
      return [
        { key: "pause", label: "Pause", icon: <CirclePause size={15} />, operation: () => pauseDeceptionEnvironment(environment.id) },
        { key: "retire", label: "Retire", icon: <ShieldOff size={15} />, operation: () => retireDeceptionEnvironment(environment.id) },
      ];
    }
    if (environment.status === DECEPTION_ENVIRONMENT_STATUS.PAUSED) {
      return [
        { key: "resume", label: "Resume", icon: <Play size={15} />, operation: () => resumeDeceptionEnvironment(environment.id) },
        { key: "retire", label: "Retire", icon: <ShieldOff size={15} />, operation: () => retireDeceptionEnvironment(environment.id) },
      ];
    }
    if (
      environment.status === DECEPTION_ENVIRONMENT_STATUS.RECOVERY_REQUIRED
      && activeRevisionId !== null
    ) {
      return [
        {
          key: "recover",
          label: "Retry recovery",
          icon: <RotateCcw size={15} />,
          operation: () => recoverDeceptionRevision(environment.id, activeRevisionId),
        },
      ];
    }
    return [];
  }, [data]);

  const appliedRevision = data?.revisions.find(
    (revision) => revision.id === data.environment.applied_revision_id,
  );
  const activeRevision = data?.revisions.find(
    (revision) => revision.id === data.environment.active_revision_id,
  );

  if (!validId) {
    return <EmptyOperationalState icon={<Box size={28} />} label="Invalid environment identifier" />;
  }

  return (
    <section className="workspace-page deception-workspace">
      <button type="button" className="workspace-back" onClick={() => navigate("/deception-environments")}>
        <ArrowLeft size={15} /> Environment list
      </button>
      <AsyncContent loading={loading} empty={!data} emptyContent={<EmptyOperationalState icon={<Box size={28} />} label="Environment not found" />}>
        {data ? (
          <>
            <header className="workspace-heading">
              <div className="workspace-title-block">
                <span className="workspace-id">ENV-{String(data.environment.id).padStart(5, "0")}</span>
                <h2>{data.environment.name}</h2>
                <p>{data.environment.description || "Use the environment Console to describe what the Agent should build."}</p>
              </div>
              <div className="workspace-heading-state">
                <OperationalTag value={data.environment.status} />
                <Button
                  icon={<MessageSquareCode size={15} />}
                  loading={action === "console"}
                  disabled={Boolean(action && action !== "console")}
                  onClick={() => void openEnvironmentConsole()}
                >Open Console</Button>
                <Button icon={<RefreshCcw size={15} />} loading={loading} onClick={() => void load()}>Refresh</Button>
                {environmentActions.map((item) => (
                  <Button
                    key={item.key}
                    icon={item.icon}
                    loading={action === item.key}
                    disabled={Boolean(action)}
                    onClick={() => void run(item.key, item.operation)}
                  >
                    {item.label}
                  </Button>
                ))}
              </div>
            </header>

            <div className="workspace-facts">
              <Fact label="Host" value={`#${data.environment.host_id}`} />
              <Fact label="Image" value={`#${data.environment.image_id}`} />
              <Fact label="Container" value={data.environment.sandbox_container_id ? `#${data.environment.sandbox_container_id}` : "Pending"} />
              <Fact label="Egress" value={formatEnumLabel(data.environment.egress_mode)} />
              <Fact label="Baseline" value={appliedRevision ? `r${appliedRevision.version}` : "None"} />
              <Fact label="Active attempt" value={activeRevision ? `r${activeRevision.version}` : "None"} />
              <Fact label="Adaptation" value={formatEnumLabel(data.environment.adaptation_mode)} />
            </div>

            <Tabs type="line" className="workspace-tabs">
              <TabPane itemKey="overview" tab={<TabLabel icon={<Network size={15} />} text="Overview" />}>
                <div className="workspace-tab-stack">
                  <div className="workspace-split">
                    <OperationalSection title="Description"><LongText value={data.environment.description} /></OperationalSection>
                    <OperationalSection title="Persona"><LongText value={data.environment.persona} /></OperationalSection>
                  </div>
                  <OperationalSection title="Reference site URLs" count={data.references.reference_urls?.length ?? 0}>
                    {data.references.reference_urls?.length ? (
                      <div className="compact-records">
                        {data.references.reference_urls.map((url) => (
                          <article key={url}>
                            <header><strong>{url}</strong><ExternalLink size={14} /></header>
                            <a href={url} target="_blank" rel="noreferrer">Open reference site</a>
                          </article>
                        ))}
                      </div>
                    ) : <EmptyOperationalState icon={<ExternalLink size={24} />} label="No reference sites supplied" />}
                  </OperationalSection>
                  <OperationalSection title="Reference files" count={data.references.files?.length ?? 0}>
                    {data.references.files?.length ? (
                      <div className="compact-records">
                        {data.references.files.map((file) => (
                          <article key={file.sha256}>
                            <header><strong>{file.filename}</strong><OperationalTag value={file.state} /></header>
                            <p><code>{file.container_path}</code></p>
                            <small>{file.media_type} · {formatFileSize(file.size)} · SHA-256 {file.sha256}</small>
                          </article>
                        ))}
                      </div>
                    ) : <EmptyOperationalState icon={<FileArchive size={24} />} label="No reference files supplied" />}
                  </OperationalSection>
                  <OperationalSection title="Deployed services" count={data.environment.services.length}>
                    {data.environment.services.length ? (
                      <div className="compact-records">
                        {data.environment.services.map((service) => (
                          <article key={`${service.name}:${service.port}`}>
                            <header><strong>{service.name}</strong><OperationalTag value={service.protocol} /></header>
                            <p>{service.persona || "No service-specific persona."}</p>
                            <small>{service.exposed ? "Exposed" : "Internal"} · container port {service.port}</small>
                          </article>
                        ))}
                      </div>
                    ) : <EmptyOperationalState icon={<Network size={24} />} label="Agent has not deployed services yet" />}
                  </OperationalSection>
                  {data.environment.last_error ? <OperationalSection title="Last error"><pre className="workspace-code-block">{data.environment.last_error}</pre></OperationalSection> : null}
                </div>
              </TabPane>

              <TabPane itemKey="revisions" tab={<TabLabel icon={<Workflow size={15} />} text={`Revisions (${data.revisions.length})`} />}>
                <RevisionList
                  revisions={data.revisions}
                  action={action}
                  onDecision={setDecision}
                  onExecute={(revision) => void run(`execute:${revision.id}`, () => executeDeceptionRevision(validId, revision.id))}
                  onRecover={(revision) => void run(`recover:${revision.id}`, () => recoverDeceptionRevision(validId, revision.id))}
                />
              </TabPane>

              <TabPane itemKey="behavior" tab={<TabLabel icon={<RadioTower size={15} />} text={`Behavior (${data.events.length})`} />}>
                <BehaviorList events={data.events} />
              </TabPane>

              <TabPane itemKey="workloads" tab={<TabLabel icon={<FileClock size={15} />} text={`Workloads (${data.workloads.length})`} />}>
                <OperationalSection className="observed-workloads-section" title="Observed workloads" count={data.workloads.length}>
                  {data.workloads.length ? (
                    <div className="compact-records">
                      {data.workloads.map((workload) => (
                        <article key={workload.run_id}>
                          <header><strong>{workload.name}</strong><OperationalTag value={workload.status} /></header>
                          <p><code>{workload.command}</code></p>
                          <small>{workload.run_id} · {formatDateTime(workload.started_at)}</small>
                          {workload.status === OBSERVED_WORKLOAD_STATUS.RUNNING ? (
                            <Button
                              icon={<X size={14} />}
                              loading={action === `stop:${workload.run_id}`}
                              onClick={() => void run(`stop:${workload.run_id}`, () => stopObservedWorkload(validId, workload.run_id))}
                            >Stop</Button>
                          ) : null}
                        </article>
                      ))}
                    </div>
                  ) : <EmptyOperationalState icon={<FileClock size={24} />} label="No observed workloads" />}
                </OperationalSection>
              </TabPane>
            </Tabs>
          </>
        ) : null}
      </AsyncContent>
      <DecisionModal
        state={decision}
        saving={Boolean(decision && action === `decision:${decision.revision.id}`)}
        onCancel={() => setDecision(null)}
        onSubmit={async (state, reason) => {
          await run(`decision:${state.revision.id}`, () => state.approve
            ? approveDeceptionRevision(validId, state.revision.id, { reason })
            : rejectDeceptionRevision(validId, state.revision.id, { reason }));
          setDecision(null);
        }}
      />
    </section>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return <div className="workspace-fact"><span>{label}</span><strong>{value}</strong></div>;
}

function LongText({ value }: { value: string }) {
  return <p className="workspace-long-text">{value || "Not recorded."}</p>;
}

function formatFileSize(value: number) {
  if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${value} B`;
}

function RevisionList({ revisions, action, onDecision, onExecute, onRecover }: {
  revisions: DeceptionRevision[];
  action: string | null;
  onDecision: (state: DecisionState) => void;
  onExecute: (revision: DeceptionRevision) => void;
  onRecover: (revision: DeceptionRevision) => void;
}) {
  if (!revisions.length) return <EmptyOperationalState icon={<Workflow size={24} />} label="No revisions" />;
  return (
    <div className="workspace-tab-stack">
      {revisions.map((revision) => (
        <OperationalSection
          key={revision.id}
          title={`Revision ${revision.version} · ${formatEnumLabel(revision.kind)}`}
          actions={(
            <>
              <OperationalTag value={revision.status} />
              {revision.status === DECEPTION_REVISION_STATUS.PENDING_APPROVAL ? (
                <>
                  <Button icon={<Check size={14} />} disabled={Boolean(action)} onClick={() => onDecision({ revision, approve: true })}>Approve</Button>
                  <Button icon={<X size={14} />} disabled={Boolean(action)} onClick={() => onDecision({ revision, approve: false })}>Reject</Button>
                </>
              ) : null}
              {revision.status === DECEPTION_REVISION_STATUS.PLANNED ? (
                <Button icon={<Play size={14} />} loading={action === `execute:${revision.id}`} onClick={() => onExecute(revision)}>Execute</Button>
              ) : null}
              {revision.status === DECEPTION_REVISION_STATUS.RECOVERY_REQUIRED ? (
                <Button icon={<RotateCcw size={14} />} loading={action === `recover:${revision.id}`} onClick={() => onRecover(revision)}>Retry recovery</Button>
              ) : null}
            </>
          )}
        >
          <div className="workspace-facts">
            <Fact label="Risk" value={formatEnumLabel(revision.risk_level)} />
            <Fact label="Container" value={revision.execution_container_id ? `#${revision.execution_container_id}` : "Not created"} />
            <Fact label="Trigger events" value={String(revision.trigger_event_ids.length)} />
            <Fact label="Created" value={formatDateTime(revision.created_at)} />
          </div>
          <LongText value={revision.rationale} />
          <div className="compact-records">
            {(revision.steps ?? []).map((step) => (
              <article key={step.id}>
                <header><strong>{step.sequence}. {step.target}</strong><OperationalTag value={step.status} /></header>
                <p>{step.expected_effect}</p>
                <small>{formatEnumLabel(step.kind)} · timeout {step.timeout_seconds}s</small>
                <pre className="workspace-code-block">{step.apply_command}</pre>
                {step.apply_output ? <pre className="workspace-code-block">{step.apply_output}</pre> : null}
                {step.verify_output ? <pre className="workspace-code-block">{step.verify_output}</pre> : null}
                {step.rollback_output ? <pre className="workspace-code-block">{step.rollback_output}</pre> : null}
                {step.error ? <p className="task-blocker">{step.error}</p> : null}
              </article>
            ))}
          </div>
          {revision.failure_reason ? <p className="task-blocker">Failure: {revision.failure_reason}</p> : null}
          {revision.rollback_error ? <p className="task-blocker">Recovery: {revision.rollback_error}</p> : null}
          {revision.result && revision.result !== revision.failure_reason ? <LongText value={revision.result} /> : null}
        </OperationalSection>
      ))}
    </div>
  );
}

function BehaviorList({ events }: { events: BehaviorEvent[] }) {
  if (!events.length) return <EmptyOperationalState icon={<RadioTower size={24} />} label="No captured behavior" />;
  return (
    <div className="behavior-timeline">
      {events.map((event) => (
        <article className="behavior-event" key={event.id}>
          <div className="behavior-event-time"><strong>{formatDateTime(event.observed_at)}</strong><span>#{event.sequence}</span></div>
          <span className="behavior-event-marker" />
          <div className="behavior-event-body">
            <header><OperationalTag value={event.category} /><strong>{event.summary || event.action}</strong></header>
            <p>{event.command_line || event.file_path || event.service_name || `${event.source_ip || "unknown"} → ${event.destination_ip || "environment"}`}</p>
            <footer><span>{event.sensor_id}</span><span>{formatEnumLabel(event.outcome)}</span></footer>
            <BehaviorEvidenceDetails event={event} />
          </div>
        </article>
      ))}
    </div>
  );
}

function DecisionModal({ state, saving, onCancel, onSubmit }: {
  state: DecisionState;
  saving: boolean;
  onCancel: () => void;
  onSubmit: (state: NonNullable<DecisionState>, reason: string) => Promise<void>;
}) {
  const [reason, setReason] = useState("");
  useEffect(() => setReason(""), [state]);
  if (!state) return null;
  return (
    <ResourceModal
      open
      title={state.approve ? "Approve Deception Revision" : "Reject Deception Revision"}
      titleIcon={state.approve ? <Check size={17} /> : <X size={17} />}
      saving={saving}
      submitLabel={state.approve ? "Approve" : "Reject"}
      submitDisabled={!reason.trim()}
      onCancel={onCancel}
      onSubmit={() => onSubmit(state, reason.trim())}
    >
      <FormField label="Revision"><Input value={`Revision ${state.revision.version}`} disabled /></FormField>
      <FormField label="Decision reason"><TextArea value={reason} rows={5} maxLength={4000} onChange={setReason} /></FormField>
    </ResourceModal>
  );
}
