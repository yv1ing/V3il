import { Button, Input, Select, TabPane, Tabs, TextArea, Tooltip } from "@douyinfe/semi-ui";
import {
  Activity,
  ArrowLeft,
  Bot,
  Check,
  CirclePause,
  ClipboardList,
  Download,
  FileCheck2,
  FileSearch,
  Fingerprint,
  ListTree,
  MessageSquareCode,
  Play,
  Plus,
  RadioTower,
  RefreshCcw,
  RotateCcw,
  Send,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { agentSessionPath } from "../../app/routePaths";
import { listAgents } from "../../shared/api/agents";
import { showApiError, showApiSuccess } from "../../shared/api/feedback";
import { collectAllPages } from "../../shared/api/pagination";
import {
  activateInvestigationTask,
  blockInvestigationTask,
  createInvestigationTask,
  ensureThreatIncidentSession,
  downloadThreatIncidentReport,
  getThreatIncidentTimeline,
  getThreatIncidentWorkspace,
  queryAuditEvents,
  queryIncidentBehaviorEvents,
  queryInvestigationEvidence,
  queryInvestigationTasks,
  reviewInvestigationTask,
  submitInvestigationTask,
  transitionThreatIncident,
  type ThreatIncidentAction,
} from "../../shared/api/threatIncidents";
import {
  AGENT_CODE,
  FIELD_CONSTRAINTS,
  INVESTIGATION_REVIEW_DECISION,
  INVESTIGATION_TASK_PRIORITY,
  INVESTIGATION_TASK_PRIORITY_VALUES,
  INVESTIGATION_TASK_STATUS,
  PAGINATION_MAXIMUM_PAGE_SIZE,
  THREAT_INCIDENT_ACTION,
  THREAT_INCIDENT_STATUS,
  THREAT_INCIDENT_STATUS_TRANSITIONS,
  THREAT_TIMELINE_ITEM_KIND,
} from "../../shared/api/generated/constants";
import type {
  AgentCode,
  AgentInfo,
  AuditEvent,
  BehaviorEvent,
  CreateInvestigationTaskRequest,
  InvestigationEvidence,
  InvestigationTask,
  ThreatIncident,
  ThreatIncidentWorkspace,
  ThreatTimelineItem,
  ThreatTimelineCursor,
} from "../../shared/api/types";
import { AsyncContent } from "../../shared/components/AsyncContent";
import { BehaviorEvidenceDetails } from "../../shared/components/BehaviorEvidenceDetails";
import { FormField } from "../../shared/components/FormField";
import { ResourceModal } from "../../shared/components/ResourceModal";
import { TabLabel } from "../../shared/components/TabLabel";
import { formatDateTime } from "../../shared/lib/date";
import { saveBlob } from "../../shared/lib/download";
import { formatEnumLabel } from "../../shared/lib/labels";
import {
  EmptyOperationalState,
  OperationalSection,
  OperationalTag,
  RiskScore,
} from "../operations/OperationalUi";
import { useAgentSessionContext } from "../playground/AgentSessionProvider";

type IncidentWorkspaceData = {
  workspace: ThreatIncidentWorkspace;
  events: BehaviorEvent[];
  tasks: InvestigationTask[];
  evidence: InvestigationEvidence[];
  audit: AuditEvent[];
  timeline: ThreatTimelineItem[];
  timelineCursor: ThreatTimelineCursor | null;
  timelineHasMore: boolean;
  agents: AgentInfo[];
};

type TaskActionKind = "block" | "submit" | "accept" | "request_changes";
type TaskActionState = { task: InvestigationTask; kind: TaskActionKind } | null;
type TransitionState = { target: ThreatIncident["status"]; action: ThreatIncidentAction } | null;

export function IncidentWorkspacePage() {
  const navigate = useNavigate();
  const { incidentId } = useParams();
  const id = Number(incidentId);
  const validIncidentId = Number.isInteger(id) && id > 0 ? id : 0;
  const { selectSession, syncSessionSummaries } = useAgentSessionContext();
  const [data, setData] = useState<IncidentWorkspaceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [action, setAction] = useState<string | null>(null);
  const [taskModalOpen, setTaskModalOpen] = useState(false);
  const [taskActionState, setTaskActionState] = useState<TaskActionState>(null);
  const [transitionState, setTransitionState] = useState<TransitionState>(null);

  const load = useCallback(async () => {
    if (!validIncidentId) return;
    setLoading(true);
    try {
      const [workspaceResponse, events, tasks, evidence, audit, timelineResponse, agentResponse] = await Promise.all([
        getThreatIncidentWorkspace(validIncidentId),
        collectAllPages<BehaviorEvent>((page) => queryIncidentBehaviorEvents(validIncidentId, { page, size: PAGINATION_MAXIMUM_PAGE_SIZE, keyword: "" })),
        collectAllPages<InvestigationTask>((page) => queryInvestigationTasks(validIncidentId, { page, size: PAGINATION_MAXIMUM_PAGE_SIZE })),
        collectAllPages<InvestigationEvidence>((page) => queryInvestigationEvidence(validIncidentId, { page, size: PAGINATION_MAXIMUM_PAGE_SIZE })),
        collectAllPages<AuditEvent>((page) => queryAuditEvents(validIncidentId, { page, size: PAGINATION_MAXIMUM_PAGE_SIZE })),
        getThreatIncidentTimeline(validIncidentId, { limit: 200 }),
        listAgents(),
      ]);
      if (!workspaceResponse.data) {
        setData(null);
        return;
      }
      setData({
        workspace: workspaceResponse.data,
        events,
        tasks,
        evidence,
        audit,
        timeline: timelineResponse.data?.items ?? [],
        timelineCursor: timelineResponse.data?.next_cursor ?? null,
        timelineHasMore: timelineResponse.data?.has_more ?? false,
        agents: agentResponse.items,
      });
    } catch (error) {
      showApiError(error);
    } finally {
      setLoading(false);
    }
  }, [validIncidentId]);

  useEffect(() => {
    void load();
  }, [load]);

  const openIncidentConsole = async () => {
    if (!validIncidentId || action) return;
    setAction("console");
    try {
      const response = await ensureThreatIncidentSession(validIncidentId);
      const session = response.data;
      if (!session) throw new Error("Incident Console session could not be ensured");
      syncSessionSummaries([session]);
      selectSession(session.id);
      navigate(agentSessionPath(session.id));
    } catch (error) {
      showApiError(error);
      setAction(null);
    }
  };

  const perform = async (key: string, operation: () => Promise<{ code: number; message: string }>) => {
    if (action) return;
    setAction(key);
    try {
      const response = await operation();
      showApiSuccess(response);
      await load();
    } catch (error) {
      showApiError(error);
    } finally {
      setAction(null);
    }
  };

  const createTask = async (payload: CreateInvestigationTaskRequest) => {
    await perform("create-task", () => createInvestigationTask(validIncidentId, payload));
    setTaskModalOpen(false);
  };

  const runTaskDecision = async (task: InvestigationTask, kind: TaskActionKind, text: string) => {
    const operation = kind === "block"
      ? () => blockInvestigationTask(validIncidentId, task.id, { reason: text })
      : kind === "submit"
        ? () => submitInvestigationTask(validIncidentId, task.id, { result_summary: text })
        : () => reviewInvestigationTask(validIncidentId, task.id, {
          decision: kind === "accept" ? INVESTIGATION_REVIEW_DECISION.ACCEPT : INVESTIGATION_REVIEW_DECISION.REQUEST_CHANGES,
          reason: text,
        });
    await perform(`task:${task.id}`, operation);
    setTaskActionState(null);
  };

  const loadOlderTimeline = async () => {
    if (!data?.timelineCursor || action) return;
    setAction("timeline");
    try {
      const response = await getThreatIncidentTimeline(validIncidentId, {
        cursor_at: data.timelineCursor.occurred_at,
        cursor_kind: data.timelineCursor.kind,
        cursor_id: data.timelineCursor.object_id,
        limit: 200,
      });
      const timeline = response.data;
      if (timeline) {
        setData((current) => current ? {
          ...current,
          timeline: [...current.timeline, ...timeline.items],
          timelineCursor: timeline.next_cursor ?? null,
          timelineHasMore: timeline.has_more,
        } : current);
      }
    } catch (error) {
      showApiError(error);
    } finally {
      setAction(null);
    }
  };

  const exportReport = async () => {
    const report = data?.workspace.current_report;
    if (!report || action) return;
    setAction("report");
    try {
      const download = await downloadThreatIncidentReport(validIncidentId, report.id);
      saveBlob(download.blob, download.filename);
    } catch (error) {
      showApiError(error);
    } finally {
      setAction(null);
    }
  };

  if (!validIncidentId) {
    return <EmptyOperationalState icon={<ShieldAlert size={28} />} label="Invalid incident identifier" />;
  }

  const workspace = data?.workspace;
  const incident = workspace?.incident;
  const transitionOptions = incident ? THREAT_INCIDENT_STATUS_TRANSITIONS[incident.status] : [];

  return (
    <section className="workspace-page incident-workspace">
      <button type="button" className="workspace-back" onClick={() => navigate("/incidents")}>
        <ArrowLeft size={15} /> Incident queue
      </button>
      <AsyncContent loading={loading} empty={!data} emptyContent={<EmptyOperationalState icon={<ShieldAlert size={28} />} label="Incident not found" />}>
        {data && workspace && incident ? (
          <>
            <header className="workspace-heading">
              <div className="workspace-title-block">
                <span className="workspace-id">INC-{String(incident.id).padStart(5, "0")}</span>
                <h2>{incident.title}</h2>
                <p>{incident.summary || "No incident summary recorded."}</p>
              </div>
              <div className="workspace-heading-state">
                <OperationalTag value={incident.severity} />
                <RiskScore value={incident.risk_score} />
                <Button icon={<MessageSquareCode size={15} />} loading={action === "console"} onClick={() => void openIncidentConsole()}>Open Console</Button>
                <Button icon={<RefreshCcw size={15} />} loading={loading} onClick={() => void load()}>Refresh</Button>
                {transitionOptions.map((target) => (
                  <Button
                    key={target}
                    disabled={Boolean(action)}
                    onClick={() => setTransitionState({
                      target,
                      action: transitionAction(incident.status, target),
                    })}
                  >{formatEnumLabel(target)}</Button>
                ))}
              </div>
            </header>

            <div className="workspace-facts">
              <Fact label="Environments" value={String(workspace.environments.length)} />
              <Fact label="Sources" value={incident.source_ips.join(", ") || "Unknown"} />
              <Fact label="Primary fingerprint" value={incident.primary_fingerprint || "Not established"} />
              <Fact label="Confidence" value={formatEnumLabel(incident.confidence)} />
              <Fact label="Evidence coverage" value={`${workspace.counts.covered_event_count}/${workspace.counts.scoped_event_count}`} />
              <Fact label="Last observed" value={formatDateTime(incident.last_observed_at)} />
            </div>

            <Tabs type="line" className="workspace-tabs">
              <TabPane itemKey="overview" tab={<TabLabel icon={<ShieldCheck size={15} />} text="Overview" />}>
                <OverviewTab workspace={workspace} />
              </TabPane>
              <TabPane itemKey="timeline" tab={<TabLabel icon={<Activity size={15} />} text={`Timeline (${data.timeline.length})`} />}>
                <TimelineTab items={data.timeline} hasMore={data.timelineHasMore} loading={action === "timeline"} onLoadMore={loadOlderTimeline} />
              </TabPane>
              <TabPane itemKey="behavior" tab={<TabLabel icon={<RadioTower size={15} />} text={`Behavior (${data.events.length})`} />}>
                <BehaviorTimeline events={data.events} />
              </TabPane>
              <TabPane itemKey="investigation" tab={<TabLabel icon={<ClipboardList size={15} />} text={`Investigation (${data.tasks.length})`} />}>
                <InvestigationTab
                  tasks={data.tasks}
                  evidence={data.evidence}
                  action={action}
                  onCreate={() => setTaskModalOpen(true)}
                  onActivate={(task) => void perform(`task:${task.id}`, () => activateInvestigationTask(validIncidentId, task.id))}
                  onOpenAction={(task, kind) => setTaskActionState({ task, kind })}
                />
              </TabPane>
              <TabPane itemKey="intelligence" tab={<TabLabel icon={<FileSearch size={15} />} text="Intelligence" />}>
                <IntelligenceTab workspace={workspace} exporting={action === "report"} onExport={() => void exportReport()} />
              </TabPane>
              <TabPane itemKey="audit" tab={<TabLabel icon={<FileCheck2 size={15} />} text={`Audit (${data.audit.length})`} />}>
                <AuditTab events={data.audit} />
              </TabPane>
            </Tabs>
          </>
        ) : null}
      </AsyncContent>
      <InvestigationTaskModal
        open={taskModalOpen}
        saving={action === "create-task"}
        agents={data?.agents ?? []}
        events={data?.events ?? []}
        tasks={data?.tasks ?? []}
        onCancel={() => setTaskModalOpen(false)}
        onSubmit={createTask}
      />
      <TaskActionModal
        state={taskActionState}
        saving={Boolean(taskActionState && action === `task:${taskActionState.task.id}`)}
        onCancel={() => setTaskActionState(null)}
        onSubmit={runTaskDecision}
      />
      <TransitionModal
        state={transitionState}
        saving={action === "transition"}
        onCancel={() => setTransitionState(null)}
        onSubmit={async (state, reason) => {
          await perform("transition", () => transitionThreatIncident(validIncidentId, state.action, { reason }));
          setTransitionState(null);
        }}
      />
    </section>
  );
}

function OverviewTab({ workspace }: { workspace: ThreatIncidentWorkspace }) {
  return (
    <div className="workspace-tab-stack">
      <div className="workspace-split">
        <OperationalSection title="Environment scope" count={workspace.environments.length}>
          {workspace.environments.length ? (
            <div className="compact-records">
              {workspace.environments.map((environment) => (
                <article key={environment.id}>
                  <header><strong>{environment.name}</strong><OperationalTag value={environment.status} /></header>
                  <p>{environment.description || environment.persona || "No environment description."}</p>
                  <small>Environment #{environment.id} · container {environment.sandbox_container_id ? `#${environment.sandbox_container_id}` : "pending"}</small>
                </article>
              ))}
            </div>
          ) : <EmptyOperationalState icon={<ShieldAlert size={24} />} label="No environments linked" />}
        </OperationalSection>
        <OperationalSection title="Sensor coverage" count={workspace.sensor_coverage?.length ?? 0}>
          {workspace.sensor_coverage?.length ? (
            <div className="compact-records">
              {workspace.sensor_coverage.map((sensor) => (
                <article key={`${sensor.environment_id}:${sensor.sensor_id}`}>
                  <header><strong>{sensor.sensor_id}</strong><OperationalTag value={sensor.status} /></header>
                  <p>{sensor.summary || `Last sequence ${sensor.last_sequence}`}</p>
                  <small>Environment #{sensor.environment_id} · verification token {sensor.verification_token}</small>
                </article>
              ))}
            </div>
          ) : <EmptyOperationalState icon={<RadioTower size={24} />} label="No sensor coverage" />}
        </OperationalSection>
      </div>
      <OperationalSection title="Operational coverage">
        <div className="workspace-facts">
          <Fact label="Assigned events" value={String(workspace.counts.assigned_event_count)} />
          <Fact label="Task-scoped events" value={String(workspace.counts.scoped_event_count)} />
          <Fact label="Evidence-covered events" value={String(workspace.counts.covered_event_count)} />
          <Fact label="Evidence records" value={String(workspace.counts.evidence_count)} />
          <Fact label="Indicators" value={String(workspace.counts.indicators_count)} />
        </div>
      </OperationalSection>
    </div>
  );
}

function TimelineTab({ items, hasMore, loading, onLoadMore }: {
  items: ThreatTimelineItem[];
  hasMore: boolean;
  loading: boolean;
  onLoadMore: () => Promise<void>;
}) {
  if (!items.length) return <EmptyOperationalState icon={<Activity size={24} />} label="No incident timeline entries" />;
  return (
    <div className="workspace-tab-stack">
      <div className="behavior-timeline">
        {items.map((item, index) => (
          <article className="behavior-event" key={`${item.kind}:${item.object_id}:${item.occurred_at}:${index}`}>
            <div className="behavior-event-time"><strong>{formatDateTime(item.occurred_at)}</strong><span>{item.object_id}</span></div>
            <span className="behavior-event-marker" />
            <div className="behavior-event-body">
              <header><OperationalTag value={item.kind} /><strong>{timelineTitle(item)}</strong></header>
              <p>{timelineDetail(item)}</p>
              <footer>{item.environment_id ? <span>Environment #{item.environment_id}</span> : null}{item.task_id ? <span>Task #{item.task_id}</span> : null}</footer>
            </div>
          </article>
        ))}
      </div>
      {hasMore ? <Button loading={loading} onClick={() => void onLoadMore()}>Load older timeline</Button> : null}
    </div>
  );
}

function BehaviorTimeline({ events }: { events: BehaviorEvent[] }) {
  if (!events.length) return <EmptyOperationalState icon={<RadioTower size={24} />} label="No behavior assigned to this incident" />;
  return (
    <div className="behavior-timeline">
      {events.map((event) => (
        <article className="behavior-event" key={event.id}>
          <div className="behavior-event-time"><strong>{formatDateTime(event.observed_at)}</strong><span>#{event.sequence}</span></div>
          <span className="behavior-event-marker" />
          <div className="behavior-event-body">
            <header><OperationalTag value={event.category} /><strong>{event.summary || event.action}</strong></header>
            <p>{event.command_line || event.file_path || event.service_name || `${event.source_ip || "unknown"} → ${event.destination_ip || "environment"}`}</p>
            <footer><span>{event.sensor_id}</span><span>{formatEnumLabel(event.outcome)}</span>{event.username ? <span>{event.username}</span> : null}</footer>
            <BehaviorEvidenceDetails event={event} />
          </div>
        </article>
      ))}
    </div>
  );
}

function InvestigationTab({ tasks, evidence, action, onCreate, onActivate, onOpenAction }: {
  tasks: InvestigationTask[];
  evidence: InvestigationEvidence[];
  action: string | null;
  onCreate: () => void;
  onActivate: (task: InvestigationTask) => void;
  onOpenAction: (task: InvestigationTask, kind: TaskActionKind) => void;
}) {
  return (
    <div className="workspace-tab-stack">
      <OperationalSection title="Investigation tasks" count={tasks.length} actions={<Button icon={<Plus size={15} />} onClick={onCreate}>Create task</Button>}>
        {tasks.length ? (
          <div className="task-board">
            {tasks.map((task) => {
              const canActivate = task.status === INVESTIGATION_TASK_STATUS.QUEUED || task.status === INVESTIGATION_TASK_STATUS.BLOCKED;
              const evidenceCount = evidence.filter((item) => item.task_id === task.id).length;
              return (
                <article className="task-row" key={task.id}>
                  <div className="task-row-main">
                    <header><strong>{task.title}</strong><OperationalTag value={task.status} /><OperationalTag value={task.priority} /></header>
                    <p>{task.objective}</p>
                    <small className="task-completion-criteria">Completion: {task.completion_criteria}</small>
                    {task.blocker_reason ? <small className="task-blocker">Blocker: {task.blocker_reason}</small> : null}
                    {task.result_summary ? <small className="task-result">Result: {task.result_summary}</small> : null}
                    <footer>
                      <span><Bot size={13} /> {task.assignee_agent_code.toUpperCase()}</span>
                      <span>{task.covered_event_ids.length}/{task.behavior_event_ids.length} events covered</span>
                      <span>{evidenceCount} evidence</span>
                      <span>{task.dependency_ids.length} dependencies</span>
                    </footer>
                  </div>
                  <div className="task-row-actions">
                    {canActivate ? <Tooltip content="Activate task"><Button icon={<Play size={15} />} loading={action === `task:${task.id}`} onClick={() => onActivate(task)} /></Tooltip> : null}
                    {task.status === INVESTIGATION_TASK_STATUS.ACTIVE ? <>
                      <Tooltip content="Block task"><Button icon={<CirclePause size={15} />} disabled={Boolean(action)} onClick={() => onOpenAction(task, "block")} /></Tooltip>
                      <Tooltip content="Submit for review"><Button icon={<Send size={15} />} disabled={Boolean(action)} onClick={() => onOpenAction(task, "submit")} /></Tooltip>
                    </> : null}
                    {task.status === INVESTIGATION_TASK_STATUS.REVIEW ? <>
                      <Tooltip content="Request changes"><Button icon={<RotateCcw size={15} />} disabled={Boolean(action)} onClick={() => onOpenAction(task, "request_changes")} /></Tooltip>
                      <Tooltip content="Accept result"><Button icon={<Check size={15} />} disabled={Boolean(action)} onClick={() => onOpenAction(task, "accept")} /></Tooltip>
                    </> : null}
                  </div>
                </article>
              );
            })}
          </div>
        ) : <EmptyOperationalState icon={<ClipboardList size={24} />} label="No investigation tasks" />}
      </OperationalSection>
      <OperationalSection title="Evidence records" count={evidence.length}>
        {evidence.length ? (
          <div className="compact-records">
            {evidence.map((item) => (
              <article key={item.id}>
                <header><strong>{item.statement}</strong><span>Task #{item.task_id}</span></header>
                <p>{item.analysis}</p>
                <small>{item.behavior_links.length} behavior links · {item.evidence_relations.length} evidence relations · {formatDateTime(item.created_at)}</small>
              </article>
            ))}
          </div>
        ) : <EmptyOperationalState icon={<FileCheck2 size={24} />} label="No evidence recorded" />}
      </OperationalSection>
    </div>
  );
}

function IntelligenceTab({ workspace, exporting, onExport }: {
  workspace: ThreatIncidentWorkspace;
  exporting: boolean;
  onExport: () => void;
}) {
  const intent = workspace.current_intent;
  const chain = workspace.current_attack_chain;
  const profile = workspace.current_attacker_profile;
  const risk = workspace.current_risk_assessment;
  const report = workspace.current_report;
  return (
    <div className="workspace-tab-stack">
      <div className="workspace-split">
        <OperationalSection title="Current intent">
          {intent ? <><header><OperationalTag value={intent.status} /></header><LongText value={intent.intent} /><small>{formatEnumLabel(intent.stage)} · {formatEnumLabel(intent.confidence)} · {intent.technique_ids.join(", ") || "No mapped techniques"}</small></> : <EmptyOperationalState icon={<Activity size={24} />} label="No intent assessment" />}
        </OperationalSection>
        <OperationalSection title="Current risk">
          {risk ? <><header><OperationalTag value={risk.severity} /><RiskScore value={risk.risk_score} /></header><LongText value={risk.rationale} /><small>{risk.response_recommendations.length} response recommendations · residual risk: {risk.residual_risk || "not recorded"}</small></> : <EmptyOperationalState icon={<ShieldAlert size={24} />} label="No risk assessment" />}
        </OperationalSection>
      </div>
      <OperationalSection title="Attacker profile">
        {profile ? (
          <div className="workspace-tab-stack">
            <header><OperationalTag value={profile.status} /><OperationalTag value={profile.confidence} /></header>
            <LongText value={profile.summary} />
            <div className="workspace-facts">
              <Fact label="Skill level" value={profile.skill_level || "Unknown"} />
              <Fact label="Objectives" value={profile.objectives.join(", ") || "Unknown"} />
              <Fact label="Tools" value={profile.tools.join(", ") || "Unknown"} />
              <Fact label="Infrastructure" value={profile.infrastructure.join(", ") || "Unknown"} />
            </div>
          </div>
        ) : <EmptyOperationalState icon={<Fingerprint size={24} />} label="No attacker profile" />}
      </OperationalSection>
      <OperationalSection title="Attack chain">
        {chain ? (
          <div className="workspace-tab-stack">
            <header><OperationalTag value={chain.status} /><span>Version {chain.version}</span></header>
            <LongText value={chain.summary} />
            <div className="compact-records">
              {chain.steps.map((step) => (
                <article key={step.sequence}>
                  <header><strong>{step.sequence}. {formatEnumLabel(step.stage)}</strong><OperationalTag value={step.confidence} /></header>
                  <p>{step.description}</p>
                  <small>{step.source || "unknown source"} → {step.target || "unknown target"} · {step.technique_ids?.join(", ") || "No ATT&CK mapping"}</small>
                </article>
              ))}
            </div>
          </div>
        ) : <EmptyOperationalState icon={<ListTree size={24} />} label="No attack chain" />}
      </OperationalSection>
      <OperationalSection
        title="Current intelligence report"
        actions={report ? <Button icon={<Download size={15} />} loading={exporting} onClick={onExport}>Export evidence bundle</Button> : null}
      >
        {report ? (
          <div className="workspace-tab-stack">
            <header><strong>{report.title}</strong><OperationalTag value={report.status} /></header>
            <LongText value={report.executive_summary} />
            <div className="workspace-facts">
              <Fact label="Version" value={String(report.version)} />
              <Fact label="Analysis snapshots" value={String(report.analysis_snapshot.length)} />
              <Fact label="Covered events" value={`${report.evidence_manifest.covered_event_count}/${report.evidence_manifest.material_event_count}`} />
              <Fact label="Knowledge" value={formatEnumLabel(report.knowledge_status)} />
            </div>
          </div>
        ) : <EmptyOperationalState icon={<FileSearch size={24} />} label="No intelligence report" />}
      </OperationalSection>
    </div>
  );
}

function AuditTab({ events }: { events: AuditEvent[] }) {
  if (!events.length) return <EmptyOperationalState icon={<FileCheck2 size={24} />} label="No audit events" />;
  return (
    <div className="compact-records">
      {events.map((event) => (
        <article key={event.id}>
          <header><strong>{event.summary}</strong><OperationalTag value={event.kind} /></header>
          <p>{event.actor_type} {event.actor_code || "system"} · {event.object_type} {event.object_id}</p>
          <small>{formatDateTime(event.created_at)} · session {event.session_id || "none"}</small>
          {Object.keys(event.details).length ? <pre className="workspace-code-block">{JSON.stringify(event.details, null, 2)}</pre> : null}
        </article>
      ))}
    </div>
  );
}

type TaskDraft = Omit<CreateInvestigationTaskRequest, "assignee_agent_code"> & {
  assignee_agent_code: AgentCode | "";
};

const EMPTY_TASK: TaskDraft = {
  title: "",
  priority: INVESTIGATION_TASK_PRIORITY.NORMAL,
  assignee_agent_code: AGENT_CODE.CTH,
  objective: "",
  completion_criteria: "",
  dependency_ids: [],
  behavior_event_ids: [],
};

function InvestigationTaskModal({ open, saving, agents, events, tasks, onCancel, onSubmit }: {
  open: boolean;
  saving: boolean;
  agents: AgentInfo[];
  events: BehaviorEvent[];
  tasks: InvestigationTask[];
  onCancel: () => void;
  onSubmit: (payload: CreateInvestigationTaskRequest) => Promise<void>;
}) {
  const [values, setValues] = useState<TaskDraft>(EMPTY_TASK);
  useEffect(() => {
    if (open) setValues({ ...EMPTY_TASK, dependency_ids: [], behavior_event_ids: [] });
  }, [open]);
  const specialistAgents = agents.filter((agent) => agent.code !== AGENT_CODE.CSO);
  const submitDisabled = !values.title.trim()
    || !values.objective.trim()
    || !values.completion_criteria.trim()
    || !values.assignee_agent_code
    || values.behavior_event_ids.length === 0;
  return (
    <ResourceModal
      open={open}
      title="Create Investigation Task"
      titleIcon={<ClipboardList size={17} />}
      saving={saving}
      submitLabel="Create"
      submitDisabled={submitDisabled}
      size="wide"
      onCancel={onCancel}
      onSubmit={() => {
        if (!values.assignee_agent_code) return;
        return onSubmit({
          ...values,
          assignee_agent_code: values.assignee_agent_code,
          title: values.title.trim(),
          objective: values.objective.trim(),
          completion_criteria: values.completion_criteria.trim(),
        });
      }}
    >
      <FormField label="Title"><Input value={values.title} maxLength={FIELD_CONSTRAINTS.CreateInvestigationTaskRequest.title.maxLength} onChange={(title) => setValues((current) => ({ ...current, title }))} /></FormField>
      <div className="form-grid-two">
        <FormField label="Priority">
          <Select value={values.priority} optionList={INVESTIGATION_TASK_PRIORITY_VALUES.map((value) => ({ label: formatEnumLabel(value), value }))} onChange={(priority) => typeof priority === "string" && setValues((current) => ({ ...current, priority }))} />
        </FormField>
        <FormField label="Assignee Agent">
          <Select value={values.assignee_agent_code} optionList={specialistAgents.map((agent) => ({ label: `${agent.name} (${agent.code.toUpperCase()})`, value: agent.code }))} onChange={(value) => typeof value === "string" && setValues((current) => ({ ...current, assignee_agent_code: value as AgentCode }))} />
        </FormField>
      </div>
      <FormField label="Dependencies">
        <Select multiple value={values.dependency_ids} optionList={tasks.map((task) => ({ label: `#${task.id} · ${task.title}`, value: task.id }))} onChange={(value) => setValues((current) => ({ ...current, dependency_ids: numberSelection(value) }))} />
      </FormField>
      <FormField label="Behavior evidence scope">
        <Select
          multiple
          value={values.behavior_event_ids}
          optionList={events.map((event) => ({ label: `#${event.id} · ${event.summary || event.action}`, value: event.id }))}
          onChange={(value) => setValues((current) => ({ ...current, behavior_event_ids: numberSelection(value) }))}
        />
      </FormField>
      <FormField label="Objective"><TextArea value={values.objective} rows={4} maxLength={FIELD_CONSTRAINTS.CreateInvestigationTaskRequest.objective.maxLength} onChange={(objective) => setValues((current) => ({ ...current, objective }))} /></FormField>
      <FormField label="Completion criteria"><TextArea value={values.completion_criteria} rows={4} maxLength={FIELD_CONSTRAINTS.CreateInvestigationTaskRequest.completion_criteria.maxLength} onChange={(completion_criteria) => setValues((current) => ({ ...current, completion_criteria }))} /></FormField>
    </ResourceModal>
  );
}

function TaskActionModal({ state, saving, onCancel, onSubmit }: {
  state: TaskActionState;
  saving: boolean;
  onCancel: () => void;
  onSubmit: (task: InvestigationTask, kind: TaskActionKind, text: string) => Promise<void>;
}) {
  const [text, setText] = useState("");
  useEffect(() => setText(""), [state]);
  if (!state) return null;
  const labels: Record<TaskActionKind, { title: string; field: string; submit: string }> = {
    block: { title: "Block Investigation Task", field: "Blocker and resume condition", submit: "Block" },
    submit: { title: "Submit Investigation Result", field: "Result summary", submit: "Submit" },
    accept: { title: "Accept Investigation Result", field: "Review decision", submit: "Accept" },
    request_changes: { title: "Request Investigation Changes", field: "Required changes", submit: "Return to specialist" },
  };
  const current = labels[state.kind];
  return (
    <ResourceModal open title={current.title} titleIcon={<ClipboardList size={17} />} saving={saving} submitLabel={current.submit} submitDisabled={!text.trim()} onCancel={onCancel} onSubmit={() => onSubmit(state.task, state.kind, text.trim())}>
      <FormField label="Task"><Input value={`#${state.task.id} · ${state.task.title}`} disabled /></FormField>
      <FormField label={current.field}><TextArea value={text} rows={6} maxLength={state.kind === "submit" ? FIELD_CONSTRAINTS.SubmitInvestigationTaskRequest.result_summary.maxLength : state.kind === "block" ? FIELD_CONSTRAINTS.BlockInvestigationTaskRequest.reason.maxLength : FIELD_CONSTRAINTS.ReviewInvestigationTaskRequest.reason.maxLength} onChange={setText} /></FormField>
    </ResourceModal>
  );
}

function TransitionModal({ state, saving, onCancel, onSubmit }: {
  state: TransitionState;
  saving: boolean;
  onCancel: () => void;
  onSubmit: (state: NonNullable<TransitionState>, reason: string) => Promise<void>;
}) {
  const [reason, setReason] = useState("");
  useEffect(() => setReason(""), [state]);
  if (!state) return null;
  return (
    <ResourceModal open title={`Transition to ${formatEnumLabel(state.target)}`} titleIcon={<ShieldAlert size={17} />} saving={saving} submitLabel="Transition" submitDisabled={!reason.trim()} onCancel={onCancel} onSubmit={() => onSubmit(state, reason.trim())}>
      <FormField label="Reason"><TextArea value={reason} rows={5} maxLength={FIELD_CONSTRAINTS.TransitionThreatIncidentRequest.reason.maxLength} onChange={setReason} /></FormField>
    </ResourceModal>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return <div className="workspace-fact"><span>{label}</span><strong>{value}</strong></div>;
}

function LongText({ value }: { value: string }) {
  return <p className="workspace-long-text">{value || "Not recorded."}</p>;
}

function numberSelection(value: unknown): number[] {
  return Array.isArray(value) ? value.filter((item): item is number => typeof item === "number") : [];
}

function transitionAction(current: ThreatIncident["status"], target: ThreatIncident["status"]): ThreatIncidentAction {
  if (target === THREAT_INCIDENT_STATUS.INVESTIGATING) {
    return current === THREAT_INCIDENT_STATUS.OPEN
      ? THREAT_INCIDENT_ACTION.START_INVESTIGATION
      : THREAT_INCIDENT_ACTION.REOPEN;
  }
  if (target === THREAT_INCIDENT_STATUS.ENGAGING) return THREAT_INCIDENT_ACTION.START_ENGAGEMENT;
  if (target === THREAT_INCIDENT_STATUS.FINALIZING) return THREAT_INCIDENT_ACTION.FINALIZE;
  return THREAT_INCIDENT_ACTION.CLOSE;
}

function timelineTitle(item: ThreatTimelineItem): string {
  switch (item.kind) {
    case THREAT_TIMELINE_ITEM_KIND.BEHAVIOR_EVENT:
      return item.payload.summary || item.payload.action || formatEnumLabel(item.kind);
    case THREAT_TIMELINE_ITEM_KIND.AUDIT_EVENT:
      return item.payload.summary || formatEnumLabel(item.payload.kind);
    case THREAT_TIMELINE_ITEM_KIND.INVESTIGATION_TASK:
      return item.payload.title;
    case THREAT_TIMELINE_ITEM_KIND.INVESTIGATION_EVIDENCE:
      return item.payload.statement;
    case THREAT_TIMELINE_ITEM_KIND.DECEPTION_REVISION:
      return `Revision v${item.payload.version}: ${item.payload.target_persona}`;
  }
}

function timelineDetail(item: ThreatTimelineItem): string {
  const value = timelineDetailText(item);
  if (typeof value === "string" && value) return value;
  const compact = JSON.stringify(item.payload);
  return compact.length > 800 ? `${compact.slice(0, 800)}…` : compact;
}

function timelineDetailText(item: ThreatTimelineItem): string {
  switch (item.kind) {
    case THREAT_TIMELINE_ITEM_KIND.BEHAVIOR_EVENT:
      return item.payload.command_line || item.payload.file_path || item.payload.summary;
    case THREAT_TIMELINE_ITEM_KIND.AUDIT_EVENT:
      return JSON.stringify(item.payload.details);
    case THREAT_TIMELINE_ITEM_KIND.INVESTIGATION_TASK:
      return item.payload.result_summary || item.payload.objective;
    case THREAT_TIMELINE_ITEM_KIND.INVESTIGATION_EVIDENCE:
      return item.payload.analysis;
    case THREAT_TIMELINE_ITEM_KIND.DECEPTION_REVISION:
      return item.payload.rationale;
  }
}
