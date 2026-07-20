import { Button, Input, Select, TabPane, Tabs, Table, Tag, TextArea, Tooltip } from "@douyinfe/semi-ui";
import {
  Activity,
  Check,
  Code2,
  Diff,
  FileCheck2,
  GitPullRequestArrow,
  Pencil,
  Plus,
  RadioTower,
  RefreshCw,
  RotateCcw,
  Send,
  ServerCog,
  ShieldCheck,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  configureManagedHostSensor,
  createDetectionRule,
  createDetectionRuleVersion,
  decideDetectionRuleChange,
  queryBehaviorDecisions,
  queryBehaviorSignals,
  queryDetectionDeployments,
  queryDetectionRuleChanges,
  queryDetectionRules,
  queryDetectionRuleVersions,
  queryManagedHostSensors,
  replayDetectionRuleVersion,
  submitDetectionRuleChange,
  validateDetectionRuleVersion,
} from "../../shared/api/detection";
import { showApiError, showApiSuccess } from "../../shared/api/feedback";
import { queryDeceptionEnvironments } from "../../shared/api/deceptionEnvironments";
import {
  BEHAVIOR_CLASSIFICATION,
  CENTRAL_RULE_OPERATOR,
  DETECTION_RULE_CHANGE_ACTION,
  DETECTION_RULE_CHANGE_ACTION_VALUES,
  DETECTION_RULE_CHANGE_DECISION,
  DETECTION_RULE_CHANGE_DECISION_VALUES,
  DETECTION_RULE_CHANGE_STATUS,
  DETECTION_RULE_ORIGIN,
  DETECTION_RULE_SCOPE,
  DETECTION_RULE_SCOPE_VALUES,
  DETECTION_RULE_TYPE,
  DETECTION_RULE_TYPE_VALUES,
  DETECTION_RULE_VERSION_STATUS,
  DETECTION_SENSOR_HEALTH_STATUS,
  PAGINATION_MAXIMUM_PAGE_SIZE,
  SYSTEM_USER_ROLE,
} from "../../shared/api/generated/constants";
import type {
  BehaviorDecision,
  BehaviorSignal,
  ConfigureManagedHostSensorRequest,
  CreateDetectionRuleRequest,
  DetectionRule,
  DetectionRuleChange,
  DetectionRuleChangeAction,
  DetectionRuleChangeDecision,
  DetectionRuleDeployment,
  DetectionRuleScope,
  DetectionRuleType,
  DetectionRuleVersion,
  DeceptionEnvironment,
  ManagedHostSensor,
} from "../../shared/api/types";
import { useAuth } from "../../shared/auth/AuthProvider";
import { AppModal } from "../../shared/components/AppModal";
import { EmptyState } from "../../shared/components/EmptyState";
import { TabLabel } from "../../shared/components/TabLabel";
import { useAdminResourceHeader } from "../../shared/hooks/useAdminResourceHeader";
import { formatDateTime } from "../../shared/lib/date";
import { formatEnumLabel } from "../../shared/lib/labels";
import { OperationalTag, RiskScore } from "../operations/OperationalUi";
import "../../app/styles/detection.css";

const PAGE_SIZE = PAGINATION_MAXIMUM_PAGE_SIZE;
const CENTRAL_RULE_TEMPLATE = JSON.stringify({
  signal_kind: "custom_signal",
  classification: BEHAVIOR_CLASSIFICATION.SUSPICIOUS,
  score: 60,
  all: [{ field: "source_ip", operator: CENTRAL_RULE_OPERATOR.EXISTS, value: true }],
  any: [],
  threshold: 1,
  window_seconds: 60,
  cooldown_seconds: 60,
  group_by: ["source_ip"],
  distinct_by: [],
  correlation_fields: ["source_ip"],
  material: true,
  reason: "Custom deterministic detection rule matched.",
}, null, 2);

type RuleForm = {
  name: string;
  description: string;
  type: DetectionRuleType;
  scope: DetectionRuleScope;
  host_id: string;
  environment_id: string;
  content: string;
};

type VersionEditorState = { rule: DetectionRule; parent: DetectionRuleVersion | null; content: string };
type ChangeFormState = { rule: DetectionRule; versionId: number | null; action: DetectionRuleChangeAction; sensorIds: string; reason: string };
type DecisionFormState = { change: DetectionRuleChange; decision: DetectionRuleChangeDecision; reason: string };

const EMPTY_RULE: RuleForm = {
  name: "",
  description: "",
  type: DETECTION_RULE_TYPE.CENTRAL_RULE,
  scope: DETECTION_RULE_SCOPE.ENVIRONMENT,
  host_id: "",
  environment_id: "",
  content: CENTRAL_RULE_TEMPLATE,
};

export function DetectionPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === SYSTEM_USER_ROLE.ADMIN;
  const [activeTab, setActiveTab] = useState("rules");
  const [loading, setLoading] = useState(false);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [changes, setChanges] = useState<DetectionRuleChange[]>([]);
  const [sensors, setSensors] = useState<ManagedHostSensor[]>([]);
  const [signals, setSignals] = useState<BehaviorSignal[]>([]);
  const [decisions, setDecisions] = useState<BehaviorDecision[]>([]);
  const [environments, setEnvironments] = useState<DeceptionEnvironment[]>([]);
  const [ruleForm, setRuleForm] = useState<RuleForm | null>(null);
  const [selectedRule, setSelectedRule] = useState<DetectionRule | null>(null);
  const [versions, setVersions] = useState<DetectionRuleVersion[]>([]);
  const [versionEditor, setVersionEditor] = useState<VersionEditorState | null>(null);
  const [changeForm, setChangeForm] = useState<ChangeFormState | null>(null);
  const [decisionForm, setDecisionForm] = useState<DecisionFormState | null>(null);
  const [deployments, setDeployments] = useState<{ change: DetectionRuleChange; items: DetectionRuleDeployment[] } | null>(null);
  const [sensorForm, setSensorForm] = useState<ConfigureManagedHostSensorRequest | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const requests = [
        queryDetectionRules({ page: 1, size: PAGE_SIZE, keyword: "" }),
        queryDetectionRuleChanges({ page: 1, size: PAGE_SIZE }),
        queryBehaviorSignals({ page: 1, size: PAGE_SIZE }),
        queryBehaviorDecisions({ page: 1, size: PAGE_SIZE }),
      ] as const;
      const [ruleResponse, changeResponse, signalResponse, decisionResponse] = await Promise.all(requests);
      setRules(ruleResponse.data?.items ?? []);
      setChanges(changeResponse.data?.items ?? []);
      setSignals(signalResponse.data?.items ?? []);
      setDecisions(decisionResponse.data?.items ?? []);
      const [sensorResponse, environmentResponse] = await Promise.all([
        queryManagedHostSensors({ page: 1, size: PAGE_SIZE }),
        queryDeceptionEnvironments({ page: 1, size: PAGE_SIZE, keyword: "" }),
      ]);
      setSensors(sensorResponse.data?.items ?? []);
      setEnvironments(environmentResponse.data?.items ?? []);
    } catch (error) {
      showApiError(error);
    } finally {
      setLoading(false);
    }
  }, [isAdmin]);

  useEffect(() => { void load(); }, [load]);

  useAdminResourceHeader({
    createLabel: "Create Rule",
    refreshLabel: "Refresh detection data",
    loading,
    onCreate: () => setRuleForm({ ...EMPTY_RULE }),
    onRefresh: load,
  });

  const openVersions = async (rule: DetectionRule) => {
    setBusy(true);
    try {
      const response = await queryDetectionRuleVersions(rule.id, { page: 1, size: PAGE_SIZE });
      setVersions(response.data?.items ?? []);
      setSelectedRule(rule);
    } catch (error) {
      showApiError(error);
    } finally {
      setBusy(false);
    }
  };

  const openChange = async (rule: DetectionRule) => {
    setBusy(true);
    try {
      const response = await queryDetectionRuleVersions(rule.id, { page: 1, size: PAGE_SIZE });
      const items = response.data?.items ?? [];
      setVersions(items);
      const defaultVersion = items.find((item) => item.status === DETECTION_RULE_VERSION_STATUS.VALIDATED)?.id ?? rule.active_version_id;
      const environmentHostId = environments.find((item) => item.id === rule.environment_id)?.host_id;
      const targetSensors = sensors.filter((sensor) => (
        rule.scope === DETECTION_RULE_SCOPE.GLOBAL
        || (rule.scope === DETECTION_RULE_SCOPE.HOST && sensor.host_id === rule.host_id)
        || (rule.scope === DETECTION_RULE_SCOPE.ENVIRONMENT && sensor.host_id === environmentHostId)
      ));
      setChangeForm({
        rule,
        versionId: defaultVersion,
        action: rule.active_version_id ? DETECTION_RULE_CHANGE_ACTION.REPLACE : DETECTION_RULE_CHANGE_ACTION.ACTIVATE,
        sensorIds: targetSensors.map((item) => item.id).join(", "),
        reason: "",
      });
    } catch (error) {
      showApiError(error);
    } finally {
      setBusy(false);
    }
  };

  const saveRule = async () => {
    if (!ruleForm) return;
    const payload: CreateDetectionRuleRequest = {
      name: ruleForm.name.trim(),
      description: ruleForm.description.trim(),
      type: ruleForm.type,
      scope: ruleForm.scope,
      host_id: ruleForm.scope === DETECTION_RULE_SCOPE.HOST ? Number(ruleForm.host_id) : null,
      environment_id: ruleForm.scope === DETECTION_RULE_SCOPE.ENVIRONMENT ? Number(ruleForm.environment_id) : null,
      content: ruleForm.content,
    };
    await runMutation(async () => {
      const response = await createDetectionRule(payload);
      showApiSuccess(response);
      setRuleForm(null);
      await load();
    });
  };

  const saveVersion = async () => {
    if (!versionEditor) return;
    await runMutation(async () => {
      const response = await createDetectionRuleVersion(versionEditor.rule.id, {
        parent_version_id: versionEditor.parent?.id ?? null,
        content: versionEditor.content,
      });
      showApiSuccess(response);
      setVersionEditor(null);
      await openVersions(versionEditor.rule);
      await load();
    });
  };

  const validateVersion = async (version: DetectionRuleVersion) => {
    if (!selectedRule) return;
    await runMutation(async () => {
      const response = await validateDetectionRuleVersion(selectedRule.id, version.id);
      showApiSuccess(response);
      await openVersions(selectedRule);
    });
  };

  const replayVersion = async (version: DetectionRuleVersion) => {
    if (!selectedRule) return;
    const raw = window.prompt("Behavior event IDs, separated by commas");
    if (!raw) return;
    const eventIds = raw.split(",").map((item) => Number(item.trim())).filter((item) => Number.isInteger(item) && item > 0);
    if (!eventIds.length) return;
    await runMutation(async () => {
      const response = await replayDetectionRuleVersion(selectedRule.id, version.id, { event_ids: eventIds });
      showApiSuccess(response);
      await openVersions(selectedRule);
    });
  };

  const submitChange = async () => {
    if (!changeForm) return;
    const targetIds = parseIds(changeForm.sensorIds);
    await runMutation(async () => {
      const response = await submitDetectionRuleChange(changeForm.rule.id, {
        action: changeForm.action,
        rule_version_id: changeForm.action === DETECTION_RULE_CHANGE_ACTION.DISABLE ? null : changeForm.versionId,
        target_sensor_ids: targetIds,
        reason: changeForm.reason.trim(),
      });
      showApiSuccess(response);
      setChangeForm(null);
      await load();
    });
  };

  const decideChange = async () => {
    if (!decisionForm) return;
    await runMutation(async () => {
      const response = await decideDetectionRuleChange(decisionForm.change.id, {
        decision: decisionForm.decision,
        reason: decisionForm.reason.trim(),
      });
      showApiSuccess(response);
      setDecisionForm(null);
      await load();
    });
  };

  const openDeployments = async (change: DetectionRuleChange) => {
    await runMutation(async () => {
      const response = await queryDetectionDeployments(change.id, { page: 1, size: PAGE_SIZE });
      setDeployments({ change, items: response.data?.items ?? [] });
    });
  };

  const saveSensor = async () => {
    if (!sensorForm) return;
    await runMutation(async () => {
      const response = await configureManagedHostSensor(sensorForm);
      showApiSuccess(response);
      setSensorForm(null);
      await load();
    });
  };

  const runMutation = async (operation: () => Promise<void>) => {
    if (busy) return;
    setBusy(true);
    try { await operation(); } catch (error) { showApiError(error); } finally { setBusy(false); }
  };

  const pendingCount = changes.filter((item) => item.status === DETECTION_RULE_CHANGE_STATUS.PENDING_APPROVAL).length;
  const metrics = useMemo(() => ({
    activeRules: rules.filter((rule) => rule.active_version_id !== null).length,
    pendingCount,
    healthySensors: sensors.filter((sensor) => sensor.status === DETECTION_SENSOR_HEALTH_STATUS.HEALTHY).length,
    criticalSignals: signals.filter((signal) => signal.score >= 90).length,
  }), [changes, pendingCount, rules, sensors, signals]);

  return (
    <section className="detection-page">
      <div className="detection-metrics" aria-label="Detection status">
        <Metric label="Active Rules" value={metrics.activeRules} />
        <Metric label="Awaiting Approval" value={metrics.pendingCount} />
        <Metric label="Healthy Sensors" value={isAdmin ? metrics.healthySensors : "-"} />
        <Metric label="Critical Signals" value={metrics.criticalSignals} />
      </div>

      <Tabs type="line" activeKey={activeTab} onChange={setActiveTab} className="detection-tabs">
        <TabPane itemKey="rules" tab={<TabLabel icon={<Code2 size={15} />} text={`Rules (${rules.length})`} />}>
          <RulesTable rules={rules} busy={busy} onVersions={openVersions} onChange={openChange} />
        </TabPane>
        <TabPane itemKey="approvals" tab={<TabLabel icon={<GitPullRequestArrow size={15} />} text={`Approvals (${pendingCount})`} />}>
          <ChangesTable changes={changes} busy={busy} onDecision={(change, decision) => setDecisionForm({ change, decision, reason: "" })} onDeployments={openDeployments} />
        </TabPane>
        {isAdmin ? (
          <TabPane itemKey="sensors" tab={<TabLabel icon={<RadioTower size={15} />} text={`Sensors (${sensors.length})`} />}>
            <div className="detection-tab-toolbar">
              <Button icon={<Plus size={15} />} theme="solid" type="primary" onClick={() => setSensorForm(emptySensorForm())}>Configure Sensor</Button>
            </div>
            <SensorsTable sensors={sensors} />
          </TabPane>
        ) : null}
        <TabPane itemKey="signals" tab={<TabLabel icon={<Activity size={15} />} text={`Signals (${signals.length})`} />}>
          <SignalsTable signals={signals} />
        </TabPane>
        <TabPane itemKey="decisions" tab={<TabLabel icon={<FileCheck2 size={15} />} text={`Decisions (${decisions.length})`} />}>
          <DecisionsTable decisions={decisions} />
        </TabPane>
      </Tabs>

      <RuleModal value={ruleForm} busy={busy} onChange={setRuleForm} onCancel={() => setRuleForm(null)} onSave={saveRule} />
      <VersionsModal rule={selectedRule} versions={versions} busy={busy} onClose={() => setSelectedRule(null)} onEdit={(version) => setVersionEditor({ rule: selectedRule!, parent: version, content: version.content })} onValidate={validateVersion} onReplay={replayVersion} />
      <VersionEditorModal value={versionEditor} busy={busy} onChange={setVersionEditor} onCancel={() => setVersionEditor(null)} onSave={saveVersion} />
      <ChangeModal value={changeForm} versions={versions} busy={busy} onChange={setChangeForm} onCancel={() => setChangeForm(null)} onSubmit={submitChange} />
      <DecisionModal value={decisionForm} busy={busy} onChange={setDecisionForm} onCancel={() => setDecisionForm(null)} onSubmit={decideChange} />
      <DeploymentsModal value={deployments} onClose={() => setDeployments(null)} />
      <SensorModal value={sensorForm} busy={busy} onChange={setSensorForm} onCancel={() => setSensorForm(null)} onSave={saveSensor} />
    </section>
  );
}

function RulesTable({ rules, busy, onVersions, onChange }: { rules: DetectionRule[]; busy: boolean; onVersions: (rule: DetectionRule) => void; onChange: (rule: DetectionRule) => void }) {
  return (
    <Table
      className="detection-table detection-fill-table"
      dataSource={rules}
      rowKey="id"
      pagination={false}
      loading={false}
      empty={<EmptyState className="data-table-empty" compact icon={<ShieldCheck size={30} />} title="No detection rules" />}
      columns={[
        { title: "Rule", render: (_: unknown, rule: DetectionRule) => <div className="detection-primary"><strong>{rule.name}</strong><small>{rule.description || "No description"}</small></div> },
        { title: "Type", dataIndex: "type", width: 150, render: (value: string) => <Tag color="blue">{formatEnumLabel(value)}</Tag> },
        { title: "Origin", dataIndex: "origin", width: 110, render: (value: string) => <Tag color={value === DETECTION_RULE_ORIGIN.AGENT ? "cyan" : value === DETECTION_RULE_ORIGIN.BUILTIN ? "amber" : "grey"}>{formatEnumLabel(value)}</Tag> },
        { title: "Scope", dataIndex: "scope", width: 125, render: (value: string) => formatEnumLabel(value) },
        { title: "Active", dataIndex: "active_version_id", width: 90, render: (value: number | null) => value ? <OperationalTag value={DETECTION_RULE_CHANGE_STATUS.ACTIVE} /> : <OperationalTag value={DETECTION_RULE_VERSION_STATUS.DRAFT} /> },
        { title: "Updated", dataIndex: "updated_at", width: 165, render: (value: string) => formatDateTime(value) },
        { title: "", width: 100, render: (_: unknown, rule: DetectionRule) => <div className="row-actions"><Tooltip content="Versions"><Button theme="borderless" icon={<Diff size={15} />} onClick={() => onVersions(rule)} /></Tooltip><Tooltip content="Submit change"><Button theme="borderless" icon={<Send size={15} />} disabled={busy} onClick={() => onChange(rule)} /></Tooltip></div> },
      ]}
    />
  );
}

function ChangesTable({ changes, busy, onDecision, onDeployments }: { changes: DetectionRuleChange[]; busy: boolean; onDecision: (change: DetectionRuleChange, decision: DetectionRuleChangeDecision) => void; onDeployments: (change: DetectionRuleChange) => void }) {
  return (
    <Table
      className="detection-table detection-fill-table"
      dataSource={changes}
      rowKey="id"
      pagination={false}
      empty={<EmptyState className="data-table-empty" compact icon={<GitPullRequestArrow size={30} />} title="No rule change requests" />}
      columns={[
        { title: "Request", render: (_: unknown, item: DetectionRuleChange) => <div className="detection-primary"><strong>Rule #{item.rule_id} · {formatEnumLabel(item.action)}</strong><small>{item.error || `${item.requested_by_actor_type}:${item.requested_by_actor_code || "system"}`}</small></div> },
        { title: "Scope", dataIndex: "scope", width: 120, render: (value: string) => formatEnumLabel(value) },
        { title: "Targets", dataIndex: "target_sensor_ids", width: 100, render: (value: number[]) => value.join(", ") },
        { title: "Bundle", dataIndex: "effective_bundle_hash", width: 135, render: (value: string) => <code>{shortHash(value)}</code> },
        { title: "Status", dataIndex: "status", width: 145, render: (value: string) => <OperationalTag value={value} /> },
        { title: "Created", dataIndex: "created_at", width: 165, render: (value: string) => formatDateTime(value) },
        { title: "", width: 145, render: (_: unknown, item: DetectionRuleChange) => <div className="row-actions">{item.status === DETECTION_RULE_CHANGE_STATUS.PENDING_APPROVAL ? <><Tooltip content="Approve exact request"><Button theme="borderless" type="primary" icon={<Check size={15} />} disabled={busy} onClick={() => onDecision(item, DETECTION_RULE_CHANGE_DECISION.APPROVE)} /></Tooltip><Tooltip content="Request changes"><Button theme="borderless" icon={<RotateCcw size={15} />} disabled={busy} onClick={() => onDecision(item, DETECTION_RULE_CHANGE_DECISION.REQUEST_CHANGES)} /></Tooltip><Tooltip content="Reject"><Button theme="borderless" type="danger" icon={<X size={15} />} disabled={busy} onClick={() => onDecision(item, DETECTION_RULE_CHANGE_DECISION.REJECT)} /></Tooltip></> : null}<Tooltip content="Deployment details"><Button theme="borderless" icon={<ServerCog size={15} />} onClick={() => onDeployments(item)} /></Tooltip></div> },
      ]}
    />
  );
}

function SensorsTable({ sensors }: { sensors: ManagedHostSensor[] }) {
  return (
    <Table
      className="detection-table detection-fill-table"
      dataSource={sensors}
      rowKey="id"
      pagination={false}
      empty={<EmptyState className="data-table-empty" compact icon={<RadioTower size={30} />} title="No managed sensors" />}
      columns={[
        { title: "Sensor", render: (_: unknown, item: ManagedHostSensor) => <div className="detection-primary"><strong>{item.sensor_id}</strong><small>Host #{item.host_id} · {item.capture_interface}</small></div> },
        { title: "Status", dataIndex: "status", width: 120, render: (value: string) => <OperationalTag value={value} /> },
        { title: "Active Bundle", dataIndex: "active_bundle_hash", width: 150, render: (value: string) => <code>{shortHash(value)}</code> },
        { title: "Sequence", dataIndex: "last_sequence", width: 100 },
        { title: "Heartbeat", dataIndex: "last_heartbeat_at", width: 170, render: (value: string | null) => value ? formatDateTime(value) : "-" },
        { title: "Error", dataIndex: "last_error", render: (value: string) => <span className="detection-error">{value || "-"}</span> },
      ]}
    />
  );
}

function SignalsTable({ signals }: { signals: BehaviorSignal[] }) {
  return (
    <Table
      className="detection-table detection-fill-table"
      dataSource={signals}
      rowKey="id"
      pagination={false}
      empty={<EmptyState className="data-table-empty" compact icon={<Activity size={30} />} title="No behavior signals" />}
      columns={[
        { title: "Signal", render: (_: unknown, item: BehaviorSignal) => <div className="detection-primary"><strong>{formatEnumLabel(item.kind)}</strong><small>Environment #{item.environment_id} · Incident {item.incident_id ? `#${item.incident_id}` : "pending"}</small></div> },
        { title: "Class", dataIndex: "classification", width: 120, render: (value: string) => <OperationalTag value={value} /> },
        { title: "Score", dataIndex: "score", width: 130, render: (value: number) => <RiskScore value={value} /> },
        { title: "Threshold", width: 110, render: (_: unknown, item: BehaviorSignal) => `${item.threshold_count}/${item.threshold}` },
        { title: "Evidence", dataIndex: "event_count", width: 90 },
        { title: "Status", dataIndex: "status", width: 105, render: (value: string) => <OperationalTag value={value} /> },
        { title: "Last Seen", dataIndex: "last_observed_at", width: 170, render: (value: string) => formatDateTime(value) },
      ]}
    />
  );
}

function DecisionsTable({ decisions }: { decisions: BehaviorDecision[] }) {
  return (
    <Table
      className="detection-table detection-fill-table"
      dataSource={decisions}
      rowKey="id"
      pagination={false}
      empty={<EmptyState className="data-table-empty" compact icon={<FileCheck2 size={30} />} title="No behavior decisions" />}
      columns={[
        { title: "Decision", render: (_: unknown, item: BehaviorDecision) => <div className="detection-primary"><strong>Event #{item.event_id} · {item.signal_kind ? formatEnumLabel(item.signal_kind) : "No signal"}</strong><small>{item.reason}</small></div> },
        { title: "Class", dataIndex: "classification", width: 120, render: (value: string) => <OperationalTag value={value} /> },
        { title: "Score", dataIndex: "score", width: 90 },
        { title: "Rules", dataIndex: "matched_rule_versions", width: 80, render: (value: unknown[]) => value.length },
        { title: "Bundle", dataIndex: "bundle_hash", width: 140, render: (value: string) => <code>{shortHash(value)}</code> },
        { title: "Created", dataIndex: "created_at", width: 170, render: (value: string) => formatDateTime(value) },
      ]}
    />
  );
}

function RuleModal({ value, busy, onChange, onCancel, onSave }: { value: RuleForm | null; busy: boolean; onChange: (value: RuleForm | null) => void; onCancel: () => void; onSave: () => void }) {
  return <AppModal open={Boolean(value)} title="Create Detection Rule" titleIcon={<ShieldCheck size={17} />} size="wide" onCancel={onCancel} footer={<><Button onClick={onCancel}>Cancel</Button><Button theme="solid" type="primary" loading={busy} disabled={!value?.name.trim() || !value?.content.trim()} onClick={onSave}>Create Draft</Button></>}>
    {value ? <div className="detection-form"><Field label="Name"><Input value={value.name} onChange={(name) => onChange({ ...value, name })} /></Field><Field label="Description"><Input value={value.description} onChange={(description) => onChange({ ...value, description })} /></Field><div className="detection-form-grid"><Field label="Type"><Select value={value.type} optionList={DETECTION_RULE_TYPE_VALUES.map((item) => ({ value: item, label: formatEnumLabel(item) }))} onChange={(next) => onChange({ ...value, type: next as DetectionRuleType, content: next === DETECTION_RULE_TYPE.CENTRAL_RULE ? CENTRAL_RULE_TEMPLATE : value.content })} /></Field><Field label="Scope"><Select value={value.scope} optionList={DETECTION_RULE_SCOPE_VALUES.map((item) => ({ value: item, label: formatEnumLabel(item) }))} onChange={(next) => onChange({ ...value, scope: next as DetectionRuleScope })} /></Field>{value.scope === DETECTION_RULE_SCOPE.HOST ? <Field label="Host ID"><Input value={value.host_id} onChange={(host_id) => onChange({ ...value, host_id })} /></Field> : null}{value.scope === DETECTION_RULE_SCOPE.ENVIRONMENT ? <Field label="Environment ID"><Input value={value.environment_id} onChange={(environment_id) => onChange({ ...value, environment_id })} /></Field> : null}</div><Field label="Rule Content"><TextArea value={value.content} autosize={{ minRows: 14, maxRows: 24 }} onChange={(content) => onChange({ ...value, content })} /></Field></div> : null}
  </AppModal>;
}

function VersionsModal({ rule, versions, busy, onClose, onEdit, onValidate, onReplay }: { rule: DetectionRule | null; versions: DetectionRuleVersion[]; busy: boolean; onClose: () => void; onEdit: (version: DetectionRuleVersion) => void; onValidate: (version: DetectionRuleVersion) => void; onReplay: (version: DetectionRuleVersion) => void }) {
  return (
    <AppModal
      open={Boolean(rule)}
      title={rule ? `${rule.name} Versions` : "Rule Versions"}
      titleIcon={<Diff size={17} />}
      size="wide"
      onCancel={onClose}
    >
      <div className="detection-version-list">
        {versions.length === 0 ? (
          <EmptyState compact icon={<Diff size={30} />} title="No rule versions" />
        ) : versions.map((version) => (
          <article key={version.id}>
            <header>
              <div>
                <strong>Version {version.version}</strong>
                <OperationalTag value={version.status} />
                {rule?.active_version_id === version.id ? <Tag color="green">Active</Tag> : null}
              </div>
              <div className="row-actions">
                <Tooltip content="Create derived version"><Button theme="borderless" icon={<Pencil size={15} />} onClick={() => onEdit(version)} /></Tooltip>
                <Tooltip content="Validate"><Button theme="borderless" icon={<Check size={15} />} disabled={busy} onClick={() => onValidate(version)} /></Tooltip>
                <Tooltip content="Offline replay"><Button theme="borderless" icon={<RefreshCw size={15} />} disabled={busy} onClick={() => onReplay(version)} /></Tooltip>
              </div>
            </header>
            <div className="detection-version-meta">
              <code>{version.content_sha256}</code>
              <span>{formatDateTime(version.created_at)}</span>
            </div>
            <pre>{version.content}</pre>
            {version.validation_result?.errors
              && Array.isArray(version.validation_result.errors)
              && version.validation_result.errors.length ? (
                <div className="detection-validation-errors">
                  {version.validation_result.errors.map((error) => <span key={String(error)}>{String(error)}</span>)}
                </div>
              ) : null}
          </article>
        ))}
      </div>
    </AppModal>
  );
}

function VersionEditorModal({ value, busy, onChange, onCancel, onSave }: { value: VersionEditorState | null; busy: boolean; onChange: (value: VersionEditorState | null) => void; onCancel: () => void; onSave: () => void }) {
  return <AppModal open={Boolean(value)} title="Create Rule Version" titleIcon={<Code2 size={17} />} size="wide" onCancel={onCancel} footer={<><Button onClick={onCancel}>Cancel</Button><Button theme="solid" type="primary" loading={busy} disabled={!value?.content.trim()} onClick={onSave}>Create Version</Button></>}>
    {value ? <div className="detection-form"><div className="detection-binding"><span>Rule</span><strong>{value.rule.name}</strong><span>Parent</span><strong>{value.parent ? `v${value.parent.version}` : "None"}</strong></div><Field label="Immutable Content"><TextArea value={value.content} autosize={{ minRows: 18, maxRows: 28 }} onChange={(content) => onChange({ ...value, content })} /></Field></div> : null}
  </AppModal>;
}

function ChangeModal({ value, versions, busy, onChange, onCancel, onSubmit }: { value: ChangeFormState | null; versions: DetectionRuleVersion[]; busy: boolean; onChange: (value: ChangeFormState | null) => void; onCancel: () => void; onSubmit: () => void }) {
  const validated = versions.filter((item) => item.status === DETECTION_RULE_VERSION_STATUS.VALIDATED);
  return <AppModal open={Boolean(value)} title="Submit Rule Change" titleIcon={<Send size={17} />} size="standard" onCancel={onCancel} footer={<><Button onClick={onCancel}>Cancel</Button><Button theme="solid" type="primary" loading={busy} disabled={!value?.reason.trim() || !parseIds(value?.sensorIds ?? "").length || (value?.action !== DETECTION_RULE_CHANGE_ACTION.DISABLE && !value?.versionId)} onClick={onSubmit}>Submit for Approval</Button></>}>
    {value ? <div className="detection-form"><div className="detection-binding"><span>Rule</span><strong>{value.rule.name}</strong><span>Scope</span><strong>{formatEnumLabel(value.rule.scope)}</strong></div><div className="detection-form-grid"><Field label="Action"><Select value={value.action} optionList={DETECTION_RULE_CHANGE_ACTION_VALUES.map((item) => ({ value: item, label: formatEnumLabel(item) }))} onChange={(action) => onChange({ ...value, action: action as DetectionRuleChangeAction })} /></Field>{value.action !== DETECTION_RULE_CHANGE_ACTION.DISABLE ? <Field label="Validated Version"><Select value={value.versionId ?? undefined} optionList={validated.map((item) => ({ value: item.id, label: `v${item.version} · ${shortHash(item.content_sha256)}` }))} onChange={(versionId) => onChange({ ...value, versionId: Number(versionId) })} /></Field> : null}</div><Field label="Target Sensor IDs"><Input value={value.sensorIds} onChange={(sensorIds) => onChange({ ...value, sensorIds })} /></Field><Field label="Reason"><TextArea value={value.reason} autosize={{ minRows: 4, maxRows: 8 }} onChange={(reason) => onChange({ ...value, reason })} /></Field></div> : null}
  </AppModal>;
}

function DecisionModal({ value, busy, onChange, onCancel, onSubmit }: { value: DecisionFormState | null; busy: boolean; onChange: (value: DecisionFormState | null) => void; onCancel: () => void; onSubmit: () => void }) {
  return <AppModal open={Boolean(value)} title="Confirm Rule Change" titleIcon={<FileCheck2 size={17} />} size="standard" onCancel={onCancel} footer={<><Button onClick={onCancel}>Cancel</Button><Button theme="solid" type={value?.decision === DETECTION_RULE_CHANGE_DECISION.REJECT ? "danger" : "primary"} loading={busy} disabled={!value?.reason.trim()} onClick={onSubmit}>{value ? formatEnumLabel(value.decision) : "Confirm"}</Button></>}>
    {value ? <div className="detection-form"><div className="detection-approval-hash"><span>Action</span><strong>{formatEnumLabel(value.change.action)}</strong><span>Rule Version</span><strong>{value.change.rule_version_id ? `#${value.change.rule_version_id}` : "Disable active version"}</strong><span>Content SHA-256</span><code>{value.change.content_sha256 || "-"}</code><span>Scope / Targets</span><strong>{formatEnumLabel(value.change.scope)} · {value.change.target_sensor_ids.join(", ")}</strong><span>Effective Bundle</span><code>{value.change.effective_bundle_hash}</code></div><Field label="Decision"><Select value={value.decision} optionList={DETECTION_RULE_CHANGE_DECISION_VALUES.map((decision) => ({ value: decision, label: formatEnumLabel(decision) }))} onChange={(decision) => onChange({ ...value, decision: decision as DetectionRuleChangeDecision })} /></Field><Field label="Reason"><TextArea value={value.reason} autosize={{ minRows: 4, maxRows: 8 }} onChange={(reason) => onChange({ ...value, reason })} /></Field></div> : null}
  </AppModal>;
}

function DeploymentsModal({ value, onClose }: { value: { change: DetectionRuleChange; items: DetectionRuleDeployment[] } | null; onClose: () => void }) {
  return (
    <AppModal
      open={Boolean(value)}
      title="Deployment Results"
      titleIcon={<ServerCog size={17} />}
      size="wide"
      onCancel={onClose}
    >
      {value ? (
        <Table
          className="detection-table"
          dataSource={value.items}
          rowKey="id"
          pagination={false}
          empty={<EmptyState className="data-table-empty" compact icon={<ServerCog size={30} />} title="No deployment results" />}
          columns={[
            { title: "Sensor", dataIndex: "sensor_id", width: 90 },
            { title: "Phase", dataIndex: "status", width: 130, render: (status: string) => <OperationalTag value={status} /> },
            { title: "Attempt", dataIndex: "attempt", width: 80 },
            { title: "Bundle", width: 170, render: (_: unknown, item: DetectionRuleDeployment) => <DeploymentBundleCell item={item} /> },
            { title: "Health Proof", width: 210, render: (_: unknown, item: DetectionRuleDeployment) => <DeploymentHealthProof item={item} /> },
            { title: "Timing", width: 170, render: (_: unknown, item: DetectionRuleDeployment) => <div className="detection-primary"><strong>{item.resolved_at ? formatDateTime(item.resolved_at) : "In progress"}</strong><small>{item.started_at ? formatDateTime(item.started_at) : "Not started"}</small></div> },
            { title: "Error", render: (error: string) => error ? <span className="detection-error">{error}</span> : "-" },
          ]}
        />
      ) : null}
    </AppModal>
  );
}

function DeploymentBundleCell({ item }: { item: DetectionRuleDeployment }) {
  const observed = item.rollback_observed_bundle_hash || item.observed_bundle_hash;
  return (
    <div className="detection-primary">
      <strong><code>{shortHash(item.target_bundle_hash)}</code></strong>
      <small>Observed {observed ? shortHash(observed) : "pending"}</small>
    </div>
  );
}

function DeploymentHealthProof({ item }: { item: DetectionRuleDeployment }) {
  const proof = item.rollback_health_snapshot ?? item.health_snapshot;
  if (!proof) return <span>-</span>;
  return (
    <div className="detection-primary">
      <strong><OperationalTag value={proof.status} /></strong>
      <small>Seq {proof.sequence} · {formatDateTime(proof.observed_at)}</small>
      {proof.error ? <small className="detection-error">{proof.error}</small> : null}
    </div>
  );
}

function SensorModal({ value, busy, onChange, onCancel, onSave }: { value: ConfigureManagedHostSensorRequest | null; busy: boolean; onChange: (value: ConfigureManagedHostSensorRequest | null) => void; onCancel: () => void; onSave: () => void }) {
  return <AppModal open={Boolean(value)} title="Configure Managed Host Sensor" titleIcon={<RadioTower size={17} />} size="standard" onCancel={onCancel} footer={<><Button onClick={onCancel}>Cancel</Button><Button theme="solid" type="primary" loading={busy} disabled={!value?.sensor_id || !value.capture_interface || !value.proxy_url || value.proxy_token.length < 16} onClick={onSave}>Save Sensor</Button></>}>
    {value ? <div className="detection-form"><div className="detection-form-grid"><Field label="Managed Host ID"><Input value={String(value.host_id || "")} onChange={(hostId) => onChange({ ...value, host_id: Number(hostId) })} /></Field><Field label="Capture Interface"><Input value={value.capture_interface} onChange={(capture_interface) => onChange({ ...value, capture_interface })} /></Field></div><Field label="Sensor ID"><Input value={value.sensor_id} onChange={(sensor_id) => onChange({ ...value, sensor_id })} /></Field><Field label="Sandbox Proxy URL"><Input value={value.proxy_url} onChange={(proxy_url) => onChange({ ...value, proxy_url })} /></Field><Field label="Sandbox Proxy Token"><Input mode="password" value={value.proxy_token} onChange={(proxy_token) => onChange({ ...value, proxy_token })} /></Field><Field label="Excluded Ports"><Input value={(value.excluded_ports ?? []).join(", ")} onChange={(ports) => onChange({ ...value, excluded_ports: parseIds(ports) })} /></Field></div> : null}
  </AppModal>;
}

function Field({ label, children }: { label: string; children: React.ReactNode }) { return <label className="detection-field"><span>{label}</span>{children}</label>; }
function Metric({ label, value }: { label: string; value: string | number }) { return <div><span>{label}</span><strong>{value}</strong></div>; }
function shortHash(value: string) { return value ? `${value.slice(0, 10)}…${value.slice(-6)}` : "-"; }
function parseIds(value: string) { return Array.from(new Set(value.split(",").map((item) => Number(item.trim())).filter((item) => Number.isInteger(item) && item > 0))); }
function emptySensorForm(): ConfigureManagedHostSensorRequest { return { host_id: 0, sensor_id: "", capture_interface: "", excluded_ports: [22, 2375, 8000], proxy_url: "http://127.0.0.1:8000", proxy_token: "" }; }
