import { Button, Input, InputNumber, Switch } from "@douyinfe/semi-ui";
import { Bot, DatabaseZap, RadioTower, RotateCcw, Save, Settings, ShieldCheck, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { getInstanceConfig, updateInstanceConfig } from "../../shared/api/systemConfig";
import { showApiError, showApiSuccess } from "../../shared/api/feedback";
import { SYSTEM_CONFIG_FIELD_CONSTRAINTS } from "../../shared/api/generated/constants";
import { MetricStrip } from "../../shared/components/ResourcePageShell";
import { AsyncContent } from "../../shared/components/AsyncContent";
import { cx } from "../../shared/lib/className";
import type {
  AgentConfig,
  AgentPoolConfig,
  AgentRuntimeConfig,
  BehaviorCaptureConfig,
  InstanceConfig,
  LightRAGConfig,
  ThreatAutomationConfig,
  UpdateInstanceConfigRequest,
} from "../../shared/api/types";
import { useAdminResourceHeader } from "../../shared/hooks/useAdminResourceHeader";
import { useMountedRef } from "../../shared/hooks/useMountedRef";

type AgentFormValue = AgentConfig;
type AgentRuntimePatch = Partial<Pick<
  AgentConfig,
  "api_key" | "base_url" | "context_window" | "model" | "use_responses"
>>;
type LightRAGFormValue = LightRAGConfig;

type ConfigFormValue = {
  agents: AgentFormValue[];
  agent_pool: AgentPoolConfig;
  agent_runtime: AgentRuntimeConfig;
  behavior_capture: BehaviorCaptureConfig;
  lightrag: LightRAGFormValue;
  threat_automation: ThreatAutomationConfig;
};

type FieldKey<T, Value> = {
  [Key in keyof T]: T[Key] extends Value ? Key : never;
}[keyof T];

type NumberFieldWidth = "compact" | "standard" | "wide" | "fill";

type ConfigField<T> = {
  key: FieldKey<T, number>;
  label: string;
  min?: number;
  max?: number;
  step?: number;
  width?: NumberFieldWidth;
};

type ConfigFieldGroup<T> = {
  title: string;
  fields: ConfigField<T>[];
};

type AgentTextField = {
  key: keyof Pick<AgentConfig, "base_url" | "model" | "api_key">;
  label: string;
  maxLength?: number;
  secret?: boolean;
};

const AGENT_CONSTRAINTS = SYSTEM_CONFIG_FIELD_CONSTRAINTS.AgentConfig;
const POOL_CONSTRAINTS = SYSTEM_CONFIG_FIELD_CONSTRAINTS.AgentPoolConfig;
const RUNTIME_CONSTRAINTS = SYSTEM_CONFIG_FIELD_CONSTRAINTS.AgentRuntimeConfig;
const CAPTURE_CONSTRAINTS = SYSTEM_CONFIG_FIELD_CONSTRAINTS.BehaviorCaptureConfig;
const AUTOMATION_CONSTRAINTS = SYSTEM_CONFIG_FIELD_CONSTRAINTS.ThreatAutomationConfig;
const LIGHTRAG_CONSTRAINTS = SYSTEM_CONFIG_FIELD_CONSTRAINTS.LightRAGConfig;
const RATIO_STEP = 0.01;

const RUNTIME_FIELD_GROUPS: ConfigFieldGroup<AgentRuntimeConfig>[] = [
  {
    title: "Execution",
    fields: [
      { key: "main_max_turns", label: "Main Max Turns", min: RUNTIME_CONSTRAINTS.main_max_turns.minimum },
      { key: "subordinate_max_turns", label: "Subordinate Max Turns", min: RUNTIME_CONSTRAINTS.subordinate_max_turns.minimum },
      { key: "model_stream_idle_timeout_seconds", label: "Stream Idle Timeout", min: RUNTIME_CONSTRAINTS.model_stream_idle_timeout_seconds.minimum },
      { key: "report_retention_seconds", label: "Report Retention Seconds", min: RUNTIME_CONSTRAINTS.report_retention_seconds.minimum },
    ],
  },
  {
    title: "Context Thresholds",
    fields: [
      ratioField("context_budget_model_call_ratio", "Model Call Budget"),
      ratioField("context_compression_trigger_ratio", "Trigger Ratio"),
      ratioField("context_compression_hard_stop_ratio", "Hard Stop Ratio"),
      ratioField("context_compression_target_ratio", "Target Ratio"),
    ],
  },
  {
    title: "Compression Policy",
    fields: [
      ratioField("context_compression_preserve_recent_ratio", "Preserve Recent Ratio"),
      { key: "context_compression_preserve_recent_items", label: "Preserve Recent Items", min: RUNTIME_CONSTRAINTS.context_compression_preserve_recent_items.minimum, width: "compact" },
      { key: "context_compression_min_items", label: "Minimum Items", min: RUNTIME_CONSTRAINTS.context_compression_min_items.minimum, width: "compact" },
      { key: "context_compression_summary_max_tokens", label: "Summary Max Tokens", min: RUNTIME_CONSTRAINTS.context_compression_summary_max_tokens.minimum },
    ],
  },
];

const POOL_FIELDS: ConfigField<AgentPoolConfig>[] = [
  { key: "max_size", label: "Max Size", min: POOL_CONSTRAINTS.max_size.minimum, width: "compact" },
  { key: "ttl_seconds", label: "TTL Seconds", min: POOL_CONSTRAINTS.ttl_seconds.minimum },
  { key: "sweep_interval_seconds", label: "Sweep Interval Seconds", min: POOL_CONSTRAINTS.sweep_interval_seconds.minimum, width: "compact" },
];

const CAPTURE_FIELDS: ConfigField<BehaviorCaptureConfig>[] = [
  { key: "poll_interval_seconds", label: "Poll Interval Seconds", min: CAPTURE_CONSTRAINTS.poll_interval_seconds.minimum, max: CAPTURE_CONSTRAINTS.poll_interval_seconds.maximum, step: 0.1 },
  { key: "batch_size", label: "Batch Size", min: CAPTURE_CONSTRAINTS.batch_size.minimum, max: CAPTURE_CONSTRAINTS.batch_size.maximum },
  { key: "max_batches_per_poll", label: "Max Batches Per Poll", min: CAPTURE_CONSTRAINTS.max_batches_per_poll.minimum, max: CAPTURE_CONSTRAINTS.max_batches_per_poll.maximum },
  { key: "concurrency", label: "Concurrency", min: CAPTURE_CONSTRAINTS.concurrency.minimum, max: CAPTURE_CONSTRAINTS.concurrency.maximum },
];

const AUTOMATION_FIELDS: ConfigField<ThreatAutomationConfig>[] = [
  { key: "correlation_window_seconds", label: "Correlation Window Seconds", min: AUTOMATION_CONSTRAINTS.correlation_window_seconds.minimum, max: AUTOMATION_CONSTRAINTS.correlation_window_seconds.maximum },
  { key: "notification_event_limit", label: "Notification Event Limit", min: AUTOMATION_CONSTRAINTS.notification_event_limit.minimum, max: AUTOMATION_CONSTRAINTS.notification_event_limit.maximum },
];

const AGENT_TEXT_FIELDS: AgentTextField[] = [
  { key: "model", label: "Model" },
  { key: "base_url", label: "Base URL" },
  { key: "api_key", label: "API Key", secret: true },
];

function ratioField(
  key: FieldKey<AgentRuntimeConfig, number>,
  label: string,
): ConfigField<AgentRuntimeConfig> {
  const constraints = RUNTIME_CONSTRAINTS[key as keyof typeof RUNTIME_CONSTRAINTS];
  if (!("exclusiveMinimum" in constraints) || !("exclusiveMaximum" in constraints)) {
    throw new Error(`missing ratio constraints for ${String(key)}`);
  }
  return {
    key,
    label,
    min: constraints.exclusiveMinimum + RATIO_STEP,
    max: constraints.exclusiveMaximum - RATIO_STEP,
    step: RATIO_STEP,
    width: "compact",
  };
}

function toFormValue(config: InstanceConfig): ConfigFormValue {
  if (!config.agent_pool || !config.agent_runtime || !config.behavior_capture || !config.lightrag || !config.threat_automation) {
    throw new Error("instance config is incomplete");
  }
  const agents = Object.values(config.agents ?? {}).map((agent) => ({ ...agent }));
  return {
    agents,
    agent_pool: { ...config.agent_pool },
    agent_runtime: { ...config.agent_runtime },
    behavior_capture: { ...config.behavior_capture },
    lightrag: { ...config.lightrag },
    threat_automation: { ...config.threat_automation },
  };
}

function cloneFormValue(values: ConfigFormValue): ConfigFormValue {
  return {
    agents: values.agents.map((agent) => ({ ...agent })),
    agent_pool: { ...values.agent_pool },
    agent_runtime: { ...values.agent_runtime },
    behavior_capture: { ...values.behavior_capture },
    lightrag: { ...values.lightrag },
    threat_automation: { ...values.threat_automation },
  };
}

function toPayload(values: ConfigFormValue): UpdateInstanceConfigRequest {
  const agents: NonNullable<UpdateInstanceConfigRequest["agents"]> = {};
  values.agents.forEach((agent) => {
    const code = agent.code.trim();
    if (!code) return;
    agents[code] = {
      base_url: agent.base_url.trim(),
      api_key: agent.api_key.trim(),
      model: agent.model.trim(),
      use_responses: agent.use_responses,
      context_window: agent.context_window,
    };
  });
  return {
    agents,
    agent_pool: values.agent_pool,
    agent_runtime: values.agent_runtime,
    behavior_capture: values.behavior_capture,
    lightrag: {
      ...values.lightrag,
      embedding_api: values.lightrag.embedding_api.trim(),
      embedding_key: values.lightrag.embedding_key.trim(),
      embedding_model: values.lightrag.embedding_model.trim(),
      llm_api: values.lightrag.llm_api.trim(),
      llm_key: values.lightrag.llm_key.trim(),
      llm_model: values.lightrag.llm_model.trim(),
    },
    threat_automation: values.threat_automation,
  };
}

export function SystemConfigPage() {
  const [values, setValues] = useState<ConfigFormValue | null>(null);
  const [savedValues, setSavedValues] = useState<ConfigFormValue | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const mountedRef = useMountedRef();
  const loadRequestIdRef = useRef(0);
  const saveRequestIdRef = useRef(0);
  const savingRef = useRef(false);

  useEffect(() => {
    return () => {
      loadRequestIdRef.current += 1;
      saveRequestIdRef.current += 1;
      savingRef.current = false;
    };
  }, []);

  const loadConfig = useCallback(async () => {
    const requestId = loadRequestIdRef.current + 1;
    loadRequestIdRef.current = requestId;
    setLoading(true);
    try {
      const response = await getInstanceConfig();
      if (mountedRef.current && loadRequestIdRef.current === requestId && response.data) {
        const nextValues = toFormValue(response.data);
        setValues(nextValues);
        setSavedValues(cloneFormValue(nextValues));
      }
    } catch (error) {
      if (mountedRef.current && loadRequestIdRef.current === requestId) showApiError(error);
    } finally {
      if (mountedRef.current && loadRequestIdRef.current === requestId) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadConfig();
  }, [loadConfig]);

  const metrics = useMemo(() => {
    const agentCount = values?.agents.length ?? 0;
    return [
      { label: "Agents", value: agentCount },
      { label: "Pool Size", value: values?.agent_pool.max_size ?? "-" },
      { label: "Main Turns", value: values?.agent_runtime.main_max_turns ?? "-" },
      {
        label: "Threat Automation",
        value: values?.threat_automation.enabled ? "Enabled" : "Disabled",
      },
    ];
  }, [values]);

  const updatePool = (patch: Partial<AgentPoolConfig>) => {
    setValues((current) => current && { ...current, agent_pool: { ...current.agent_pool, ...patch } });
  };

  const updateRuntime = (patch: Partial<AgentRuntimeConfig>) => {
    setValues((current) => current && { ...current, agent_runtime: { ...current.agent_runtime, ...patch } });
  };

  const updateLightRAG = (patch: Partial<LightRAGFormValue>) => {
    setValues((current) => current && { ...current, lightrag: { ...current.lightrag, ...patch } });
  };

  const updateBehaviorCapture = (patch: Partial<BehaviorCaptureConfig>) => {
    setValues((current) => current && { ...current, behavior_capture: { ...current.behavior_capture, ...patch } });
  };

  const updateThreatAutomation = (patch: Partial<ThreatAutomationConfig>) => {
    setValues((current) => current && { ...current, threat_automation: { ...current.threat_automation, ...patch } });
  };

  const updateAgent = (code: string, patch: AgentRuntimePatch) => {
    setValues((current) => current && {
      ...current,
      agents: current.agents.map((agent) => (agent.code === code ? { ...agent, ...patch } : agent)),
    });
  };

  const handleCancel = useCallback(() => {
    if (savedValues) setValues(cloneFormValue(savedValues));
  }, [savedValues]);

  const handleSave = useCallback(async () => {
    if (!values || savingRef.current) return;

    savingRef.current = true;
    const requestId = saveRequestIdRef.current + 1;
    saveRequestIdRef.current = requestId;
    setSaving(true);
    try {
      const response = await updateInstanceConfig(toPayload(values));
      if (!mountedRef.current || saveRequestIdRef.current !== requestId) return;
      showApiSuccess(response);
      if (response.data?.config) {
        const nextValues = toFormValue(response.data.config);
        setValues(nextValues);
        setSavedValues(cloneFormValue(nextValues));
      }
    } catch (error) {
      if (mountedRef.current && saveRequestIdRef.current === requestId) showApiError(error);
    } finally {
      if (saveRequestIdRef.current === requestId) {
        savingRef.current = false;
        if (mountedRef.current) setSaving(false);
      }
    }
  }, [values]);

  const headerActions = useMemo(() => (
    <>
      <Button icon={<X size={16} />} type="tertiary" disabled={!savedValues || saving || loading} onClick={handleCancel}>
        Cancel
      </Button>
      <Button icon={<Save size={16} />} theme="solid" type="primary" loading={saving} disabled={!values} onClick={handleSave}>
        Save
      </Button>
    </>
  ), [handleCancel, loading, savedValues, saving, values]);

  useAdminResourceHeader({
    refreshLabel: "Refresh config",
    loading: loading || saving,
    onRefresh: loadConfig,
    extraActions: headerActions,
  });

  return (
    <section className="system-config-page">
      <MetricStrip metrics={metrics} />

      <div className="system-config-workspace">
        <AsyncContent
          loading={loading}
          empty={values === null}
          emptyIcon={<Settings size={42} />}
          emptyTitle="Configuration is unavailable"
          wrapperClassName="system-config-spin"
        >
          {values ? (
            <div className="system-config-layout">
              <ConfigPanel icon={<Settings size={18} />} title="Runtime">
                <RuntimeConfigEditor value={values.agent_runtime} onChange={updateRuntime} />
              </ConfigPanel>

              <ConfigPanel icon={<RotateCcw size={18} />} title="Agent Pool">
                <ConfigFieldGrid fill fields={POOL_FIELDS} values={values.agent_pool} onChange={updatePool} />
              </ConfigPanel>

              <ConfigPanel icon={<RadioTower size={18} />} title="Behavior Capture">
                <ConfigFieldGrid fields={CAPTURE_FIELDS} values={values.behavior_capture} onChange={updateBehaviorCapture} />
              </ConfigPanel>

              <ConfigPanel icon={<ShieldCheck size={18} />} title="Threat Automation">
                <div className="config-grid threat-automation-grid">
                  <Field kind="toggle" label="Automation Enabled" value={values.threat_automation.enabled}
                    onChange={(enabled) => updateThreatAutomation({ enabled })}
                  />
                  <ConfigFieldGrid fill fields={AUTOMATION_FIELDS} values={values.threat_automation} onChange={updateThreatAutomation} />
                </div>
              </ConfigPanel>

              <ConfigPanel icon={<DatabaseZap size={18} />} title="LightRAG">
                <LightRAGConfigEditor value={values.lightrag} onChange={updateLightRAG} />
              </ConfigPanel>

              <ConfigPanel icon={<Bot size={18} />} title="Agents">
                <div className="agent-config-list">
                  {values.agents.map((agent) => (
                    <AgentConfigEditor
                      key={agent.code}
                      agent={agent}
                      onChange={(patch) => updateAgent(agent.code, patch)}
                    />
                  ))}
                </div>
              </ConfigPanel>
            </div>
          ) : null}
        </AsyncContent>
      </div>
    </section>
  );
}

function RuntimeConfigEditor({ value, onChange }: {
  value: AgentRuntimeConfig;
  onChange: (patch: Partial<AgentRuntimeConfig>) => void;
}) {
  return (
    <div className="runtime-config-groups">
      {RUNTIME_FIELD_GROUPS.map((group) => (
        <section key={group.title} className="runtime-config-group">
          <h3>{group.title}</h3>
          <ConfigFieldGrid fields={group.fields} values={value} onChange={onChange} />
        </section>
      ))}
    </div>
  );
}

function LightRAGConfigEditor({ value, onChange }: {
  value: LightRAGFormValue;
  onChange: (patch: Partial<LightRAGFormValue>) => void;
}) {
  return (
    <div className="config-grid lightrag-config-grid">
      <Field kind="text" label="Embedding API" value={value.embedding_api}
        onChange={(embedding_api) => onChange({ embedding_api })} />
      <Field kind="text" label="Embedding Key" value={value.embedding_key} secret
        onChange={(embedding_key) => onChange({ embedding_key })} />
      <Field kind="text" label="Embedding Model" value={value.embedding_model}
        onChange={(embedding_model) => onChange({ embedding_model })} />
      <Field kind="number" label="Embedding Dimension" value={value.embedding_dim}
        width="fill"
        min={LIGHTRAG_CONSTRAINTS.embedding_dim.minimum} max={LIGHTRAG_CONSTRAINTS.embedding_dim.maximum}
        onChange={(embedding_dim) => onChange({ embedding_dim })} />
      <Field kind="text" label="Extraction LLM API" value={value.llm_api}
        onChange={(llm_api) => onChange({ llm_api })} />
      <Field kind="text" label="Extraction LLM Key" value={value.llm_key} secret
        onChange={(llm_key) => onChange({ llm_key })} />
      <Field kind="text" label="Extraction LLM Model" value={value.llm_model}
        onChange={(llm_model) => onChange({ llm_model })} />
      <div className="lightrag-retrieval-fields">
        <Field kind="number" label="Graph Matches" value={value.graph_matches} width="fill"
          min={LIGHTRAG_CONSTRAINTS.graph_matches.minimum} max={LIGHTRAG_CONSTRAINTS.graph_matches.maximum}
          onChange={(graph_matches) => onChange({ graph_matches })} />
        <Field kind="number" label="Chunk Matches" value={value.chunk_matches} width="fill"
          min={LIGHTRAG_CONSTRAINTS.chunk_matches.minimum} max={LIGHTRAG_CONSTRAINTS.chunk_matches.maximum}
          onChange={(chunk_matches) => onChange({ chunk_matches })} />
      </div>
    </div>
  );
}

function ConfigPanel({ children, icon, title }: { children: ReactNode; icon: ReactNode; title: string }) {
  return (
    <div className="config-panel">
      <div className="config-panel-header">
        <div>
          {icon}
          <h2>{title}</h2>
        </div>
      </div>
      {children}
    </div>
  );
}

function ConfigFieldGrid<T extends object>({ fill = false, fields, values, onChange }: {
  fill?: boolean;
  fields: ConfigField<T>[];
  values: T;
  onChange: (patch: Partial<T>) => void;
}) {
  return (
    <div className={cx("config-value-grid", fill && "config-value-grid-fill")}>
      {fields.map((field) => (
        <Field
          key={String(field.key)}
          kind="number"
          label={field.label}
          value={values[field.key] as number}
          min={field.min}
          max={field.max}
          step={field.step}
          width={field.width}
          onChange={(value) => onChange({ [field.key]: value } as Partial<T>)}
        />
      ))}
    </div>
  );
}

function AgentConfigEditor({ agent, onChange }: {
  agent: AgentFormValue;
  onChange: (patch: AgentRuntimePatch) => void;
}) {
  return (
    <div className="agent-config-card">
      <div className="agent-config-card-header">
        <div className="agent-config-identity">
          <strong>{agent.name}</strong>
          <small>{agent.description}</small>
        </div>
        <span>{agent.code}</span>
      </div>
      <div className="agent-form-grid">
        {AGENT_TEXT_FIELDS.map((field) => (
          <Field
            key={field.key}
            kind="text"
            label={field.label}
            value={agent[field.key]}
            maxLength={field.maxLength}
            secret={field.secret}
            onChange={(value) => onChange({ [field.key]: value })}
          />
        ))}
        <Field kind="number" label="Context Window" value={agent.context_window} min={AGENT_CONSTRAINTS.context_window.minimum} width="wide"
          onChange={(context_window) => onChange({ context_window })}
        />
        <Field kind="toggle" label="Use Responses API" value={agent.use_responses}
          onChange={(use_responses) => onChange({ use_responses })}
        />
      </div>
    </div>
  );
}

type FieldProps =
  | { kind: "text"; label: string; value: string; maxLength?: number; secret?: boolean; onChange: (value: string) => void }
  | {
      kind: "number";
      label: string;
      value: number;
      min?: number;
      max?: number;
      step?: number;
      width?: NumberFieldWidth;
      onChange: (value: number) => void;
    }
  | { kind: "toggle"; label: string; value: boolean; onChange: (value: boolean) => void };

function Field(props: FieldProps) {
  const className = cx(
    "field",
    props.kind === "toggle" && "switch-field",
    props.kind === "number" && "number-field",
    props.kind === "number" && `number-field-${props.width ?? "standard"}`,
  );
  return (
    <label className={className}>
      <span>{props.label}</span>
      {props.kind === "text" ? (
        <Input mode={props.secret ? "password" : undefined} value={props.value} maxLength={props.maxLength} onChange={props.onChange} />
      ) : props.kind === "number" ? (
        <InputNumber
          value={props.value}
          min={props.min}
          max={props.max}
          step={props.step}
          onChange={(next) => typeof next === "number" && props.onChange(next)}
        />
      ) : (
        <Switch checked={props.value} onChange={props.onChange} aria-label={props.label} />
      )}
    </label>
  );
}
