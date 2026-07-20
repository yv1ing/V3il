import { Button } from "@douyinfe/semi-ui";
import { Activity, ArrowRight, Bot, Radar, ServerCog, ShieldAlert } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listAgents } from "../../shared/api/agents";
import { queryDeceptionEnvironments } from "../../shared/api/deceptionEnvironments";
import { showApiError } from "../../shared/api/feedback";
import { collectAllPages } from "../../shared/api/pagination";
import { DECEPTION_ENVIRONMENT_STATUS, PAGINATION_MAXIMUM_PAGE_SIZE, THREAT_INCIDENT_STATUS, THREAT_SEVERITY } from "../../shared/api/generated/constants";
import { queryThreatIncidents } from "../../shared/api/threatIncidents";
import type { AgentInfo, DeceptionEnvironment, ThreatIncident } from "../../shared/api/types";
import { AsyncContent } from "../../shared/components/AsyncContent";
import { MetricStrip } from "../../shared/components/ResourcePageShell";
import { useAdminResourceHeader } from "../../shared/hooks/useAdminResourceHeader";
import { formatDateTime } from "../../shared/lib/date";
import { EmptyOperationalState, OperationalSection, OperationalTag, RiskScore } from "../operations/OperationalUi";

type CommandCenterData = {
  incidents: ThreatIncident[];
  incidentTotal: number;
  environments: DeceptionEnvironment[];
  environmentTotal: number;
  agents: AgentInfo[];
};

const EMPTY_DATA: CommandCenterData = {
  incidents: [],
  incidentTotal: 0,
  environments: [],
  environmentTotal: 0,
  agents: [],
};

export function CommandCenterPage() {
  const navigate = useNavigate();
  const [data, setData] = useState<CommandCenterData>(EMPTY_DATA);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [incidentResponse, environmentResponse, agentResponse] = await Promise.all([
        collectAllPages<ThreatIncident>((page) => queryThreatIncidents({ page, size: PAGINATION_MAXIMUM_PAGE_SIZE, keyword: "" })),
        collectAllPages<DeceptionEnvironment>((page) => queryDeceptionEnvironments({ page, size: PAGINATION_MAXIMUM_PAGE_SIZE, keyword: "" })),
        listAgents(),
      ]);
      setData({
        incidents: incidentResponse,
        incidentTotal: incidentResponse.length,
        environments: environmentResponse,
        environmentTotal: environmentResponse.length,
        agents: agentResponse.items,
      });
    } catch (error) {
      showApiError(error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useAdminResourceHeader({
    refreshLabel: "Refresh command center",
    loading,
    onRefresh: load,
  });

  const metrics = useMemo(() => {
    const openIncidents = data.incidents.filter((incident) => incident.status !== THREAT_INCIDENT_STATUS.CLOSED).length;
    const criticalIncidents = data.incidents.filter((incident) => incident.severity === THREAT_SEVERITY.CRITICAL).length;
    const activeEnvironments = data.environments.filter((environment) => environment.status === DECEPTION_ENVIRONMENT_STATUS.ACTIVE).length;
    return [
      { label: "Open Incidents", value: openIncidents },
      { label: "Critical", value: criticalIncidents },
      { label: "Active Deceptions", value: activeEnvironments },
      { label: "Expert Agents", value: data.agents.length },
    ];
  }, [data]);

  return (
    <section className="command-center">
      <MetricStrip metrics={metrics} />
      <div className="command-center-grid">
        <OperationalSection
          title="Incident Queue"
          count={data.incidentTotal}
          actions={<Button theme="borderless" icon={<ArrowRight size={15} />} onClick={() => navigate("/incidents")}>Open queue</Button>}
        >
          <AsyncContent loading={loading} empty={data.incidents.length === 0} emptyContent={<EmptyOperationalState icon={<ShieldAlert size={24} />} label="No incidents detected" />}>
            <div className="operational-list">
              {data.incidents.slice(0, 8).map((incident) => (
                <button key={incident.id} type="button" className="operational-list-row" onClick={() => navigate(`/incidents/${incident.id}`)}>
                  <span className="operational-row-icon"><ShieldAlert size={17} /></span>
                  <span className="operational-row-main">
                    <strong>{incident.title}</strong>
                    <small>{incident.source_ips.join(", ") || incident.primary_fingerprint || "Unattributed source"} · {formatDateTime(incident.last_observed_at)}</small>
                  </span>
                  <OperationalTag value={incident.severity} />
                  <OperationalTag value={incident.status} />
                  <RiskScore value={incident.risk_score} />
                </button>
              ))}
            </div>
          </AsyncContent>
        </OperationalSection>

        <OperationalSection
          title="Deception Readiness"
          count={data.environmentTotal}
          actions={<Button theme="borderless" icon={<ArrowRight size={15} />} onClick={() => navigate("/deception-environments")}>Open environments</Button>}
        >
          <AsyncContent loading={loading} empty={data.environments.length === 0} emptyContent={<EmptyOperationalState icon={<ServerCog size={24} />} label="No deception environments" />}>
            <div className="operational-list operational-list-compact">
              {data.environments.slice(0, 8).map((environment) => (
                <button key={environment.id} type="button" className="operational-list-row" onClick={() => navigate(`/deception-environments/${environment.id}`)}>
                  <span className="operational-row-icon"><Radar size={17} /></span>
                  <span className="operational-row-main">
                    <strong>{environment.name}</strong>
                    <small>{environment.services.length} services · baseline {environment.applied_revision_id ? `#${environment.applied_revision_id}` : "not applied"}</small>
                  </span>
                  <OperationalTag value={environment.status} />
                </button>
              ))}
            </div>
          </AsyncContent>
        </OperationalSection>
      </div>

      <OperationalSection title="Autonomous Defense Team" count={data.agents.length}>
        {data.agents.length === 0 ? (
          <EmptyOperationalState icon={<Bot size={24} />} label="No agents registered" />
        ) : (
          <div className="agent-roster">
            {data.agents.map((agent) => (
              <div className="agent-roster-item" key={agent.code}>
                <span><Bot size={17} /></span>
                <div><strong>{agent.name}</strong><small>{agent.code.toUpperCase()} · {agent.description || "Security specialist"}</small></div>
                <i><Activity size={13} /> Ready</i>
              </div>
            ))}
          </div>
        )}
      </OperationalSection>
    </section>
  );
}
