import { ArrowRight, Fingerprint, ShieldAlert } from "lucide-react";
import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { THREAT_INCIDENT_STATUS, THREAT_SEVERITY } from "../../shared/api/generated/constants";
import { queryThreatIncidents } from "../../shared/api/threatIncidents";
import type { ThreatIncident } from "../../shared/api/types";
import { PagedResourceTable } from "../../shared/components/PagedResourceTable";
import { ResourceIdentity, ResourceText, RowActionButton, RowActions } from "../../shared/components/ResourceCells";
import type { ResourceColumn } from "../../shared/components/ResourceTable";
import { useAdminResourceHeader } from "../../shared/hooks/useAdminResourceHeader";
import { usePagedResourceList } from "../../shared/hooks/usePagedResourceList";
import { formatDateTime } from "../../shared/lib/date";
import { OperationalTag, RiskScore } from "../operations/OperationalUi";

export function IncidentsPage() {
  const navigate = useNavigate();
  const incidents = usePagedResourceList<ThreatIncident>({ query: queryThreatIncidents });

  useAdminResourceHeader({
    refreshLabel: "Refresh threat incidents",
    loading: incidents.loading,
    onRefresh: incidents.loadItems,
  });

  const summary = useMemo(() => ({
    active: incidents.items.filter((incident) => incident.status !== THREAT_INCIDENT_STATUS.CLOSED).length,
    engaging: incidents.items.filter((incident) => incident.status === THREAT_INCIDENT_STATUS.ENGAGING).length,
    critical: incidents.items.filter((incident) => incident.severity === THREAT_SEVERITY.CRITICAL).length,
  }), [incidents.items]);

  const columns: ResourceColumn<ThreatIncident>[] = [
    {
      key: "incident",
      header: "Incident",
      width: "minmax(250px, 1.2fr)",
      render: (incident) => (
        <ResourceIdentity
          icon={<ShieldAlert size={18} />}
          title={incident.title}
          detail={`INC-${String(incident.id).padStart(5, "0")} · ${incident.source_ips.join(", ") || "Source unknown"}`}
        />
      ),
    },
    { key: "severity", header: "Severity", width: "100px", render: (incident) => <OperationalTag value={incident.severity} /> },
    { key: "status", header: "Status", width: "110px", render: (incident) => <OperationalTag value={incident.status} /> },
    {
      key: "fingerprint",
      header: "Attacker",
      width: "minmax(190px, 0.9fr)",
      render: (incident) => <span className="resource-inline-cell"><Fingerprint size={13} /><ResourceText title={incident.primary_fingerprint}>{incident.primary_fingerprint || "Not established"}</ResourceText></span>,
    },
    { key: "risk", header: "Risk", width: "130px", render: (incident) => <RiskScore value={incident.risk_score} /> },
    { key: "observed", header: "Last observed", width: "170px", render: (incident) => formatDateTime(incident.last_observed_at) },
    {
      key: "actions",
      header: "",
      width: "58px",
      render: (incident) => (
        <RowActions><RowActionButton icon={<ArrowRight size={15} />} label={`Open ${incident.title}`} onClick={() => navigate(`/incidents/${incident.id}`)} /></RowActions>
      ),
    },
  ];

  return (
    <PagedResourceTable
      ariaLabel="Threat incidents"
      columns={columns}
      rows={incidents.items}
      rowKey={(incident) => incident.id}
      searchPlaceholder="Search title, summary, or attacker fingerprint"
      state={incidents}
      metrics={[
        { label: "Total", value: incidents.total },
        { label: "Active", value: summary.active },
        { label: "Engaging", value: summary.engaging },
        { label: "Critical", value: summary.critical },
      ]}
      emptyIcon={<ShieldAlert size={42} />}
      emptyTitle="No threat incidents detected"
    />
  );
}
