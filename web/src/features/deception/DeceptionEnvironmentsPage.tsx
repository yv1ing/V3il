import { ArrowRight, Network, Radar } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { agentSessionPath } from "../../app/routePaths";
import { createDeceptionEnvironment, queryDeceptionEnvironments } from "../../shared/api/deceptionEnvironments";
import { queryEgressProxies } from "../../shared/api/egressProxies";
import {
  queryAvailableSandboxContainers,
  querySandboxContainerHostOptions,
  querySandboxContainerImageOptions,
} from "../../shared/api/sandboxContainers";
import { DECEPTION_ENVIRONMENT_STATUS } from "../../shared/api/generated/constants";
import type {
  CreateDeceptionEnvironmentResponse,
  DeceptionEnvironment,
  EgressProxy,
  SandboxContainer,
  SandboxContainerHostOption,
  SandboxImage,
} from "../../shared/api/types";
import { PagedResourceTable } from "../../shared/components/PagedResourceTable";
import { ResourceIdentity, ResourceText, RowActionButton, RowActions } from "../../shared/components/ResourceCells";
import type { ResourceColumn } from "../../shared/components/ResourceTable";
import { useAdminResourceHeader } from "../../shared/hooks/useAdminResourceHeader";
import { useOptionList } from "../../shared/hooks/useOptionList";
import { usePagedResourceList } from "../../shared/hooks/usePagedResourceList";
import { useResourceSubmit } from "../../shared/hooks/useResourceSubmit";
import { formatDateTime } from "../../shared/lib/date";
import { OperationalTag } from "../operations/OperationalUi";
import { useAgentSessionContext } from "../playground/AgentSessionProvider";
import { DeceptionEnvironmentFormModal } from "./DeceptionEnvironmentFormModal";

export function DeceptionEnvironmentsPage() {
  const navigate = useNavigate();
  const { refreshSessions, selectSession, syncSessionSummaries } = useAgentSessionContext();
  const environments = usePagedResourceList<DeceptionEnvironment>({ query: queryDeceptionEnvironments });
  const hostQuery = useCallback(
    (params: { page: number; size: number; keyword: string }) => querySandboxContainerHostOptions(params),
    [],
  );
  const containerQuery = useCallback(
    (params: { page: number; size: number; keyword: string }) => queryAvailableSandboxContainers(params),
    [],
  );
  const imageQuery = useCallback(
    (params: { page: number; size: number; keyword: string }) => querySandboxContainerImageOptions(params),
    [],
  );
  const proxyQuery = useCallback(
    (params: { page: number; size: number; keyword: string }) => queryEgressProxies(params),
    [],
  );
  const hosts = useOptionList<SandboxContainerHostOption>({ query: hostQuery });
  const containers = useOptionList<SandboxContainer>({ query: containerQuery });
  const images = useOptionList<SandboxImage>({ query: imageQuery });
  const proxies = useOptionList<EgressProxy>({ query: proxyQuery });
  const [createOpen, setCreateOpen] = useState(false);
  const { saving, submit } = useResourceSubmit<CreateDeceptionEnvironmentResponse>({
    onSuccess: async (response) => {
      setCreateOpen(false);
      await Promise.all([environments.loadItems(), refreshSessions()]);
      const session = response.data?.session;
      if (session) {
        syncSessionSummaries([session]);
        selectSession(session.id);
        navigate(agentSessionPath(session.id));
      }
    },
  });

  useAdminResourceHeader({
    createLabel: "Create Environment",
    refreshLabel: "Refresh deception environments",
    loading: environments.loading,
    onCreate: () => setCreateOpen(true),
    onRefresh: environments.loadItems,
  });

  const summary = useMemo(() => ({
    active: environments.items.filter((environment) => environment.status === DECEPTION_ENVIRONMENT_STATUS.ACTIVE).length,
    adapting: environments.items.filter((environment) => environment.status === DECEPTION_ENVIRONMENT_STATUS.ADAPTING).length,
    services: environments.items.reduce((count, environment) => count + environment.services.length, 0),
  }), [environments.items]);

  const columns: ResourceColumn<DeceptionEnvironment>[] = [
    {
      key: "environment", header: "Environment", width: "minmax(240px, 1.1fr)",
      render: (environment) => <ResourceIdentity icon={<Radar size={18} />} title={environment.name} detail={`Environment ${environment.id} · Host ${environment.host_id} · Image ${environment.image_id}`} />,
    },
    { key: "status", header: "Status", width: "110px", render: (environment) => <OperationalTag value={environment.status} /> },
    {
      key: "description", header: "Description", width: "minmax(220px, 1fr)",
      render: (environment) => <ResourceText title={environment.description}>{environment.description || "Awaiting Console instructions"}</ResourceText>,
    },
    {
      key: "services", header: "Services", width: "minmax(150px, 0.7fr)",
      render: (environment) => <span className="resource-inline-cell"><Network size={13} /> {environment.services.length} exposed</span>,
    },
    {
      key: "baseline",
      header: "Baseline",
      width: "100px",
      render: (environment) => environment.applied_revision_id ? `#${environment.applied_revision_id}` : "Draft",
    },
    { key: "updated", header: "Updated", width: "minmax(150px, 0.7fr)", render: (environment) => formatDateTime(environment.updated_at) },
    {
      key: "actions", header: "", width: "58px",
      render: (environment) => <RowActions><RowActionButton icon={<ArrowRight size={15} />} label={`Open ${environment.name}`} onClick={() => navigate(`/deception-environments/${environment.id}`)} /></RowActions>,
    },
  ];

  return (
    <>
      <PagedResourceTable
        ariaLabel="Deception environments"
        columns={columns}
        rows={environments.items}
        rowKey={(environment) => environment.id}
        searchPlaceholder="Search name, description, or generated persona"
        state={environments}
        metrics={[
          { label: "Total", value: environments.total },
          { label: "Active", value: summary.active },
          { label: "Adapting", value: summary.adapting },
          { label: "Services", value: summary.services },
        ]}
        emptyIcon={<Radar size={42} />}
        emptyTitle="No deception environments found"
      />
      <DeceptionEnvironmentFormModal
        open={createOpen}
        saving={saving}
        containers={containers}
        hosts={hosts}
        images={images}
        proxies={proxies}
        onCancel={() => setCreateOpen(false)}
        onSubmit={(payload) => submit(() => createDeceptionEnvironment(payload))}
      />
    </>
  );
}
