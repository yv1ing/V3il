import { Button, Popconfirm, Tooltip } from "@douyinfe/semi-ui";
import {
  Activity,
  Bot,
  Box,
  CircleMinus,
  FolderOpen,
  Pause,
  Play,
  Plus,
  RotateCcw,
  ShieldAlert,
  SquareStop,
  SquareTerminal,
} from "lucide-react";
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useNavigate, useParams } from "react-router-dom";
import "../../app/styles/playground.css";
import { useAdminHeaderActions } from "../../app/layouts/AdminLayout";
import { AGENT_CONSOLE_PATH, agentSessionPath } from "../../app/routePaths";
import { showApiError, showApiSuccess } from "../../shared/api/feedback";
import { SANDBOX_CONTAINER_STATUS } from "../../shared/api/generated/constants";
import {
  canManageSandboxContainer,
  pauseSandboxContainer,
  queryAvailableSandboxContainers,
  removeSandboxContainer,
  resumeSandboxContainer,
  startSandboxContainer,
  stopSandboxContainer,
} from "../../shared/api/sandboxContainers";
import type { AgentInputPart, SandboxContainer } from "../../shared/api/types";
import { useOptionList } from "../../shared/hooks/useOptionList";
import { cx } from "../../shared/lib/className";
import { UI_TEXT } from "../../shared/lib/uiText";
import { useContainerShell } from "../container-shell/ContainerShellProvider";
import { SandboxContainerFormModal } from "../sandbox-containers/SandboxContainerFormModal";
import { useAgentSessionContext, type AgentSessionConnectionStatus } from "./AgentSessionProvider";
import { ChatStream } from "./ChatStream";
import { Composer } from "./Composer";
import { MessageScrollPanel } from "./MessageScrollPanel";
import { SandboxSelector } from "./SandboxSelector";

type SandboxActionButtonProps = {
  ariaLabel: string;
  disabled: boolean;
  icon: ReactNode;
  loading?: boolean;
  tooltip: string;
  onClick: () => void;
};

const STATUS_LABEL: Record<AgentSessionConnectionStatus, string> = {
  open: "Live",
  connecting: "Connecting",
  closed: "Disconnected",
  idle: "Idle",
};

export function PlaygroundPage() {
  const setHeaderActions = useAdminHeaderActions();
  const {
    activeSessionId, activeSessionSummary, invalidSessionId, selectSession,
    refreshSessions,
    chatState, status, historyLoading, historyHasMore, historyPrepending, historyVersion,
    agents, activeAgentCode, setActiveAgentCode,
    send, updateSelectedSandboxContainer, interrupt, cancelAll, loadPreviousHistory,
  } = useAgentSessionContext();
  const navigate = useNavigate();
  const { sessionId: routeSessionId } = useParams<{ sessionId?: string }>();
  const [managedSandboxContainerId, setManagedSandboxContainerId] = useState<number | null>(null);
  const [agentSandboxContainerId, setAgentSandboxContainerId] = useState<number | null>(null);
  const [createSandboxOpen, setCreateSandboxOpen] = useState(false);
  const [sandboxAction, setSandboxAction] = useState<string | null>(null);
  const activeSessionIdRef = useRef(activeSessionId);
  const sandboxOperationRef = useRef({ busy: false, generation: 0 });
  activeSessionIdRef.current = activeSessionId;
  const { openFileManager, openShell, syncContainerWindows } = useContainerShell();
  const capabilities = activeSessionSummary?.capabilities;
  const sessionSummaryPending = Boolean(activeSessionId && !activeSessionSummary);
  const canSelectSandbox = !activeSessionId || Boolean(capabilities?.can_select_sandbox_container);
  const composerDisabled = historyLoading
    || sessionSummaryPending
    || Boolean(activeSessionId && !capabilities?.can_submit_turn);
  const composerDisabledReason = historyLoading
    ? "Loading conversation history..."
    : sessionSummaryPending
      ? "Loading session state..."
      : capabilities?.turn_block_reason || "This session cannot accept a new turn";
  const sandboxOperationBusy = sandboxAction !== null;

  const activeIncidentId = activeSessionSummary?.incident_id ?? null;
  const querySandboxOptions = useCallback((params: { page: number; size: number; keyword: string }) => (
    queryAvailableSandboxContainers({
      ...params,
      include_non_running: true,
    })
  ), []);
  const sandboxOptions = useOptionList<SandboxContainer>({ query: querySandboxOptions });
  const availableSandboxContainers = sandboxOptions.items;
  const knownSandboxContainers = sandboxOptions.knownItems;
  const selectableSandboxContainers = availableSandboxContainers;
  const agentSandboxContainers = availableSandboxContainers.filter(
    (container) => container.status === SANDBOX_CONTAINER_STATUS.RUNNING,
  );
  const selectedSandboxContainer = useMemo(
    () => findSandboxContainerById(knownSandboxContainers, managedSandboxContainerId),
    [knownSandboxContainers, managedSandboxContainerId],
  );
  const sandboxAccessUnavailableReason = getSandboxAccessUnavailableReason(selectedSandboxContainer);
  const sandboxManageUnavailableReason = sandboxAccessUnavailableReason ? "No permission to operate this sandbox" : null;
  const shellUnavailableReason = sandboxAccessUnavailableReason
    ?? getSandboxActionUnavailableReason(selectedSandboxContainer, { requiresControlProxy: true });
  const selectedSandboxName = selectedSandboxContainer?.container_name ?? "selected sandbox";
  const selectedSandboxActionId = selectedSandboxContainer?.id ?? 0;
  const canStartSelectedSandbox = Boolean(!sandboxManageUnavailableReason && selectedSandboxContainer && (
    selectedSandboxContainer.status === SANDBOX_CONTAINER_STATUS.CREATED
    || selectedSandboxContainer.status === SANDBOX_CONTAINER_STATUS.STOPPED
  ));
  const canStopSelectedSandbox = !sandboxManageUnavailableReason
    && selectedSandboxContainer?.status === SANDBOX_CONTAINER_STATUS.RUNNING;
  const canPauseSelectedSandbox = !sandboxManageUnavailableReason
    && selectedSandboxContainer?.status === SANDBOX_CONTAINER_STATUS.RUNNING;
  const canResumeSelectedSandbox = !sandboxManageUnavailableReason
    && selectedSandboxContainer?.status === SANDBOX_CONTAINER_STATUS.PAUSED;
  const canRemoveSelectedSandbox = Boolean(
    !sandboxOperationBusy
    && selectedSandboxContainer
    && !sandboxManageUnavailableReason,
  );
  const openSelectedFileManager = useCallback(() => {
    if (selectedSandboxContainer) openFileManager(selectedSandboxContainer);
  }, [openFileManager, selectedSandboxContainer]);

  const openSelectedShell = useCallback(() => {
    if (selectedSandboxContainer) openShell(selectedSandboxContainer);
  }, [openShell, selectedSandboxContainer]);

  useEffect(() => {
    if (routeSessionId) {
      selectSession(routeSessionId, { navigateBlank: false });
      return;
    }
    selectSession(null);
  }, [routeSessionId, selectSession]);

  useEffect(() => {
    if (routeSessionId && invalidSessionId === routeSessionId) {
      navigate(AGENT_CONSOLE_PATH, { replace: true });
    }
  }, [invalidSessionId, navigate, routeSessionId]);

  useEffect(() => {
    const selectedId = activeSessionSummary?.selected_sandbox_container_id ?? null;
    setAgentSandboxContainerId(selectedId);
    if (selectedId !== null) setManagedSandboxContainerId(selectedId);
  }, [activeSessionSummary?.selected_sandbox_container_id]);

  useEffect(() => {
    sandboxOperationRef.current.generation += 1;
    sandboxOperationRef.current.busy = false;
    setSandboxAction(null);
  }, [activeSessionId]);

  useEffect(() => {
    syncContainerWindows(selectedSandboxContainer);
  }, [
    activeSessionId,
    selectedSandboxContainer?.id,
    selectedSandboxContainer?.control_proxy_host_port,
    selectedSandboxContainer?.status,
    syncContainerWindows,
  ]);

  const changeManagedSandboxContainer = useCallback((nextContainerId: number | null) => {
    setManagedSandboxContainerId(nextContainerId);
    syncContainerWindows(findSandboxContainerById(selectableSandboxContainers, nextContainerId));
  }, [selectableSandboxContainers, syncContainerWindows]);

  const changeAgentSandboxContainer = useCallback(async (nextContainerId: number | null) => {
    if (nextContainerId !== null && !findSandboxContainerById(agentSandboxContainers, nextContainerId)) return;
    if (!activeSessionId) {
      setAgentSandboxContainerId(nextContainerId);
      return;
    }
    const operation = beginSandboxOperation(sandboxOperationRef, activeSessionId, "select", setSandboxAction);
    if (!operation) return;
    try {
      const summary = await updateSelectedSandboxContainer(activeSessionId, nextContainerId);
      if (!isCurrentSandboxOperation(sandboxOperationRef, activeSessionIdRef, operation)) return;
      const selectedId = summary?.selected_sandbox_container_id ?? null;
      setAgentSandboxContainerId(selectedId);
    } catch (error) {
      if (isCurrentSandboxOperation(sandboxOperationRef, activeSessionIdRef, operation)) showApiError(error);
    } finally {
      finishSandboxOperation(sandboxOperationRef, operation, setSandboxAction);
    }
  }, [activeSessionId, agentSandboxContainers, updateSelectedSandboxContainer]);

  const handleSandboxCreated = useCallback(async (container: SandboxContainer) => {
    setCreateSandboxOpen(false);
    sandboxOptions.updateItems((current) => upsertSandboxContainer(current, container));
    setManagedSandboxContainerId(container.id);
    syncContainerWindows(container);
  }, [
    sandboxOptions.updateItems,
    syncContainerWindows,
  ]);

  const runSandboxMutation = useCallback(async (
    action: "start" | "stop" | "pause" | "resume",
    container: SandboxContainer | null,
  ) => {
    if (!container) return;
    const actionKey = `${action}:${container.id}`;
    const operation = beginSandboxOperation(sandboxOperationRef, activeSessionId, actionKey, setSandboxAction);
    if (!operation) return;
    try {
      const response = action === "start"
        ? await startSandboxContainer(container.id)
        : action === "stop"
          ? await stopSandboxContainer(container.id)
          : action === "pause"
          ? await pauseSandboxContainer(container.id)
            : await resumeSandboxContainer(container.id);
      if (!isCurrentSandboxOperation(sandboxOperationRef, activeSessionIdRef, operation)) return;
      showApiSuccess(response);
      const updatedContainer = response.data;
      if (updatedContainer) {
        sandboxOptions.updateItems((current) => upsertSandboxContainer(current, updatedContainer));
        setManagedSandboxContainerId(updatedContainer.id);
        syncContainerWindows(updatedContainer);
        if (
          updatedContainer.status !== SANDBOX_CONTAINER_STATUS.RUNNING
        ) {
          if (updatedContainer.id === agentSandboxContainerId) setAgentSandboxContainerId(null);
          await refreshSessions();
        }
      }
    } catch (error) {
      if (isCurrentSandboxOperation(sandboxOperationRef, activeSessionIdRef, operation)) showApiError(error);
    } finally {
      finishSandboxOperation(sandboxOperationRef, operation, setSandboxAction);
    }
  }, [activeSessionId, agentSandboxContainerId, refreshSessions, sandboxOptions.updateItems, syncContainerWindows]);

  const removeSelectedSandboxContainer = useCallback(async () => {
    if (!selectedSandboxContainer) return;
    const actionKey = `remove:${selectedSandboxContainer.id}`;
    const operation = beginSandboxOperation(sandboxOperationRef, activeSessionId, actionKey, setSandboxAction);
    if (!operation) return;
    try {
      const response = await removeSandboxContainer(selectedSandboxContainer.id);
      if (!isCurrentSandboxOperation(sandboxOperationRef, activeSessionIdRef, operation)) return;
      showApiSuccess(response);
      sandboxOptions.updateItems((current) => current.filter((container) => container.id !== selectedSandboxContainer.id));
      setManagedSandboxContainerId(null);
      if (agentSandboxContainerId === selectedSandboxContainer.id) setAgentSandboxContainerId(null);
      syncContainerWindows(null);
      await refreshSessions();
    } catch (error) {
      if (isCurrentSandboxOperation(sandboxOperationRef, activeSessionIdRef, operation)) showApiError(error);
    } finally {
      finishSandboxOperation(sandboxOperationRef, operation, setSandboxAction);
    }
  }, [activeSessionId, agentSandboxContainerId, refreshSessions, sandboxOptions.updateItems, selectedSandboxContainer, syncContainerWindows]);

  const headerNode = useMemo(() => (
    <>
      <SandboxSelector
        containers={selectableSandboxContainers}
        source={sandboxOptions}
        value={managedSandboxContainerId}
        className="sandbox-selector-topbar"
        disabled={sandboxOperationBusy}
        placeholder="Manage sandbox"
        emptyContent="No manageable sandbox"
        ariaLabel="Manage sandbox container"
        onChange={changeManagedSandboxContainer}
      />
      <SandboxSelector
        containers={agentSandboxContainers}
        source={sandboxOptions}
        value={agentSandboxContainerId}
        className="sandbox-selector-topbar"
        disabled={sandboxOperationBusy || !canSelectSandbox}
        prefix={<Bot size={15} />}
        placeholder="Agent sandbox"
        emptyContent="No running sandbox"
        ariaLabel="Select Agent sandbox container"
        onChange={(id) => void changeAgentSandboxContainer(id)}
      />
      <div className="sandbox-container-actions" aria-label="Selected sandbox actions">
        <SandboxActionButton
          ariaLabel="Create sandbox container"
          disabled={false}
          icon={<Box size={15} />}
          tooltip="Create sandbox container"
          onClick={() => setCreateSandboxOpen(true)}
        />
        <SandboxActionButton
          ariaLabel={`Start ${selectedSandboxName}`}
          disabled={sandboxOperationBusy || !canStartSelectedSandbox}
          icon={<Play size={15} />}
          loading={sandboxAction === `start:${selectedSandboxActionId}`}
          tooltip={sandboxManageUnavailableReason ?? (canStartSelectedSandbox ? `Start ${selectedSandboxName}` : "Select a created or stopped sandbox")}
          onClick={() => void runSandboxMutation("start", selectedSandboxContainer)}
        />
        <SandboxActionButton
          ariaLabel={`Stop ${selectedSandboxName}`}
          disabled={sandboxOperationBusy || !canStopSelectedSandbox}
          icon={<SquareStop size={15} />}
          loading={sandboxAction === `stop:${selectedSandboxActionId}`}
          tooltip={sandboxManageUnavailableReason ?? (canStopSelectedSandbox ? `Stop ${selectedSandboxName}` : "Select a running sandbox")}
          onClick={() => void runSandboxMutation("stop", selectedSandboxContainer)}
        />
        <SandboxActionButton
          ariaLabel={`Pause ${selectedSandboxName}`}
          disabled={sandboxOperationBusy || !canPauseSelectedSandbox}
          icon={<Pause size={15} />}
          loading={sandboxAction === `pause:${selectedSandboxActionId}`}
          tooltip={sandboxManageUnavailableReason ?? (canPauseSelectedSandbox ? `Pause ${selectedSandboxName}` : "Select a running sandbox")}
          onClick={() => void runSandboxMutation("pause", selectedSandboxContainer)}
        />
        <SandboxActionButton
          ariaLabel={`Resume ${selectedSandboxName}`}
          disabled={sandboxOperationBusy || !canResumeSelectedSandbox}
          icon={<RotateCcw size={15} />}
          loading={sandboxAction === `resume:${selectedSandboxActionId}`}
          tooltip={sandboxManageUnavailableReason ?? (canResumeSelectedSandbox ? `Resume ${selectedSandboxName}` : "Select a paused sandbox")}
          onClick={() => void runSandboxMutation("resume", selectedSandboxContainer)}
        />
        {canRemoveSelectedSandbox ? (
          <Popconfirm
            title="Remove container"
            content={`Remove ${selectedSandboxContainer?.container_name}?`}
            okType="danger"
            cancelText={UI_TEXT.cancel}
            onConfirm={() => void removeSelectedSandboxContainer()}
          >
            <span>
              <SandboxActionButton
                ariaLabel={`Remove ${selectedSandboxName}`}
                disabled={false}
                icon={<CircleMinus size={15} />}
                loading={sandboxAction === `remove:${selectedSandboxActionId}`}
                tooltip={`Remove ${selectedSandboxName}`}
                onClick={() => undefined}
              />
            </span>
          </Popconfirm>
        ) : (
          <SandboxActionButton
            ariaLabel={`Remove ${selectedSandboxName}`}
            disabled
            icon={<CircleMinus size={15} />}
            loading={sandboxAction === `remove:${selectedSandboxActionId}`}
            tooltip={sandboxManageUnavailableReason ?? (selectedSandboxContainer ? `Remove ${selectedSandboxName}` : "Select a sandbox first")}
            onClick={() => undefined}
          />
        )}
        <SandboxActionButton
          ariaLabel={`Open terminal for ${selectedSandboxName}`}
          disabled={Boolean(shellUnavailableReason)}
          icon={<SquareTerminal size={15} />}
          tooltip={shellUnavailableReason ?? `Open terminal for ${selectedSandboxName}`}
          onClick={openSelectedShell}
        />
        <SandboxActionButton
          ariaLabel={`Browse files for ${selectedSandboxName}`}
          disabled={Boolean(shellUnavailableReason)}
          icon={<FolderOpen size={15} />}
          tooltip={shellUnavailableReason ?? `Browse files for ${selectedSandboxName}`}
          onClick={openSelectedFileManager}
        />
        {activeIncidentId ? (
          <SandboxActionButton
            ariaLabel="Open incident workspace"
            disabled={false}
            icon={<ShieldAlert size={15} />}
            tooltip="Open incident workspace"
            onClick={() => navigate(`/incidents/${activeIncidentId}`)}
          />
        ) : null}
      </div>
      <Button
        icon={<Plus size={16} />}
        theme="solid"
        type="primary"
        onClick={() => {
          selectSession(null);
          navigate(AGENT_CONSOLE_PATH);
        }}
      >
        New chat
      </Button>
      <span className={cx("stream-status", `stream-status-${status}`)}>
        <Activity size={14} />
        <span>{STATUS_LABEL[status]}</span>
      </span>
    </>
  ), [
    activeIncidentId,
    canPauseSelectedSandbox,
    canRemoveSelectedSandbox,
    canResumeSelectedSandbox,
    canStartSelectedSandbox,
    canStopSelectedSandbox,
    canSelectSandbox,
    changeAgentSandboxContainer,
    changeManagedSandboxContainer,
    removeSelectedSandboxContainer,
    openSelectedFileManager,
    openSelectedShell,
    runSandboxMutation,
    sandboxAction,
    sandboxManageUnavailableReason,
    sandboxOperationBusy,
    agentSandboxContainerId,
    agentSandboxContainers,
    managedSandboxContainerId,
    selectableSandboxContainers,
    sandboxOptions,
    selectSession,
    selectedSandboxActionId,
    selectedSandboxContainer,
    selectedSandboxName,
    shellUnavailableReason,
    status,
    navigate,
  ]);

  useLayoutEffect(() => {
    setHeaderActions(headerNode);
    return () => setHeaderActions(null);
  }, [headerNode, setHeaderActions]);

  const handleSend = async (content: AgentInputPart[]) => {
    try {
      const session = await send(content, activeSessionId, agentSandboxContainerId);
      navigate(agentSessionPath(session.id), { replace: activeSessionId == null });
      return true;
    } catch {
      return false;
    }
  };

  return (
    <div className="playground-shell">
      <div className="playground-main">
        <div className="playground-conversation-frame">
          <div className="playground-main-column">
            <MessageScrollPanel
              ariaLabel="Conversation messages"
              className="playground-canvas-shell"
              contentClassName="playground-canvas"
              loading={historyLoading}
              loadingPrevious={historyPrepending}
              onLoadPrevious={historyHasMore && !historyPrepending ? () => void loadPreviousHistory() : undefined}
              preserveScrollKey={historyVersion}
              resetKey={activeSessionId ?? "new-chat"}
              scrollButtonClassName="chat-scroll-tail-floating"
              watch={[chatState.nodes, chatState.streaming]}
            >
              {(tailRef) => (
                <ChatStream
                  nodes={chatState.nodes}
                  streaming={chatState.streaming}
                  agents={agents}
                  tailRef={tailRef}
                />
              )}
            </MessageScrollPanel>
            <div className="playground-composer">
              <Composer
                streaming={chatState.streaming}
                disabled={composerDisabled}
                disabledReason={composerDisabledReason}
                agents={agents}
                activeAgentCode={activeAgentCode}
                agentSwitchDisabled={Boolean(activeSessionId && !capabilities?.can_switch_agent)}
                agentSwitchDisabledReason={capabilities?.turn_block_reason || "Agent switching is unavailable for this session"}
                canInterrupt={Boolean(capabilities?.can_interrupt)}
                canCancelAll={Boolean(capabilities?.can_cancel_all)}
                onPickAgent={setActiveAgentCode}
                onSend={handleSend}
                onInterrupt={() => void interrupt()}
                onCancelAll={() => void cancelAll()}
              />
            </div>
          </div>
        </div>
      </div>
      <SandboxContainerFormModal
        open={createSandboxOpen}
        onCancel={() => setCreateSandboxOpen(false)}
        onCreated={handleSandboxCreated}
      />
    </div>
  );
}

function SandboxActionButton({ ariaLabel, disabled, icon, loading = false, onClick, tooltip }: SandboxActionButtonProps) {
  return (
    <Tooltip content={tooltip}>
      <span className="sandbox-action-tooltip">
        <Button
          aria-label={ariaLabel}
          className="sandbox-action-button"
          disabled={disabled}
          icon={icon}
          loading={loading}
          theme="borderless"
          type="tertiary"
          onClick={onClick}
        />
      </span>
    </Tooltip>
  );
}

function getSandboxActionUnavailableReason(
  container: SandboxContainer | null,
  options: { requiresControlProxy?: boolean },
) {
  if (!container) return "Select a sandbox first";
  if (container.status !== SANDBOX_CONTAINER_STATUS.RUNNING) return "Selected sandbox is not running";
  if (options.requiresControlProxy && container.control_proxy_host_port <= 0) return "Selected sandbox control port is not ready";
  return null;
}

function getSandboxAccessUnavailableReason(
  container: SandboxContainer | null,
) {
  if (!container) return null;
  if (canManageSandboxContainer(container)) return null;
  return "No permission to access this sandbox";
}

function upsertSandboxContainer(containers: SandboxContainer[], nextContainer: SandboxContainer) {
  if (!containers.some((container) => container.id === nextContainer.id)) {
    return [nextContainer, ...containers];
  }
  return containers.map((container) => (
    container.id === nextContainer.id ? nextContainer : container
  ));
}

function findSandboxContainerById(containers: SandboxContainer[], id: number | null) {
  if (id === null) return null;
  return containers.find((container) => container.id === id) ?? null;
}

type SandboxOperation = {
  generation: number;
  sessionId: string | null;
};

type SandboxOperationState = {
  busy: boolean;
  generation: number;
};

function beginSandboxOperation(
  operationRef: { current: SandboxOperationState },
  sessionId: string | null,
  action: string,
  setAction: (action: string | null) => void,
): SandboxOperation | null {
  if (operationRef.current.busy) return null;
  const generation = operationRef.current.generation + 1;
  operationRef.current = { busy: true, generation };
  setAction(action);
  return { generation, sessionId };
}

function isCurrentSandboxOperation(
  operationRef: { current: SandboxOperationState },
  activeSessionIdRef: { current: string | null },
  operation: SandboxOperation,
) {
  return operationRef.current.generation === operation.generation
    && activeSessionIdRef.current === operation.sessionId;
}

function finishSandboxOperation(
  operationRef: { current: SandboxOperationState },
  operation: SandboxOperation,
  setAction: (action: string | null) => void,
) {
  if (operationRef.current.generation !== operation.generation) return;
  operationRef.current.busy = false;
  setAction(null);
}
