import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { listAgents } from "../../shared/api/agents";
import {
  AGENT_CLIENT_FRAME_TYPE,
  AGENT_DURABLE_EVENT_TYPE,
  AGENT_SERVER_FRAME_TYPE,
  AGENT_SERVER_FRAME_TYPE_VALUES,
  PAGINATION_DEFAULT_PAGE_SIZE,
  SESSION_TYPE,
} from "../../shared/api/generated/constants";
import {
  buildAgentStreamUrl,
  cancelAllAgentSessionTasks,
  createAgentSessionTurn,
  archiveAgentSession,
  getAgentSession,
  interruptAgentSession,
  listAgentEvents,
  listAgentSessions,
  submitAgentSessionTurn,
  updateAgentSessionSandboxContainer,
} from "../../shared/api/agentSessions";
import { ApiError } from "../../shared/api/client";
import { showApiError } from "../../shared/api/feedback";
import { getStoredAccessToken } from "../../shared/auth/session";
import { mergeByKey } from "../../shared/lib/array";
import type {
  AgentClientFrame,
  AgentCode,
  AgentInfo,
  AgentInputPart,
  AgentServerFrame,
  AgentSessionSummary,
} from "../../shared/api/types";
import {
  applyServerFrame,
  createAgentStore,
  deriveChatState,
  ingestDurableEvents,
  replaceDurableEvents,
  type AgentStore,
} from "./agentStore";
import type { ChatState } from "./transcriptTypes";

export type AgentSessionConnectionStatus = "idle" | "connecting" | "open" | "closed";

type SessionRuntime = {
  store: AgentStore;
  status: AgentSessionConnectionStatus;
  historyLoading: boolean;
  historyPrepending: boolean;
  historyHasMore: boolean;
  historyBeforeSeq: number | null;
  historyVersion: number;
  agentCodeOverride: AgentCode | "";
};

function createSessionRuntime(): SessionRuntime {
  return {
    store: createAgentStore(),
    status: "idle",
    historyLoading: false,
    historyPrepending: false,
    historyHasMore: false,
    historyBeforeSeq: null,
    historyVersion: 0,
    agentCodeOverride: "",
  };
}

const HISTORY_PAGE_SIZE = 80;
const SOCKET_PING_INTERVAL_MS = 25_000;
const SOCKET_RECONNECT_MAX_MS = 30_000;

type AgentSessionContextValue = {
  sessions: AgentSessionSummary[];
  sessionsLoading: boolean;
  sessionsLoadingMore: boolean;
  sessionsHasMore: boolean;
  refreshSessions: () => Promise<void>;
  loadMoreSessions: () => Promise<void>;
  syncSessionSummaries: (items: AgentSessionSummary[]) => void;
  archiveSession: (sessionId: string) => Promise<boolean>;
  activeSessionId: string | null;
  activeSessionSummary: AgentSessionSummary | null;
  invalidSessionId: string | null;
  selectSession: (sessionId: string | null, options?: { navigateBlank?: boolean }) => void;
  chatState: ChatState;
  status: AgentSessionConnectionStatus;
  historyLoading: boolean;
  historyPrepending: boolean;
  historyHasMore: boolean;
  historyVersion: number;
  agents: AgentInfo[];
  defaultAgentCode: AgentCode | "";
  activeAgentCode: AgentCode | "";
  setActiveAgentCode: (code: AgentCode) => void;
  send: (content: AgentInputPart[], sessionId: string | null, sandboxContainerId: number | null) => Promise<AgentSessionSummary>;
  updateSelectedSandboxContainer: (sessionId: string, sandboxContainerId: number | null) => Promise<AgentSessionSummary | null>;
  interrupt: (sessionId?: string | null) => Promise<void>;
  cancelAll: (sessionId?: string | null) => Promise<void>;
  loadPreviousHistory: (sessionId?: string | null) => Promise<void>;
};

const AgentSessionContext = createContext<AgentSessionContextValue | null>(null);

export function useAgentSessionContext(): AgentSessionContextValue {
  const value = useContext(AgentSessionContext);
  if (!value) throw new Error("useAgentSessionContext must be used inside AgentSessionProvider");
  return value;
}

export function AgentSessionProvider({ children }: { children: ReactNode }) {
  const [sessions, setSessions] = useState<AgentSessionSummary[]>([]);
  const [sessionSummaries, setSessionSummaries] = useState<Map<string, AgentSessionSummary>>(() => new Map());
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [sessionsLoadingMore, setSessionsLoadingMore] = useState(false);
  const [sessionsPage, setSessionsPage] = useState(1);
  const [sessionsTotal, setSessionsTotal] = useState(0);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [invalidSessionId, setInvalidSessionId] = useState<string | null>(null);
  const [runtimes, setRuntimes] = useState<Map<string, SessionRuntime>>(() => new Map());
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [defaultAgentCode, setDefaultAgentCode] = useState<AgentCode | "">("");
  const [pendingAgentCode, setPendingAgentCode] = useState<AgentCode | "">("");

  const runtimesRef = useRef(runtimes);
  const activeSessionIdRef = useRef(activeSessionId);
  const sessionSummariesRef = useRef(sessionSummaries);
  const socketsRef = useRef<Map<string, WebSocket>>(new Map());
  const socketCleanupRef = useRef<Map<string, () => void>>(new Map());
  const reconnectTimersRef = useRef<Map<string, number>>(new Map());
  const reconnectAttemptsRef = useRef<Map<string, number>>(new Map());
  const ensuredHistoryRef = useRef<Set<string>>(new Set());
  const loadingHistoryRef = useRef<Set<string>>(new Set());
  const historyGenerationRef = useRef<Map<string, number>>(new Map());
  const historyPrependRequestsRef = useRef<Map<string, number>>(new Map());
  const pendingRecoveryHeadsRef = useRef<Map<string, number>>(new Map());
  const recoveringSessionsRef = useRef<Set<string>>(new Set());
  const recoveryTimersRef = useRef<Map<string, number>>(new Map());
  const recoveryAttemptsRef = useRef<Map<string, number>>(new Map());
  const archivedSessionsRef = useRef<Set<string>>(new Set());
  const invalidSessionsRef = useRef<Set<string>>(new Set());
  const archivingSessionsRef = useRef<Set<string>>(new Set());
  const sandboxSelectionGenerationRef = useRef<Map<string, number>>(new Map());
  const controlCommandSessionsRef = useRef<Set<string>>(new Set());
  const manualBlankSessionRef = useRef(false);
  const sessionsRequestIdRef = useRef(0);
  const sessionSummaryRequestIdRef = useRef<Map<string, number>>(new Map());
  const sessionsLoadingMoreRef = useRef(false);
  const connectForRef = useRef<(sessionId: string) => WebSocket | null>(() => null);
  const recoverStreamRef = useRef<(sessionId: string, targetHead: number) => Promise<void>>(async () => undefined);
  const invalidateSessionRef = useRef<(sessionId: string, error?: unknown) => void>(() => undefined);

  activeSessionIdRef.current = activeSessionId;
  sessionSummariesRef.current = sessionSummaries;
  runtimesRef.current = runtimes;

  const updateRuntime = useCallback((sessionId: string, update: (runtime: SessionRuntime) => SessionRuntime) => {
    setRuntimes((current) => {
      const runtime = current.get(sessionId) ?? createSessionRuntime();
      const nextRuntime = update(runtime);
      if (nextRuntime === runtime && current.has(sessionId)) return current;
      const next = new Map(current);
      next.set(sessionId, nextRuntime);
      runtimesRef.current = next;
      return next;
    });
  }, []);

  const requestStreamRecovery = useCallback((sessionId: string, targetHead: number) => {
    if (archivedSessionsRef.current.has(sessionId) || invalidSessionsRef.current.has(sessionId)) return;
    const store = runtimesRef.current.get(sessionId)?.store ?? createAgentStore();
    if (store.durableCursorSeq >= targetHead && !store.rebaseRequired) {
      pendingRecoveryHeadsRef.current.delete(sessionId);
      return;
    }
    pendingRecoveryHeadsRef.current.set(
      sessionId,
      Math.max(pendingRecoveryHeadsRef.current.get(sessionId) ?? 0, targetHead),
    );
    void recoverStreamRef.current(sessionId, targetHead);
  }, []);

  const syncSessionSummaries = useCallback((items: AgentSessionSummary[]) => {
    if (!items.length) return;
    setSessionSummaries((current) => {
      const next = new Map(current);
      for (const item of items) {
        const existing = next.get(item.id);
        next.set(item.id, existing ? preferSessionSummary(existing, item) : item);
      }
      sessionSummariesRef.current = next;
      return next;
    });
  }, []);

  const syncSession = useCallback((item: AgentSessionSummary) => {
    sessionSummaryRequestIdRef.current.set(
      item.id,
      (sessionSummaryRequestIdRef.current.get(item.id) ?? 0) + 1,
    );
    syncSessionSummaries([item]);
    setSessions((current) => {
      if (item.session_type !== SESSION_TYPE.CHAT) return current.filter((session) => session.id !== item.id);
      if (!current.some((session) => session.id === item.id)) return [item, ...current];
      return current.map((session) => session.id === item.id ? preferSessionSummary(session, item) : session);
    });
  }, [syncSessionSummaries]);

  const refreshSessionSummary = useCallback(async (sessionId: string, reportError = true) => {
    const requestId = (sessionSummaryRequestIdRef.current.get(sessionId) ?? 0) + 1;
    sessionSummaryRequestIdRef.current.set(sessionId, requestId);
    try {
      const summary = await getAgentSession(sessionId);
      if (sessionSummaryRequestIdRef.current.get(sessionId) !== requestId) return null;
      if (!archivedSessionsRef.current.has(sessionId)) syncSession(summary);
      return summary;
    } catch (error) {
      if (sessionSummaryRequestIdRef.current.get(sessionId) !== requestId) return null;
      if (error instanceof ApiError && error.status === 404) {
        invalidateSessionRef.current(sessionId, error);
        return null;
      }
      if (reportError && !archivedSessionsRef.current.has(sessionId)) showApiError(error);
      return null;
    }
  }, [syncSession]);

  useEffect(() => {
    listAgents()
      .then((response) => {
        setAgents(response.items);
        setDefaultAgentCode(response.default_code);
      })
      .catch(showApiError);
  }, []);

  const refreshSessions = useCallback(async (silent = false) => {
    const requestId = sessionsRequestIdRef.current + 1;
    sessionsRequestIdRef.current = requestId;
    if (!silent) setSessionsLoading(true);
    try {
      const response = await listAgentSessions({ page: 1, size: PAGINATION_DEFAULT_PAGE_SIZE });
      if (sessionsRequestIdRef.current !== requestId) return;
      setSessions((current) => mergeSessionRefresh(current, response.items));
      setSessionsPage(1);
      setSessionsTotal(response.total);
      syncSessionSummaries(response.items);
    } catch (error) {
      if (!silent && sessionsRequestIdRef.current === requestId) showApiError(error);
    } finally {
      if (sessionsRequestIdRef.current === requestId) setSessionsLoading(false);
    }
  }, [syncSessionSummaries]);

  const loadMoreSessions = useCallback(async () => {
    if (sessionsLoadingMoreRef.current || sessions.length >= sessionsTotal) return;
    const nextPage = sessionsPage + 1;
    const requestId = sessionsRequestIdRef.current;
    sessionsLoadingMoreRef.current = true;
    setSessionsLoadingMore(true);
    try {
      const response = await listAgentSessions({ page: nextPage, size: PAGINATION_DEFAULT_PAGE_SIZE });
      if (sessionsRequestIdRef.current !== requestId) return;
      setSessions((current) => mergeByKey(current, response.items, (session) => session.id));
      setSessionsPage(nextPage);
      setSessionsTotal(response.total);
      syncSessionSummaries(response.items);
    } catch (error) {
      showApiError(error);
    } finally {
      sessionsLoadingMoreRef.current = false;
      setSessionsLoadingMore(false);
    }
  }, [sessions.length, sessionsPage, sessionsTotal, syncSessionSummaries]);

  useEffect(() => {
    void refreshSessions();
  }, [refreshSessions]);

  const shouldMaintainSocket = useCallback((sessionId: string) => (
    activeSessionIdRef.current === sessionId
    || sessionSummariesRef.current.get(sessionId)?.capabilities.can_cancel_all === true
  ), []);

  const clearReconnectTimer = useCallback((sessionId: string) => {
    const timer = reconnectTimersRef.current.get(sessionId);
    if (timer != null) window.clearTimeout(timer);
    reconnectTimersRef.current.delete(sessionId);
  }, []);

  const closeSocket = useCallback((sessionId: string) => {
    clearReconnectTimer(sessionId);
    const socket = socketsRef.current.get(sessionId);
    if (!socket) return;
    socketsRef.current.delete(sessionId);
    socketCleanupRef.current.get(sessionId)?.();
    socketCleanupRef.current.delete(sessionId);
    socket.close(1000, "client closed idle stream");
    updateRuntime(sessionId, (runtime) => ({ ...runtime, status: "closed" }));
  }, [clearReconnectTimer, updateRuntime]);

  const clearRecoveryTimer = useCallback((sessionId: string) => {
    const timer = recoveryTimersRef.current.get(sessionId);
    if (timer != null) window.clearTimeout(timer);
    recoveryTimersRef.current.delete(sessionId);
  }, []);

  const invalidateSession = useCallback((sessionId: string, error?: unknown) => {
    const firstInvalidation = !invalidSessionsRef.current.has(sessionId);
    invalidSessionsRef.current.add(sessionId);
    sessionSummaryRequestIdRef.current.set(
      sessionId,
      (sessionSummaryRequestIdRef.current.get(sessionId) ?? 0) + 1,
    );
    recoveringSessionsRef.current.delete(sessionId);
    pendingRecoveryHeadsRef.current.delete(sessionId);
    ensuredHistoryRef.current.delete(sessionId);
    loadingHistoryRef.current.delete(sessionId);
    historyGenerationRef.current.set(
      sessionId,
      (historyGenerationRef.current.get(sessionId) ?? 0) + 1,
    );
    historyPrependRequestsRef.current.delete(sessionId);
    recoveryAttemptsRef.current.delete(sessionId);
    clearRecoveryTimer(sessionId);
    closeSocket(sessionId);
    setSessions((current) => current.filter((session) => session.id !== sessionId));
    setSessionSummaries((current) => {
      const next = new Map(current);
      next.delete(sessionId);
      sessionSummariesRef.current = next;
      return next;
    });
    setRuntimes((current) => {
      const next = new Map(current);
      next.delete(sessionId);
      runtimesRef.current = next;
      return next;
    });
    if (activeSessionIdRef.current === sessionId) {
      manualBlankSessionRef.current = true;
      setActiveSessionId(null);
      setInvalidSessionId(sessionId);
    }
    if (firstInvalidation && error) showApiError(error);
  }, [clearRecoveryTimer, closeSocket]);
  invalidateSessionRef.current = invalidateSession;

  const scheduleReconnect = useCallback((sessionId: string) => {
    if (
      !shouldMaintainSocket(sessionId)
      || archivedSessionsRef.current.has(sessionId)
      || invalidSessionsRef.current.has(sessionId)
      || recoveringSessionsRef.current.has(sessionId)
    ) return;
    clearReconnectTimer(sessionId);
    const attempt = (reconnectAttemptsRef.current.get(sessionId) ?? 0) + 1;
    reconnectAttemptsRef.current.set(sessionId, attempt);
    const delay = Math.min(SOCKET_RECONNECT_MAX_MS, 1_000 * 2 ** Math.min(attempt - 1, 5));
    const timer = window.setTimeout(() => {
      reconnectTimersRef.current.delete(sessionId);
      connectForRef.current(sessionId);
    }, delay);
    reconnectTimersRef.current.set(sessionId, timer);
  }, [clearReconnectTimer, shouldMaintainSocket]);

  const connectFor = useCallback((sessionId: string): WebSocket | null => {
    const existing = socketsRef.current.get(sessionId);
    if (existing && (existing.readyState === WebSocket.OPEN || existing.readyState === WebSocket.CONNECTING)) return existing;
    const token = getStoredAccessToken();
    if (
      !token
      || !ensuredHistoryRef.current.has(sessionId)
      || archivedSessionsRef.current.has(sessionId)
      || invalidSessionsRef.current.has(sessionId)
      || recoveringSessionsRef.current.has(sessionId)
    ) return null;

    const socket = new WebSocket(buildAgentStreamUrl(sessionId, token));
    socketsRef.current.set(sessionId, socket);
    updateRuntime(sessionId, (runtime) => ({ ...runtime, status: "connecting" }));
    let pingTimer: number | null = null;

    const onOpen = () => {
      if (socketsRef.current.get(sessionId) !== socket) return;
      reconnectAttemptsRef.current.delete(sessionId);
      clearReconnectTimer(sessionId);
      updateRuntime(sessionId, (runtime) => ({ ...runtime, status: "open" }));
      void refreshSessionSummary(sessionId, false);
      pingTimer = window.setInterval(
        () => sendClientFrame(socket, { type: AGENT_CLIENT_FRAME_TYPE.PING }),
        SOCKET_PING_INTERVAL_MS,
      );
    };

    const onTerminate = (event: Event) => {
      if (socketsRef.current.get(sessionId) !== socket) return;
      socketsRef.current.delete(sessionId);
      socketCleanupRef.current.get(sessionId)?.();
      socketCleanupRef.current.delete(sessionId);
      if (
        event.type === "error"
        && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)
      ) {
        socket.close(4000, "agent stream transport error");
      }
      updateRuntime(sessionId, (runtime) => ({
        ...runtime,
        status: "closed",
        store: runtime.store.activeRunIds.size
          ? { ...runtime.store, streamError: websocketCloseMessage(event) }
          : runtime.store,
      }));
      scheduleReconnect(sessionId);
    };

    const onMessage = (message: MessageEvent) => {
      if (socketsRef.current.get(sessionId) !== socket || typeof message.data !== "string") return;
      let frame: AgentServerFrame;
      try {
        frame = parseAgentServerFrame(JSON.parse(message.data) as unknown);
      } catch {
        socket.close(1003, "invalid agent stream frame");
        return;
      }

      let requiresRebase = false;
      let nextCursor = 0;
      updateRuntime(sessionId, (runtime) => {
        const store = applyServerFrame(runtime.store, frame);
        requiresRebase = store.rebaseRequired;
        nextCursor = store.durableCursorSeq;
        return store === runtime.store ? runtime : { ...runtime, store };
      });

      if (frame.type === AGENT_SERVER_FRAME_TYPE.HELLO) {
        if (frame.session_id !== sessionId) {
          socket.close(1008, "agent stream session mismatch");
          return;
        }
        sendClientFrame(socket, { type: AGENT_CLIENT_FRAME_TYPE.ACK, durable_seq: nextCursor });
      } else if (frame.type === AGENT_SERVER_FRAME_TYPE.EVENT && !requiresRebase) {
        sendClientFrame(socket, { type: AGENT_CLIENT_FRAME_TYPE.ACK, durable_seq: nextCursor });
      } else if (frame.type === AGENT_SERVER_FRAME_TYPE.REPLAY) {
        sendClientFrame(socket, { type: AGENT_CLIENT_FRAME_TYPE.ACK, durable_seq: nextCursor });
      } else if (frame.type === AGENT_SERVER_FRAME_TYPE.HEARTBEAT) {
        sendClientFrame(socket, { type: AGENT_CLIENT_FRAME_TYPE.PING });
      }
      if (frame.type === AGENT_SERVER_FRAME_TYPE.REBASE_REQUIRED || requiresRebase) {
        requestStreamRecovery(sessionId, frame.type === AGENT_SERVER_FRAME_TYPE.REBASE_REQUIRED
          ? frame.durable_head_seq
          : runtimesRef.current.get(sessionId)?.store.durableHeadSeq ?? 0);
      }
      if (
        (
          frame.type === AGENT_SERVER_FRAME_TYPE.EVENT
          && frame.event.type === AGENT_DURABLE_EVENT_TYPE.RUN_TRANSITION
        )
        || (
          frame.type === AGENT_SERVER_FRAME_TYPE.REPLAY
          && frame.events.some((event) => event.type === AGENT_DURABLE_EVENT_TYPE.RUN_TRANSITION)
        )
      ) {
        void refreshSessionSummary(sessionId, false);
      }
    };

    socket.addEventListener("open", onOpen);
    socket.addEventListener("close", onTerminate);
    socket.addEventListener("error", onTerminate);
    socket.addEventListener("message", onMessage);
    socketCleanupRef.current.set(sessionId, () => {
      socket.removeEventListener("open", onOpen);
      socket.removeEventListener("close", onTerminate);
      socket.removeEventListener("error", onTerminate);
      socket.removeEventListener("message", onMessage);
      if (pingTimer != null) window.clearInterval(pingTimer);
    });
    return socket;
  }, [clearReconnectTimer, refreshSessionSummary, requestStreamRecovery, scheduleReconnect, updateRuntime]);
  connectForRef.current = connectFor;

  const loadHistory = useCallback(async (sessionId: string) => {
    if (
      loadingHistoryRef.current.has(sessionId)
      || archivedSessionsRef.current.has(sessionId)
      || invalidSessionsRef.current.has(sessionId)
    ) return;
    loadingHistoryRef.current.add(sessionId);
    const generation = (historyGenerationRef.current.get(sessionId) ?? 0) + 1;
    historyGenerationRef.current.set(sessionId, generation);
    historyPrependRequestsRef.current.delete(sessionId);
    updateRuntime(sessionId, (runtime) => ({
      ...runtime,
      historyLoading: true,
      historyPrepending: false,
    }));
    try {
      const response = await listAgentEvents(sessionId, { limit: HISTORY_PAGE_SIZE });
      if (
        historyGenerationRef.current.get(sessionId) !== generation
        || archivedSessionsRef.current.has(sessionId)
        || invalidSessionsRef.current.has(sessionId)
      ) return;
      ensuredHistoryRef.current.add(sessionId);
      updateRuntime(sessionId, (runtime) => ({
        ...runtime,
        store: replaceDurableEvents(response.items),
        historyLoading: false,
        historyPrepending: false,
        historyHasMore: response.has_more,
        historyBeforeSeq: response.next_before_seq ?? null,
        historyVersion: runtime.historyVersion + 1,
      }));
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        invalidateSessionRef.current(sessionId, error);
        return;
      } else if (!archivedSessionsRef.current.has(sessionId)) {
        showApiError(error);
      }
      if (historyGenerationRef.current.get(sessionId) === generation) {
        updateRuntime(sessionId, (runtime) => ({ ...runtime, historyLoading: false }));
      }
    } finally {
      loadingHistoryRef.current.delete(sessionId);
      const pendingHead = pendingRecoveryHeadsRef.current.get(sessionId);
      if (pendingHead != null) requestStreamRecovery(sessionId, pendingHead);
      else if (ensuredHistoryRef.current.has(sessionId)) connectForRef.current(sessionId);
    }
  }, [requestStreamRecovery, updateRuntime]);

  const recoverStream = useCallback(async (sessionId: string, targetHead: number) => {
    if (archivedSessionsRef.current.has(sessionId) || invalidSessionsRef.current.has(sessionId)) return;
    pendingRecoveryHeadsRef.current.set(
      sessionId,
      Math.max(pendingRecoveryHeadsRef.current.get(sessionId) ?? 0, targetHead),
    );
    if (loadingHistoryRef.current.has(sessionId)) return;
    recoveringSessionsRef.current.add(sessionId);
    clearRecoveryTimer(sessionId);
    closeSocket(sessionId);
    loadingHistoryRef.current.add(sessionId);
    const generation = (historyGenerationRef.current.get(sessionId) ?? 0) + 1;
    historyGenerationRef.current.set(sessionId, generation);
    historyPrependRequestsRef.current.delete(sessionId);
    updateRuntime(sessionId, (runtime) => ({ ...runtime, historyPrepending: false }));
    const recoveryHead = pendingRecoveryHeadsRef.current.get(sessionId) ?? targetHead;
    pendingRecoveryHeadsRef.current.delete(sessionId);
    let recovered = false;
    try {
      const response = await listAgentEvents(sessionId, { limit: HISTORY_PAGE_SIZE });
      if (
        historyGenerationRef.current.get(sessionId) !== generation
        || archivedSessionsRef.current.has(sessionId)
        || invalidSessionsRef.current.has(sessionId)
      ) return;
      ensuredHistoryRef.current.add(sessionId);
      updateRuntime(sessionId, (runtime) => {
        return {
          ...runtime,
          store: replaceDurableEvents(response.items, recoveryHead),
          historyLoading: false,
          historyPrepending: false,
          historyHasMore: response.has_more,
          historyBeforeSeq: response.next_before_seq ?? null,
          historyVersion: runtime.historyVersion + 1,
        };
      });
      recoveryAttemptsRef.current.delete(sessionId);
      recovered = true;
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        invalidateSessionRef.current(sessionId, error);
      } else {
        const attempt = (recoveryAttemptsRef.current.get(sessionId) ?? 0) + 1;
        if (attempt === 1) showApiError(error);
        pendingRecoveryHeadsRef.current.set(
          sessionId,
          Math.max(pendingRecoveryHeadsRef.current.get(sessionId) ?? 0, recoveryHead),
        );
        recoveryAttemptsRef.current.set(sessionId, attempt);
        const delay = Math.min(SOCKET_RECONNECT_MAX_MS, 1_000 * 2 ** Math.min(attempt - 1, 5));
        const timer = window.setTimeout(() => {
          recoveryTimersRef.current.delete(sessionId);
          void recoverStreamRef.current(sessionId, recoveryHead);
        }, delay);
        recoveryTimersRef.current.set(sessionId, timer);
      }
    } finally {
      loadingHistoryRef.current.delete(sessionId);
      if (recovered) recoveringSessionsRef.current.delete(sessionId);
      const pendingHead = pendingRecoveryHeadsRef.current.get(sessionId);
      if (recovered && pendingHead != null) requestStreamRecovery(sessionId, pendingHead);
      else if (recovered && shouldMaintainSocket(sessionId)) connectForRef.current(sessionId);
    }
  }, [clearRecoveryTimer, closeSocket, requestStreamRecovery, shouldMaintainSocket, updateRuntime]);
  recoverStreamRef.current = recoverStream;

  const loadPreviousHistory = useCallback(async (sessionId: string | null = activeSessionIdRef.current) => {
    const targetSessionId = sessionId ?? activeSessionIdRef.current;
    if (!targetSessionId || archivedSessionsRef.current.has(targetSessionId)) return;
    const runtime = runtimesRef.current.get(targetSessionId);
    if (
      !runtime?.historyHasMore
      || runtime.historyBeforeSeq == null
      || historyPrependRequestsRef.current.has(targetSessionId)
    ) return;
    const generation = historyGenerationRef.current.get(targetSessionId) ?? 0;
    historyPrependRequestsRef.current.set(targetSessionId, generation);
    updateRuntime(targetSessionId, (current) => ({ ...current, historyPrepending: true }));
    try {
      const response = await listAgentEvents(targetSessionId, { before_seq: runtime.historyBeforeSeq, limit: HISTORY_PAGE_SIZE });
      if (
        historyGenerationRef.current.get(targetSessionId) !== generation
        || historyPrependRequestsRef.current.get(targetSessionId) !== generation
        || archivedSessionsRef.current.has(targetSessionId)
        || invalidSessionsRef.current.has(targetSessionId)
      ) return;
      updateRuntime(targetSessionId, (current) => ({
        ...current,
        store: ingestDurableEvents(current.store, response.items),
        historyPrepending: false,
        historyHasMore: response.has_more,
        historyBeforeSeq: response.next_before_seq ?? null,
        historyVersion: current.historyVersion + 1,
      }));
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        invalidateSessionRef.current(targetSessionId, error);
        return;
      }
      if (
        historyGenerationRef.current.get(targetSessionId) === generation
        && historyPrependRequestsRef.current.get(targetSessionId) === generation
      ) showApiError(error);
    } finally {
      if (historyPrependRequestsRef.current.get(targetSessionId) === generation) {
        historyPrependRequestsRef.current.delete(targetSessionId);
        updateRuntime(targetSessionId, (current) => ({ ...current, historyPrepending: false }));
      }
    }
  }, [updateRuntime]);

  const selectSession = useCallback((sessionId: string | null, options: { navigateBlank?: boolean } = {}) => {
    if (sessionId && invalidSessionsRef.current.has(sessionId)) {
      setInvalidSessionId(sessionId);
      setActiveSessionId(null);
      return;
    }
    manualBlankSessionRef.current = sessionId === null && options.navigateBlank !== false;
    setInvalidSessionId(null);
    setActiveSessionId(sessionId);
  }, []);

  useEffect(() => {
    if (!activeSessionId) return;
    if (!sessionSummariesRef.current.has(activeSessionId)) void refreshSessionSummary(activeSessionId);
    if (!ensuredHistoryRef.current.has(activeSessionId)) void loadHistory(activeSessionId);
    else connectFor(activeSessionId);
  }, [activeSessionId, connectFor, loadHistory, refreshSessionSummary]);

  useEffect(() => {
    const maintained = new Set<string>();
    if (activeSessionId) maintained.add(activeSessionId);
    for (const summary of sessionSummaries.values()) {
      if (summary.capabilities.can_cancel_all) maintained.add(summary.id);
    }
    if (!activeSessionId && !manualBlankSessionRef.current) {
      const running = sessions.find((session) => session.active_run);
      if (running) setActiveSessionId(running.id);
    }
    for (const sessionId of maintained) {
      if (ensuredHistoryRef.current.has(sessionId)) connectFor(sessionId);
      else void loadHistory(sessionId);
    }
    for (const sessionId of socketsRef.current.keys()) {
      if (!maintained.has(sessionId)) closeSocket(sessionId);
    }
  }, [activeSessionId, closeSocket, connectFor, loadHistory, sessionSummaries, sessions]);

  const activeAgentCode = useMemo<AgentCode | "">(() => {
    if (!activeSessionId) return pendingAgentCode || defaultAgentCode;
    const runtime = runtimes.get(activeSessionId);
    return runtime?.agentCodeOverride
      || sessionSummaries.get(activeSessionId)?.primary_agent_code
      || defaultAgentCode;
  }, [activeSessionId, defaultAgentCode, pendingAgentCode, runtimes, sessionSummaries]);

  const setActiveAgentCode = useCallback((code: AgentCode) => {
    if (!agents.some((agent) => agent.code === code)) return;
    if (!activeSessionIdRef.current) {
      setPendingAgentCode(code);
      return;
    }
    const summary = sessionSummariesRef.current.get(activeSessionIdRef.current);
    if (!summary?.capabilities.can_switch_agent) return;
    updateRuntime(activeSessionIdRef.current, (runtime) => ({ ...runtime, agentCodeOverride: code }));
  }, [agents, updateRuntime]);

  const selectedAgentCode = useCallback((sessionId: string | null): AgentCode | null => {
    const selected = sessionId
      ? runtimesRef.current.get(sessionId)?.agentCodeOverride || sessionSummariesRef.current.get(sessionId)?.primary_agent_code
      : pendingAgentCode || defaultAgentCode;
    return agents.some((agent) => agent.code === selected) ? selected || null : null;
  }, [agents, defaultAgentCode, pendingAgentCode]);

  const updateSelectedSandboxContainer = useCallback(async (sessionId: string, sandboxContainerId: number | null) => {
    const currentSummary = sessionSummariesRef.current.get(sessionId);
    if (!currentSummary?.capabilities.can_select_sandbox_container) {
      throw new Error(
        currentSummary?.capabilities.turn_block_reason
        || "Sandbox selection is unavailable for this session",
      );
    }
    const generation = (sandboxSelectionGenerationRef.current.get(sessionId) ?? 0) + 1;
    sandboxSelectionGenerationRef.current.set(sessionId, generation);
    const summary = await updateAgentSessionSandboxContainer(sessionId, { sandbox_container_id: sandboxContainerId });
    if (sandboxSelectionGenerationRef.current.get(sessionId) !== generation || archivedSessionsRef.current.has(sessionId)) return null;
    syncSession(summary);
    return summary;
  }, [syncSession]);

  const send = useCallback(async (content: AgentInputPart[], sessionId: string | null, sandboxContainerId: number | null) => {
    const agentCode = selectedAgentCode(sessionId);
    try {
      if (sessionId) {
        const currentSummary = sessionSummariesRef.current.get(sessionId);
        if (!currentSummary?.capabilities.can_submit_turn) {
          throw new Error(
            currentSummary?.capabilities.turn_block_reason
            || "This session cannot accept a new turn",
          );
        }
        const response = await submitAgentSessionTurn(sessionId, { content, agent_code: agentCode });
        syncSession(response.session);
        updateRuntime(sessionId, (runtime) => ({ ...runtime, store: ingestDurableEvents(runtime.store, [response.accepted_event]) }));
        connectFor(sessionId);
        return response.session;
      }
      const response = await createAgentSessionTurn({ content, agent_code: agentCode, sandbox_container_id: sandboxContainerId });
      syncSession(response.session);
      updateRuntime(response.session.id, (runtime) => ({ ...runtime, store: ingestDurableEvents(runtime.store, [response.accepted_event]) }));
      ensuredHistoryRef.current.add(response.session.id);
      setActiveSessionId(response.session.id);
      setPendingAgentCode("");
      connectFor(response.session.id);
      return response.session;
    } catch (error) {
      showApiError(error);
      throw error;
    }
  }, [connectFor, selectedAgentCode, syncSession, updateRuntime]);

  const interrupt = useCallback(async (sessionId: string | null = activeSessionIdRef.current) => {
    const target = sessionId ?? activeSessionIdRef.current;
    if (
      !target
      || !sessionSummariesRef.current.get(target)?.capabilities.can_interrupt
      || controlCommandSessionsRef.current.has(target)
    ) return;
    controlCommandSessionsRef.current.add(target);
    try {
      const response = await interruptAgentSession(target);
      syncSession(response.session);
      connectFor(target);
    } catch (error) {
      showApiError(error);
    } finally {
      controlCommandSessionsRef.current.delete(target);
    }
  }, [connectFor, syncSession]);

  const cancelAll = useCallback(async (sessionId: string | null = activeSessionIdRef.current) => {
    const target = sessionId ?? activeSessionIdRef.current;
    if (
      !target
      || !sessionSummariesRef.current.get(target)?.capabilities.can_cancel_all
      || controlCommandSessionsRef.current.has(target)
    ) return;
    controlCommandSessionsRef.current.add(target);
    try {
      const response = await cancelAllAgentSessionTasks(target);
      syncSession(response.session);
      connectFor(target);
    } catch (error) {
      showApiError(error);
    } finally {
      controlCommandSessionsRef.current.delete(target);
    }
  }, [connectFor, syncSession]);

  const archiveSession = useCallback(async (sessionId: string) => {
    if (archivedSessionsRef.current.has(sessionId)) return true;
    if (
      archivingSessionsRef.current.has(sessionId)
      || !sessionSummariesRef.current.get(sessionId)?.capabilities.can_archive
    ) return false;
    archivingSessionsRef.current.add(sessionId);
    try {
      await archiveAgentSession(sessionId);
      archivedSessionsRef.current.add(sessionId);
      closeSocket(sessionId);
      if (activeSessionIdRef.current === sessionId) selectSession(null);
      setSessions((current) => current.filter((session) => session.id !== sessionId));
      setSessionSummaries((current) => {
        const next = new Map(current);
        next.delete(sessionId);
        sessionSummariesRef.current = next;
        return next;
      });
      setRuntimes((current) => {
        const next = new Map(current);
        next.delete(sessionId);
        runtimesRef.current = next;
        return next;
      });
      pendingRecoveryHeadsRef.current.delete(sessionId);
      recoveringSessionsRef.current.delete(sessionId);
      recoveryAttemptsRef.current.delete(sessionId);
      ensuredHistoryRef.current.delete(sessionId);
      loadingHistoryRef.current.delete(sessionId);
      historyGenerationRef.current.set(
        sessionId,
        (historyGenerationRef.current.get(sessionId) ?? 0) + 1,
      );
      historyPrependRequestsRef.current.delete(sessionId);
      clearRecoveryTimer(sessionId);
      sandboxSelectionGenerationRef.current.delete(sessionId);
      await refreshSessions();
      return true;
    } catch (error) {
      showApiError(error);
      return false;
    } finally {
      archivingSessionsRef.current.delete(sessionId);
    }
  }, [clearRecoveryTimer, closeSocket, refreshSessions, selectSession]);

  useEffect(() => () => {
    for (const cleanup of socketCleanupRef.current.values()) cleanup();
    for (const socket of socketsRef.current.values()) socket.close(1000, "provider unmounted");
    for (const timer of reconnectTimersRef.current.values()) window.clearTimeout(timer);
    for (const timer of recoveryTimersRef.current.values()) window.clearTimeout(timer);
    socketsRef.current.clear();
    socketCleanupRef.current.clear();
    reconnectTimersRef.current.clear();
    recoveryTimersRef.current.clear();
  }, []);

  const defaultRuntime = useMemo(createSessionRuntime, []);
  const activeRuntime = activeSessionId ? runtimes.get(activeSessionId) ?? defaultRuntime : defaultRuntime;
  const chatState = useMemo(() => deriveChatState(activeRuntime.store), [activeRuntime.store]);
  const activeSessionSummary = activeSessionId ? sessionSummaries.get(activeSessionId) ?? null : null;
  const value = useMemo<AgentSessionContextValue>(() => ({
    sessions,
    sessionsLoading,
    sessionsLoadingMore,
    sessionsHasMore: sessions.length < sessionsTotal,
    refreshSessions,
    loadMoreSessions,
    syncSessionSummaries,
    archiveSession,
    activeSessionId,
    activeSessionSummary,
    invalidSessionId,
    selectSession,
    chatState,
    status: activeRuntime.status,
    historyLoading: activeRuntime.historyLoading,
    historyPrepending: activeRuntime.historyPrepending,
    historyHasMore: activeRuntime.historyHasMore,
    historyVersion: activeRuntime.historyVersion,
    agents,
    defaultAgentCode,
    activeAgentCode,
    setActiveAgentCode,
    send,
    updateSelectedSandboxContainer,
    interrupt,
    cancelAll,
    loadPreviousHistory,
  }), [
    activeAgentCode, activeRuntime, activeSessionId, activeSessionSummary, agents, cancelAll, chatState,
    archiveSession, defaultAgentCode, interrupt, invalidSessionId, loadMoreSessions, loadPreviousHistory, refreshSessions, selectSession,
    send, sessions, sessionsLoading, sessionsLoadingMore, sessionsTotal, setActiveAgentCode, syncSessionSummaries,
    updateSelectedSandboxContainer,
  ]);

  return <AgentSessionContext.Provider value={value}>{children}</AgentSessionContext.Provider>;
}

const AGENT_SERVER_FRAME_TYPE_SET = new Set<string>(AGENT_SERVER_FRAME_TYPE_VALUES);

function parseAgentServerFrame(value: unknown): AgentServerFrame {
  if (typeof value !== "object" || value === null) throw new Error("agent stream frame must be an object");
  const type = Reflect.get(value, "type");
  if (typeof type !== "string" || !AGENT_SERVER_FRAME_TYPE_SET.has(type)) throw new Error("unknown agent stream frame type");
  return value as AgentServerFrame;
}

function sendClientFrame(socket: WebSocket, frame: AgentClientFrame) {
  if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(frame));
}

function websocketCloseMessage(event: Event): string {
  if (event instanceof CloseEvent) {
    if (event.reason) return `Agent stream connection closed: ${event.reason}`;
    if (event.code !== 1000 && event.code !== 1005) return `Agent stream connection closed unexpectedly (code ${event.code})`;
  }
  return "Agent stream connection closed before the run reached a durable terminal state";
}

function mergeSessionRefresh(current: AgentSessionSummary[], head: AgentSessionSummary[]): AgentSessionSummary[] {
  const currentIds = new Set(current.map((session) => session.id));
  const refreshed = new Map(head.map((session) => [session.id, session]));
  return [
    ...head.filter((session) => !currentIds.has(session.id)),
    ...current.map((session) => {
      const candidate = refreshed.get(session.id);
      return candidate ? preferSessionSummary(session, candidate) : session;
    }),
  ];
}

function preferSessionSummary(
  current: AgentSessionSummary,
  candidate: AgentSessionSummary,
): AgentSessionSummary {
  if (candidate.event_count !== current.event_count) {
    return candidate.event_count > current.event_count ? candidate : current;
  }
  const currentUpdatedAt = Date.parse(current.updated_at);
  const candidateUpdatedAt = Date.parse(candidate.updated_at);
  if (Number.isFinite(currentUpdatedAt) && Number.isFinite(candidateUpdatedAt)) {
    return candidateUpdatedAt >= currentUpdatedAt ? candidate : current;
  }
  return candidate;
}
