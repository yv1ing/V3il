import {
  AGENT_DURABLE_EVENT_TYPE,
  AGENT_RUN_STATUS,
  AGENT_SEGMENT_KIND,
  AGENT_SEGMENT_STATUS,
  AGENT_SERVER_FRAME_TYPE,
} from "../../shared/api/generated/constants";
import type {
  AgentCode,
  AgentDurableEvent,
  AgentInputPart,
  AgentSegmentSnapshot,
  AgentServerFrame,
  DelegationEvent,
  ToolCallEvent,
  ToolResultEvent,
} from "../../shared/api/types";
import type {
  ChatNode,
  ChatState,
  DelegationExecutionItem,
  StreamingItem,
  ToolExecutionItem,
  TranscriptBlock,
} from "./transcriptTypes";

export type AgentStore = {
  durableEvents: Map<number, AgentDurableEvent>;
  durableCursorSeq: number;
  durableHeadSeq: number;
  activeRunIds: Set<string>;
  runStateFloorSeq: number;
  runStateSeqById: Map<string, number>;
  liveSegments: Map<string, AgentSegmentSnapshot>;
  rebaseRequired: boolean;
  streamError: string;
};

export function createAgentStore(): AgentStore {
  return {
    durableEvents: new Map(),
    durableCursorSeq: 0,
    durableHeadSeq: 0,
    activeRunIds: new Set(),
    runStateFloorSeq: 0,
    runStateSeqById: new Map(),
    liveSegments: new Map(),
    rebaseRequired: false,
    streamError: "",
  };
}

export function ingestDurableEvents(store: AgentStore, events: readonly AgentDurableEvent[]): AgentStore {
  if (!events.length) return store;
  const durableEvents = new Map(store.durableEvents);
  const activeRunIds = new Set(store.activeRunIds);
  const runStateSeqById = new Map(store.runStateSeqById);
  const liveSegments = new Map(store.liveSegments);
  let durableHeadSeq = store.durableHeadSeq;
  let identityConflict = false;
  let changed = false;

  for (const event of [...events].sort((left, right) => left.seq - right.seq)) {
    const current = durableEvents.get(event.seq);
    if (current?.id === event.id) continue;
    if (current) identityConflict = true;
    durableEvents.set(event.seq, event);
    durableHeadSeq = Math.max(durableHeadSeq, event.seq);
    changed = true;

    if (
      event.run_id
      && isRunStateEvent(event)
      && event.seq > Math.max(store.runStateFloorSeq, runStateSeqById.get(event.run_id) ?? 0)
    ) {
      if (
        event.type === AGENT_DURABLE_EVENT_TYPE.USER_MESSAGE
        || isActiveRunStatus(event.status)
      ) activeRunIds.add(event.run_id);
      else activeRunIds.delete(event.run_id);
      runStateSeqById.set(event.run_id, event.seq);
    } else if (event.type === AGENT_DURABLE_EVENT_TYPE.SEGMENT_COMPLETED) {
      liveSegments.delete(event.segment_id);
    }
  }

  if (!changed) return store;
  let durableCursorSeq = store.durableCursorSeq;
  while (durableEvents.has(durableCursorSeq + 1)) durableCursorSeq += 1;
  return {
    ...store,
    durableEvents,
    durableCursorSeq,
    durableHeadSeq,
    activeRunIds,
    runStateSeqById,
    liveSegments: identityConflict || store.rebaseRequired ? new Map() : liveSegments,
    rebaseRequired: store.rebaseRequired || identityConflict,
  };
}

export function replaceDurableEvents(
  events: readonly AgentDurableEvent[],
  advertisedHeadSeq = 0,
): AgentStore {
  const replacement = ingestDurableEvents(createAgentStore(), events);
  const latestSeq = latestDurableSeq(replacement);
  return {
    ...replacement,
    durableCursorSeq: latestSeq,
    durableHeadSeq: Math.max(advertisedHeadSeq, latestSeq),
    streamError: "",
  };
}

export function applyServerFrame(store: AgentStore, frame: AgentServerFrame): AgentStore {
  switch (frame.type) {
    case AGENT_SERVER_FRAME_TYPE.HELLO:
      return {
        ...store,
        durableHeadSeq: Math.max(store.durableHeadSeq, frame.durable_head_seq),
        activeRunIds: new Set(frame.active_run_ids),
        runStateFloorSeq: frame.durable_head_seq,
        runStateSeqById: new Map(),
        liveSegments: new Map((frame.segments ?? []).map((segment) => [segment.segment_id, segment])),
        rebaseRequired: false,
        streamError: "",
      };
    case AGENT_SERVER_FRAME_TYPE.REPLAY: {
      const replayed = ingestDurableEvents(store, frame.events);
      return {
        ...replayed,
        durableCursorSeq: Math.max(replayed.durableCursorSeq, frame.durable_head_seq),
        durableHeadSeq: Math.max(replayed.durableHeadSeq, frame.durable_head_seq),
      };
    }
    case AGENT_SERVER_FRAME_TYPE.EVENT: {
      const hasSequenceGap = frame.event.seq > store.durableCursorSeq + 1;
      const next = ingestDurableEvents(store, [frame.event]);
      return hasSequenceGap
        ? { ...next, liveSegments: new Map(), rebaseRequired: true }
        : next;
    }
    case AGENT_SERVER_FRAME_TYPE.DELTA:
      return applyDelta(store, frame);
    case AGENT_SERVER_FRAME_TYPE.REBASE_REQUIRED:
      return {
        ...store,
        durableHeadSeq: Math.max(store.durableHeadSeq, frame.durable_head_seq),
        liveSegments: new Map(),
        rebaseRequired: true,
      };
    case AGENT_SERVER_FRAME_TYPE.ERROR:
      return { ...store, streamError: frame.message };
    case AGENT_SERVER_FRAME_TYPE.HEARTBEAT:
      return store;
  }
}

export function deriveChatState(store: AgentStore): ChatState {
  const nodes: ChatNode[] = [];
  const runNodes = new Map<string, Extract<ChatNode, { kind: "agent" }>>();
  const events = [...store.durableEvents.values()].sort((left, right) => left.seq - right.seq);

  const ensureRunNode = (runId: string, occurredAt = "", agentCode: AgentCode | "" = "") => {
    const current = runNodes.get(runId);
    if (current) {
      if (!current.createdAt && occurredAt) current.createdAt = occurredAt;
      if (!current.agentCode && agentCode) current.agentCode = agentCode;
      return current;
    }
    const next: Extract<ChatNode, { kind: "agent" }> = {
      kind: "agent",
      id: `run:${runId}`,
      runId,
      createdAt: occurredAt,
      agentCode,
      blocks: [],
    };
    runNodes.set(runId, next);
    nodes.push(next);
    return next;
  };

  for (const event of events) {
    if (event.type === AGENT_DURABLE_EVENT_TYPE.USER_MESSAGE) {
      nodes.push(userNode(event.id, event.occurred_at, event.content, event.display_text, event.agent_code));
      if (event.run_id) ensureRunNode(event.run_id, event.occurred_at, event.agent_code);
      continue;
    }
    if (!event.run_id) continue;
    if (!isTranscriptEvent(event)) continue;
    const node = ensureRunNode(event.run_id, event.occurred_at, eventAgentCode(event));
    if (event.type === AGENT_DURABLE_EVENT_TYPE.SEGMENT_COMPLETED) {
      upsertSegment(node.blocks, event.segment_id, event.segment_kind, event.text, true);
    } else if (event.type === AGENT_DURABLE_EVENT_TYPE.TOOL_CALL) {
      upsertToolCall(node.blocks, event);
    } else if (event.type === AGENT_DURABLE_EVENT_TYPE.TOOL_RESULT) {
      upsertToolResult(node.blocks, event);
    } else if (event.type === AGENT_DURABLE_EVENT_TYPE.DELEGATION) {
      upsertDelegation(node.blocks, event);
    } else if (event.type === AGENT_DURABLE_EVENT_TYPE.ERROR) {
      node.blocks.push({ kind: "error", id: event.id, message: event.message });
    }
  }

  for (const segment of store.liveSegments.values()) {
    const node = ensureRunNode(segment.run_id);
    upsertSegment(node.blocks, segment.segment_id, segment.segment_kind, segment.text, false);
  }

  if (store.streamError) {
    const lastRun = [...runNodes.values()].at(-1);
    if (lastRun && !lastRun.blocks.some((block) => block.kind === "error" && block.id === "stream-error")) {
      lastRun.blocks.push({ kind: "error", id: "stream-error", message: store.streamError });
    }
  }

  return { nodes, streaming: store.activeRunIds.size > 0 || store.liveSegments.size > 0 };
}

export function latestDurableSeq(store: AgentStore): number {
  return store.durableEvents.size ? Math.max(...store.durableEvents.keys()) : 0;
}

function applyDelta(
  store: AgentStore,
  frame: Extract<AgentServerFrame, { type: "delta" }>,
): AgentStore {
  const current = store.liveSegments.get(frame.segment_id);
  const text = current?.text ?? "";
  if (current && (
    current.run_id !== frame.run_id
    || current.attempt_id !== frame.attempt_id
    || current.segment_kind !== frame.segment_kind
  )) {
    return { ...store, liveSegments: new Map(), rebaseRequired: true };
  }
  if (
    frame.start_utf16_offset > text.length
    || frame.end_utf16_offset !== frame.start_utf16_offset + frame.delta.length
  ) {
    return { ...store, liveSegments: new Map(), rebaseRequired: true };
  }
  if (frame.end_utf16_offset <= text.length) {
    return text.slice(frame.start_utf16_offset, frame.end_utf16_offset) === frame.delta
      ? store
      : { ...store, liveSegments: new Map(), rebaseRequired: true };
  }
  const overlap = text.length - frame.start_utf16_offset;
  if (overlap > 0 && text.slice(frame.start_utf16_offset) !== frame.delta.slice(0, overlap)) {
    return { ...store, liveSegments: new Map(), rebaseRequired: true };
  }
  const liveSegments = new Map(store.liveSegments);
  liveSegments.set(frame.segment_id, {
    segment_id: frame.segment_id,
    run_id: frame.run_id,
    attempt_id: frame.attempt_id,
    segment_kind: frame.segment_kind,
    status: AGENT_SEGMENT_STATUS.STREAMING,
    text: text + frame.delta.slice(Math.max(0, overlap)),
    persisted_utf16_offset: current?.persisted_utf16_offset ?? 0,
  });
  return { ...store, liveSegments, rebaseRequired: false };
}

function userNode(
  id: string,
  createdAt: string,
  content: AgentInputPart[],
  displayText: string,
  targetAgentCode: AgentCode,
): Extract<ChatNode, { kind: "user" }> {
  return { kind: "user", id, createdAt, content, displayText, targetAgentCode };
}

function eventAgentCode(event: AgentDurableEvent): AgentCode | "" {
  return "agent_code" in event ? event.agent_code : "";
}

function upsertSegment(
  blocks: TranscriptBlock[],
  segmentId: string,
  segmentKind: "text" | "thinking",
  text: string,
  complete: boolean,
) {
  const kind: StreamingItem["kind"] = segmentKind === AGENT_SEGMENT_KIND.THINKING ? "thinking" : "text";
  const index = blocks.findIndex((block) => block.kind === kind && block.segmentId === segmentId);
  const item: StreamingItem = { kind, id: `${kind}:${segmentId}`, segmentId, text, complete };
  if (index === -1) blocks.push(item);
  else blocks[index] = item;
}

function upsertToolCall(blocks: TranscriptBlock[], event: ToolCallEvent) {
  const index = blocks.findIndex((block) => block.kind === "tool" && block.callId === event.call_id);
  const previous = index === -1 ? null : blocks[index] as ToolExecutionItem;
  const item: ToolExecutionItem = {
    kind: "tool",
    id: event.call_id,
    callId: event.call_id,
    name: event.name,
    arguments: event.arguments,
    output: previous?.output ?? "",
    isError: previous?.isError ?? false,
    resolved: previous?.resolved ?? false,
  };
  if (index === -1) blocks.push(item);
  else blocks[index] = item;
}

function upsertToolResult(blocks: TranscriptBlock[], event: ToolResultEvent) {
  const index = blocks.findIndex((block) => block.kind === "tool" && block.callId === event.call_id);
  if (index === -1) {
    blocks.push({
      kind: "tool",
      id: event.call_id,
      callId: event.call_id,
      name: event.call_id,
      arguments: {},
      output: event.output,
      isError: event.is_error,
      resolved: true,
    });
    return;
  }
  const previous = blocks[index] as ToolExecutionItem;
  blocks[index] = { ...previous, output: event.output, isError: event.is_error, resolved: true };
}

function upsertDelegation(blocks: TranscriptBlock[], event: DelegationEvent) {
  const index = blocks.findIndex((block) => block.kind === "delegation" && block.childRunId === event.child_run_id);
  const item: DelegationExecutionItem = {
    kind: "delegation",
    id: event.child_run_id,
    childRunId: event.child_run_id,
    childAgentCode: event.child_agent_code,
    parentAgentCode: event.parent_agent_code,
    status: event.status,
    summary: event.summary,
  };
  if (index === -1) blocks.push(item);
  else blocks[index] = item;
}

function isActiveRunStatus(status: string) {
  return status === AGENT_RUN_STATUS.QUEUED
    || status === AGENT_RUN_STATUS.RUNNING
    || status === AGENT_RUN_STATUS.WAITING;
}

function isRunStateEvent(event: AgentDurableEvent) {
  return event.type === AGENT_DURABLE_EVENT_TYPE.USER_MESSAGE
    || event.type === AGENT_DURABLE_EVENT_TYPE.RUN_TRANSITION;
}

function isTranscriptEvent(event: AgentDurableEvent) {
  return event.type === AGENT_DURABLE_EVENT_TYPE.SEGMENT_COMPLETED
    || event.type === AGENT_DURABLE_EVENT_TYPE.TOOL_CALL
    || event.type === AGENT_DURABLE_EVENT_TYPE.TOOL_RESULT
    || event.type === AGENT_DURABLE_EVENT_TYPE.DELEGATION
    || event.type === AGENT_DURABLE_EVENT_TYPE.ERROR;
}
