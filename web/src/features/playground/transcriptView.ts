import type {
  AgentTranscript,
  DelegationExecutionItem,
  ErrorItem,
  ExecutionItem,
  TextItem,
  ThinkingItem,
  ToolExecutionItem,
} from "./transcriptTypes";
import { AGENT_RUN_STATUS } from "../../shared/api/generated/constants";

type TranscriptItem = AgentTranscript["blocks"][number];
export type ToolBlock = ExecutionItem;
export type ContentBlock = TextItem | ErrorItem;
export type TranscriptRenderSegment =
  | { kind: "thinking"; id: "thinking"; items: ThinkingItem[] }
  | { kind: "tools"; id: "tools"; items: ToolBlock[] }
  | { kind: "content"; id: string; block: ContentBlock };

export function buildTranscriptSegments(blocks: TranscriptItem[]): TranscriptRenderSegment[] {
  const thinkingItems: ThinkingItem[] = [];
  const executionItems: ToolBlock[] = [];
  const contentSegments: TranscriptRenderSegment[] = [];

  for (const block of blocks) {
    if (block.kind === "thinking") thinkingItems.push(block);
    else if (isExecutionBlock(block)) executionItems.push(block);
    else contentSegments.push({ kind: "content", id: `${block.kind}:${block.id}`, block });
  }

  return [
    ...(thinkingItems.length ? [{ kind: "thinking" as const, id: "thinking" as const, items: thinkingItems }] : []),
    ...(executionItems.length ? [{ kind: "tools" as const, id: "tools" as const, items: executionItems }] : []),
    ...contentSegments,
  ];
}

export function emptyAgentTranscript(): AgentTranscript {
  return { runId: "", createdAt: "", agentCode: "", blocks: [] };
}

export function isTranscriptEmpty(transcript: AgentTranscript) {
  return transcript.blocks.length === 0;
}

export function activeThinkingItemId(blocks: TranscriptItem[]) {
  return [...blocks].reverse().find((block): block is ThinkingItem => block.kind === "thinking" && !block.complete)?.id ?? "";
}

export function activeTextItemId(blocks: TranscriptItem[]) {
  return [...blocks].reverse().find((block): block is TextItem => block.kind === "text" && !block.complete)?.id ?? "";
}

export function transcriptHasRunningExecution(transcript: AgentTranscript): boolean {
  return transcript.blocks.some((block) => isExecutionBlock(block) && isExecutionRunning(block));
}

export function transcriptItemCount(transcript: AgentTranscript) {
  return transcript.blocks.length;
}

function isExecutionBlock(block: TranscriptItem): block is ToolExecutionItem | DelegationExecutionItem {
  return block.kind === "tool" || block.kind === "delegation";
}

function isExecutionRunning(item: ExecutionItem) {
  if (item.kind === "tool") return !item.resolved;
  return item.status === AGENT_RUN_STATUS.QUEUED
    || item.status === AGENT_RUN_STATUS.RUNNING
    || item.status === AGENT_RUN_STATUS.WAITING;
}
