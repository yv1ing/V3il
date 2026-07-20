import type { AgentCode, AgentInputPart, AgentRun, ToolCallEvent, ToolResultEvent } from "../../shared/api/types";

export type ThinkingItem = {
  kind: "thinking";
  id: string;
  segmentId: string;
  text: string;
  complete: boolean;
};

export type TextItem = {
  kind: "text";
  id: string;
  segmentId: string;
  text: string;
  complete: boolean;
};

export type StreamingItem = ThinkingItem | TextItem;

export type ToolExecutionItem = {
  kind: "tool";
  id: string;
  callId: ToolCallEvent["call_id"];
  name: ToolCallEvent["name"];
  arguments: ToolCallEvent["arguments"];
  output: ToolResultEvent["output"];
  isError: ToolResultEvent["is_error"];
  resolved: boolean;
};

export type DelegationExecutionItem = {
  kind: "delegation";
  id: string;
  childRunId: string;
  childAgentCode: AgentCode;
  parentAgentCode: AgentCode;
  status: AgentRun["status"];
  summary: string;
};

export type ErrorItem = { kind: "error"; id: string; message: string };
export type ExecutionItem = ToolExecutionItem | DelegationExecutionItem;
export type TranscriptBlock = ThinkingItem | TextItem | ExecutionItem | ErrorItem;

export type AgentTranscript = {
  runId: string;
  createdAt: string;
  agentCode: AgentCode | "";
  blocks: TranscriptBlock[];
};

export type ChatNode =
  | {
      kind: "user";
      id: string;
      createdAt: string;
      content: AgentInputPart[];
      displayText: string;
      targetAgentCode: AgentCode;
    }
  | ({ kind: "agent"; id: string } & AgentTranscript);

export type ChatState = {
  nodes: ChatNode[];
  streaming: boolean;
};
