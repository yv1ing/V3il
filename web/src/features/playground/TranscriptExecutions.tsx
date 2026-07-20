import { Tag } from "@douyinfe/semi-ui";
import { ChevronDown, ChevronRight, GitBranch, Wrench } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { AGENT_RUN_STATUS } from "../../shared/api/generated/constants";
import type { DelegationExecutionItem, ToolExecutionItem } from "./transcriptTypes";
import { cx } from "../../shared/lib/className";
import type { ToolBlock } from "./transcriptView";

export function ToolGroup({
  items,
  live,
  header,
}: {
  items: ToolBlock[];
  live: boolean;
  header: (props: PanelHeaderProps) => ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className={cx("transcript-panel transcript-panel-tools", live && "transcript-panel-live")}>
      {header({
        icon: <Wrench size={13} />,
        title: "Execution",
        count: items.length,
        open,
        onToggle: () => setOpen((next) => !next),
      })}
      {open ? (
        <div className="tool-list">
          {items.map((item) => item.kind === "tool"
            ? <ToolExecutionBlock key={`tool:${item.id}`} item={item} />
            : <DelegationExecutionBlock key={`delegation:${item.id}`} item={item} />)}
        </div>
      ) : null}
    </div>
  );
}

type PanelHeaderProps = {
  icon: ReactNode;
  title: string;
  count?: number;
  open: boolean;
  onToggle: () => void;
};

function ToolExecutionBlock({ item }: { item: ToolExecutionItem }) {
  const [open, setOpen] = useState(false);
  const detailRef = useRef<HTMLDivElement | null>(null);
  const status = toolExecutionStatus(item);

  useEffect(() => {
    if (open) detailRef.current?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [open]);

  return (
    <div className={cx("execution-row", `execution-row-${status.tone}`)}>
      <button type="button" className="execution-row-head" aria-expanded={open} onClick={() => setOpen((next) => !next)}>
        <ExecutionName name={item.name} />
        <Tag size="small" color={status.color}>{status.label}</Tag>
        <span className="execution-row-toggle">{open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}</span>
      </button>
      {open ? (
        <div ref={detailRef} className="execution-row-detail">
          <JsonExecutionSection label="Arguments" value={item.arguments} />
          {item.resolved
            ? <ToolOutputSection output={item.output} tone={item.isError ? "error" : undefined} />
            : <ExecutionSection label="Output" body="Pending..." />}
        </div>
      ) : null}
    </div>
  );
}

function DelegationExecutionBlock({ item }: { item: DelegationExecutionItem }) {
  const color = item.status === AGENT_RUN_STATUS.FAILED || item.status === AGENT_RUN_STATUS.CANCELED
    ? "red"
    : item.status === AGENT_RUN_STATUS.SUCCEEDED
      ? "green"
      : "amber";
  return (
    <div className={cx("execution-row", `execution-row-${color === "red" ? "error" : color === "green" ? "ok" : "running"}`)}>
      <div className="execution-row-head execution-row-head-static">
        <GitBranch size={14} />
        <ExecutionName name={`${item.parentAgentCode} to ${item.childAgentCode}`} />
        <Tag size="small" color={color}>{item.status}</Tag>
      </div>
      {item.summary ? <ExecutionSection label="Result" body={item.summary} /> : null}
    </div>
  );
}

function ExecutionName({ name }: { name: string }) {
  return <span className="execution-row-name" title={name}>{name}</span>;
}

export function ExecutionSection({ label, body, tone }: { label: string; body: string; tone?: "error" }) {
  return (
    <div className={cx("execution-section", tone && `execution-section-${tone}`)}>
      <div className="execution-section-label">{label}</div>
      <pre className="execution-section-body">{body}</pre>
    </div>
  );
}

function JsonExecutionSection({ label, value, tone }: { label: string; value: unknown; tone?: "error" }) {
  const json = useMemo(() => tokenizeJson(stringifyJson(value)), [value]);
  return (
    <div className={cx("execution-section", tone && `execution-section-${tone}`)}>
      <div className="execution-section-label">{label}</div>
      <pre className="execution-section-body execution-json-body"><code>
        {json.map((token, index) => token.tone
          ? <span key={`${index}:${token.text}`} className={`json-token-${token.tone}`}>{token.text}</span>
          : token.text)}
      </code></pre>
    </div>
  );
}

function ToolOutputSection({ output, tone }: { output: string; tone?: "error" }) {
  const parsed = useMemo(() => parseJsonText(output), [output]);
  return parsed.ok
    ? <JsonExecutionSection label="Output" value={parsed.value} tone={tone} />
    : <ExecutionSection label="Output" body={output || "(empty)"} tone={tone} />;
}

function toolExecutionStatus(item: ToolExecutionItem): { label: string; color: "red" | "green" | "amber"; tone: "error" | "ok" | "running" } {
  if (item.resolved && item.isError) return { label: "Failed", color: "red", tone: "error" };
  if (!item.resolved) return { label: "Running", color: "amber", tone: "running" };
  return { label: "Done", color: "green", tone: "ok" };
}

function parseJsonText(output: string): { ok: true; value: unknown } | { ok: false } {
  const text = output.trim();
  if (!text) return { ok: true, value: "" };
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}

function stringifyJson(value: unknown) {
  try {
    return JSON.stringify(value, null, 2) ?? JSON.stringify(String(value));
  } catch {
    return JSON.stringify(String(value));
  }
}

type JsonToken = { text: string; tone?: "key" | "string" | "number" | "boolean" | "null" };
const JSON_TOKEN_PATTERN = /"(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|\btrue\b|\bfalse\b|\bnull\b/g;

function tokenizeJson(source: string): JsonToken[] {
  const tokens: JsonToken[] = [];
  let cursor = 0;
  for (const match of source.matchAll(JSON_TOKEN_PATTERN)) {
    const text = match[0];
    const index = match.index ?? cursor;
    if (index > cursor) tokens.push({ text: source.slice(cursor, index) });
    tokens.push({ text, tone: jsonTokenTone(source, index, text) });
    cursor = index + text.length;
  }
  if (cursor < source.length) tokens.push({ text: source.slice(cursor) });
  return tokens;
}

function jsonTokenTone(source: string, index: number, text: string): JsonToken["tone"] {
  if (text.startsWith("\"")) return /^\s*:/.test(source.slice(index + text.length)) ? "key" : "string";
  if (text === "true" || text === "false") return "boolean";
  if (text === "null") return "null";
  return "number";
}
