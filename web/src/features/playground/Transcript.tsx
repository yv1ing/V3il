import { AlertOctagon, Brain, ChevronDown, ChevronRight } from "lucide-react";
import { memo, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { AgentTranscript, ErrorItem, ThinkingItem } from "./transcriptTypes";
import { MarkdownContent } from "../../shared/components/MarkdownContent";
import { normalizeMarkdownForRender } from "./markdown";
import { cx } from "../../shared/lib/className";
import { ToolGroup } from "./TranscriptExecutions";
import {
  activeTextItemId,
  activeThinkingItemId,
  buildTranscriptSegments,
  isTranscriptEmpty,
  type ContentBlock,
  type TranscriptRenderSegment,
} from "./transcriptView";

export function TranscriptContent({
  transcript,
  live,
  emptyText,
  pendingEmpty = false,
}: {
  transcript: AgentTranscript;
  live: boolean;
  emptyText?: string;
  pendingEmpty?: boolean;
}) {
  const isEmpty = isTranscriptEmpty(transcript);
  const activeTextId = live ? activeTextItemId(transcript.blocks) : "";
  const activeThinkingId = live ? activeThinkingItemId(transcript.blocks) : "";
  const segments = useMemo(() => buildTranscriptSegments(transcript.blocks), [transcript.blocks]);

  return (
    <div className="transcript-body">
      {pendingEmpty && isEmpty && live ? <PendingShimmer /> : null}
      {segments.map((segment) => (
        <TranscriptSegmentView
          key={segment.id}
          segment={segment}
          live={live}
          activeTextId={activeTextId}
          activeThinkingId={activeThinkingId}
        />
      ))}
      {live && !isEmpty ? <span className="caret" /> : null}
      {isEmpty && emptyText ? <div className="transcript-empty">{emptyText}</div> : null}
    </div>
  );
}

function TranscriptSegmentView({
  segment,
  live,
  activeTextId,
  activeThinkingId,
}: {
  segment: TranscriptRenderSegment;
  live: boolean;
  activeTextId: string;
  activeThinkingId: string;
}) {
  if (segment.kind === "thinking") {
    return (
      <ThinkingGroup
        items={segment.items}
        activeItemId={activeThinkingId}
        active={segment.items.some((item) => item.id === activeThinkingId && !item.complete)}
        live={live}
      />
    );
  }
  if (segment.kind === "tools") {
    return <ToolGroup items={segment.items} live={live} header={(props) => <PanelHeader {...props} />} />;
  }
  return (
    <ContentBlockView
      block={segment.block}
      streaming={segment.block.kind === "text" ? segment.block.id === activeTextId && !segment.block.complete : false}
    />
  );
}

function ContentBlockView({ block, streaming }: { block: ContentBlock; streaming: boolean }) {
  if (block.kind === "text") return <MarkdownText text={block.text} streaming={streaming} />;
  return <ErrorNotice item={block} />;
}

const STREAM_RENDER_INTERVAL_MS = 80;

const MarkdownText = memo(function MarkdownText({ text, streaming }: { text: string; streaming: boolean }) {
  const [renderText, setRenderText] = useState(text);
  const latestTextRef = useRef(text);
  latestTextRef.current = text;

  useEffect(() => {
    if (!streaming) {
      setRenderText(text);
      return;
    }
    const timer = window.setInterval(() => setRenderText(latestTextRef.current), STREAM_RENDER_INTERVAL_MS);
    return () => {
      window.clearInterval(timer);
      setRenderText(latestTextRef.current);
    };
  }, [streaming, text === ""]);

  useEffect(() => {
    if (!streaming) setRenderText(text);
  }, [streaming, text]);

  const markdown = useMemo(() => normalizeMarkdownForRender(renderText, streaming), [renderText, streaming]);
  if (!renderText && !streaming) return null;
  return <MarkdownContent className="agent-text" content={markdown} mode="document" mermaid />;
});

function ThinkingGroup({
  items,
  active,
  activeItemId,
  live,
}: {
  items: ThinkingItem[];
  active: boolean;
  activeItemId: string;
  live: boolean;
}) {
  const [open, setOpen] = useState(active);
  const wasActive = useRef(active);
  const bodyRef = useRef<HTMLPreElement | null>(null);
  const text = useMemo(() => items.map((item) => item.text.trim()).filter(Boolean).join("\n\n"), [items]);

  useEffect(() => {
    if (active) setOpen(true);
    else if (wasActive.current) setOpen(false);
    wasActive.current = active;
  }, [active]);

  useEffect(() => {
    if (open && bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
  }, [text, open]);

  return (
    <div className={cx("thinking-block", live && "transcript-panel-live", active && "thinking-block-active")}>
      <PanelHeader
        icon={<Brain size={13} />}
        title={active ? "Thinking..." : "Thought"}
        count={items.length > 1 ? items.length : undefined}
        open={open}
        onToggle={() => setOpen((next) => !next)}
      />
      {open ? (
        <div className="thinking-body">
          <div className="thinking-fade thinking-fade-top" />
          <pre ref={bodyRef} className="thinking-text">{text || (activeItemId ? " " : "(empty)")}</pre>
          <div className="thinking-fade thinking-fade-bottom" />
        </div>
      ) : null}
    </div>
  );
}

function PanelHeader({
  icon,
  title,
  count,
  open,
  onToggle,
}: {
  icon: ReactNode;
  title: string;
  count?: number;
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <button type="button" className="transcript-panel-header" onClick={onToggle}>
      {icon}
      <span>{title}</span>
      {count ? <span className="transcript-panel-count">{count}</span> : null}
      <span className="transcript-panel-toggle">{open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}</span>
    </button>
  );
}

function ErrorNotice({ item }: { item: ErrorItem }) {
  return <div className="agent-error"><AlertOctagon size={16} /><span>{item.message}</span></div>;
}

function PendingShimmer() {
  return (
    <div className="pending-shimmer" aria-label="Agent is working">
      <span /><span /><span />
    </div>
  );
}
