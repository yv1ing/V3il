import { Button, Input, Popconfirm } from "@douyinfe/semi-ui";
import { Archive, Edit3, MessageCircle } from "lucide-react";
import { memo, useState } from "react";
import { updateAgentSessionTitle } from "../../shared/api/agentSessions";
import { showApiError } from "../../shared/api/feedback";
import { FIELD_CONSTRAINTS } from "../../shared/api/generated/constants";
import type { AgentSessionSummary } from "../../shared/api/types";
import { AsyncContent } from "../../shared/components/AsyncContent";
import { EmptyState } from "../../shared/components/EmptyState";
import { FormField } from "../../shared/components/FormField";
import { ResourceModal } from "../../shared/components/ResourceModal";
import { cx } from "../../shared/lib/className";
import { UI_TEXT } from "../../shared/lib/uiText";

type SessionListProps = {
  sessions: AgentSessionSummary[];
  loading: boolean;
  loadingMore: boolean;
  hasMore: boolean;
  activeSessionId: string | null;
  onSelect: (sessionId: string) => void;
  onArchive: (sessionId: string) => void;
  onRefreshSessions: () => Promise<void>;
  onLoadMoreSessions: () => Promise<void>;
};

type SessionRowProps = {
  active: boolean;
  session: AgentSessionSummary;
  onRename: () => void;
  onSelect: () => void;
  onArchive: () => void;
};

export const SessionList = memo(function SessionList({
  sessions,
  loading,
  loadingMore,
  hasMore,
  activeSessionId,
  onSelect,
  onArchive,
  onRefreshSessions,
  onLoadMoreSessions,
}: SessionListProps) {
  const [renameTarget, setRenameTarget] = useState<AgentSessionSummary | null>(null);
  const [renameTitle, setRenameTitle] = useState("");
  const [renaming, setRenaming] = useState(false);
  const openRename = (session: AgentSessionSummary) => {
    setRenameTarget(session);
    setRenameTitle(session.title || "");
  };

  const saveRename = async () => {
    const title = renameTitle.trim();
    if (!renameTarget || !title) return;
    if (renaming) return;
    setRenaming(true);
    try {
      await updateAgentSessionTitle(renameTarget.id, { title });
      setRenameTarget(null);
      setRenameTitle("");
      await onRefreshSessions();
    } catch (error) {
      showApiError(error);
    } finally {
      setRenaming(false);
    }
  };

  return (
    <div className="session-list">
      <div className="session-list-body">
        <AsyncContent
          loading={loading}
          empty={sessions.length === 0}
          emptyContent={(
            <EmptyState className="session-empty" compact icon={<MessageCircle size={28} />} title="No active conversations" />
          )}
          wrapperClassName="session-list-spin"
        >
          <>
            <SessionGroup
              label="Operator chats"
              sessions={sessions}
              activeSessionId={activeSessionId}
              onSelect={onSelect}
              onArchive={onArchive}
              onRename={openRename}
            />
            {hasMore ? (
              <Button
                className="session-list-more"
                theme="borderless"
                type="tertiary"
                loading={loadingMore}
                onClick={() => void onLoadMoreSessions()}
              >
                Load more
              </Button>
            ) : null}
          </>
        </AsyncContent>
      </div>
      <ResourceModal
        open={Boolean(renameTarget)}
        title="Edit Session Title"
        titleIcon={<Edit3 size={17} />}
        saving={renaming}
        submitLabel={UI_TEXT.save}
        submitDisabled={!renameTitle.trim()}
        onSubmit={saveRename}
        onCancel={() => setRenameTarget(null)}
      >
        <FormField label="Session Title">
          <Input autoFocus maxLength={FIELD_CONSTRAINTS.UpdateAgentSessionTitleRequest.title.maxLength} value={renameTitle} onChange={setRenameTitle} />
        </FormField>
      </ResourceModal>
    </div>
  );
}, areSessionListPropsEqual);

function areSessionListPropsEqual(previous: SessionListProps, next: SessionListProps) {
  if (
    previous.loading !== next.loading
    || previous.loadingMore !== next.loadingMore
    || previous.hasMore !== next.hasMore
    || previous.activeSessionId !== next.activeSessionId
    || previous.onSelect !== next.onSelect
    || previous.onArchive !== next.onArchive
    || previous.onRefreshSessions !== next.onRefreshSessions
    || previous.onLoadMoreSessions !== next.onLoadMoreSessions
    || previous.sessions.length !== next.sessions.length
  ) {
    return false;
  }
  return previous.sessions.every((session, index) => {
    const nextSession = next.sessions[index];
    return nextSession != null
      && session.id === nextSession.id
      && session.session_type === nextSession.session_type
      && session.title === nextSession.title
      && session.capabilities.can_archive === nextSession.capabilities.can_archive;
  });
}

function SessionGroup({
  label,
  sessions,
  activeSessionId,
  onSelect,
  onArchive,
  onRename,
}: {
  label: string;
  sessions: AgentSessionSummary[];
  activeSessionId: string | null;
  onSelect: (sessionId: string) => void;
  onArchive: (sessionId: string) => void;
  onRename: (session: AgentSessionSummary) => void;
}) {
  if (sessions.length === 0) return null;
  return (
    <section className="session-group" aria-label={label}>
      <div className="session-group-label">{label}</div>
      {sessions.map((session) => (
        <SessionRow
          key={session.id}
          active={session.id === activeSessionId}
          session={session}
          onRename={() => onRename(session)}
          onSelect={() => onSelect(session.id)}
          onArchive={() => onArchive(session.id)}
        />
      ))}
    </section>
  );
}

function SessionRow({
  active,
  session,
  onRename,
  onSelect,
  onArchive,
}: SessionRowProps) {
  const title = session.title || "Untitled session";
  const archiveButton = (
    <Button
      icon={<Archive size={14} />}
      theme="borderless"
      type="danger"
      size="small"
      aria-label={`Archive ${title}`}
      disabled={!session.capabilities.can_archive}
    />
  );
  return (
    <div className={cx("session-row", active && "session-row-active")}>
      <button type="button" className="session-row-main" onClick={onSelect}>
        <span className="session-row-icon"><MessageCircle size={14} /></span>
        <span className="session-row-body">
          <span className="session-row-title">{title}</span>
        </span>
      </button>
      <Button
        icon={<Edit3 size={14} />}
        theme="borderless"
        type="tertiary"
        size="small"
        aria-label={`Edit ${title}`}
        onClick={onRename}
      />
      {session.capabilities.can_archive ? (
        <Popconfirm
          title="Archive session"
          content="Archive this conversation?"
          okType="danger"
          cancelText={UI_TEXT.cancel}
          onConfirm={onArchive}
        >
          {archiveButton}
        </Popconfirm>
      ) : archiveButton}
    </div>
  );
}
