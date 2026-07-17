import { Button, Input, Popconfirm } from "@douyinfe/semi-ui";
import { Edit3, MessageCircle, ShieldAlert, Trash2 } from "lucide-react";
import { memo, useMemo, useState, type ReactNode } from "react";
import { updateAgentSessionTitle } from "../../shared/api/agentSessions";
import type { AgentSessionSummary } from "../../shared/api/types";
import { AsyncContent } from "../../shared/components/AsyncContent";
import { EmptyState } from "../../shared/components/EmptyState";
import { FormField } from "../../shared/components/FormField";
import { ResourceModal } from "../../shared/components/ResourceModal";
import { useResourceSubmit } from "../../shared/hooks/useResourceSubmit";
import { cx } from "../../shared/lib/className";
import { UI_TEXT } from "../../shared/lib/uiText";

type SessionListProps = {
  sessions: AgentSessionSummary[];
  loading: boolean;
  loadingMore: boolean;
  hasMore: boolean;
  activeSessionId: string | null;
  onSelect: (sessionId: string) => void;
  onDelete: (sessionId: string) => void;
  onRefreshSessions: () => Promise<void>;
  onLoadMoreSessions: () => Promise<void>;
};

type SessionRowProps = {
  active: boolean;
  icon: ReactNode;
  session: AgentSessionSummary;
  titleFallback: string;
  onRename: () => void;
  onSelect: () => void;
  onDelete: () => void;
};

export const SessionList = memo(function SessionList({
  sessions,
  loading,
  loadingMore,
  hasMore,
  activeSessionId,
  onSelect,
  onDelete,
  onRefreshSessions,
  onLoadMoreSessions,
}: SessionListProps) {
  const [renameTarget, setRenameTarget] = useState<AgentSessionSummary | null>(null);
  const [renameTitle, setRenameTitle] = useState("");
  const { saving: renaming, submit } = useResourceSubmit();
  const groupedSessions = useMemo(() => ({
    incidents: sessions.filter((session) => session.incident_id != null),
    chats: sessions.filter((session) => session.incident_id == null),
  }), [sessions]);

  const openRename = (session: AgentSessionSummary) => {
    setRenameTarget(session);
    setRenameTitle(session.title || "");
  };

  const saveRename = async () => {
    const title = renameTitle.trim();
    if (!renameTarget || !title) return;
    await submit(async () => {
      const response = await updateAgentSessionTitle(renameTarget.session_id, { title });
      setRenameTarget(null);
      setRenameTitle("");
      await onRefreshSessions();
      return response;
    });
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
              label="Incident investigations"
              sessions={groupedSessions.incidents}
              icon={<ShieldAlert size={14} />}
              titleFallback="Incident investigation"
              activeSessionId={activeSessionId}
              onSelect={onSelect}
              onDelete={onDelete}
              onRename={openRename}
            />
            <SessionGroup
              label="Operator chats"
              sessions={groupedSessions.chats}
              icon={<MessageCircle size={14} />}
              titleFallback="Untitled session"
              activeSessionId={activeSessionId}
              onSelect={onSelect}
              onDelete={onDelete}
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
          <Input autoFocus maxLength={80} value={renameTitle} onChange={setRenameTitle} />
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
    || previous.onDelete !== next.onDelete
    || previous.onRefreshSessions !== next.onRefreshSessions
    || previous.onLoadMoreSessions !== next.onLoadMoreSessions
    || previous.sessions.length !== next.sessions.length
  ) {
    return false;
  }
  return previous.sessions.every((session, index) => {
    const nextSession = next.sessions[index];
    return nextSession != null
      && session.session_id === nextSession.session_id
      && session.session_type === nextSession.session_type
      && session.incident_id === nextSession.incident_id
      && session.title === nextSession.title;
  });
}

function SessionGroup({
  label,
  sessions,
  icon,
  titleFallback,
  activeSessionId,
  onSelect,
  onDelete,
  onRename,
}: {
  label: string;
  sessions: AgentSessionSummary[];
  icon: ReactNode;
  titleFallback: string;
  activeSessionId: string | null;
  onSelect: (sessionId: string) => void;
  onDelete: (sessionId: string) => void;
  onRename: (session: AgentSessionSummary) => void;
}) {
  if (sessions.length === 0) return null;
  return (
    <section className="session-group" aria-label={label}>
      <div className="session-group-label">{label}</div>
      {sessions.map((session) => (
        <SessionRow
          key={session.session_id}
          active={session.session_id === activeSessionId}
          icon={icon}
          session={session}
          titleFallback={titleFallback}
          onRename={() => onRename(session)}
          onSelect={() => onSelect(session.session_id)}
          onDelete={() => onDelete(session.session_id)}
        />
      ))}
    </section>
  );
}

function SessionRow({
  active,
  icon,
  session,
  titleFallback,
  onRename,
  onSelect,
  onDelete,
}: SessionRowProps) {
  const title = session.title || titleFallback;
  return (
    <div className={cx("session-row", active && "session-row-active")}>
      <button type="button" className="session-row-main" onClick={onSelect}>
        <span className="session-row-icon">{icon}</span>
        <span className="session-row-body">
          <span className="session-row-title">{title}</span>
          {session.incident_id ? <span className="session-row-context">Incident {session.incident_id}</span> : null}
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
      <Popconfirm
        title="Delete session"
        content="Permanently delete this conversation?"
        okType="danger"
        cancelText={UI_TEXT.cancel}
        onConfirm={onDelete}
      >
        <Button
          icon={<Trash2 size={14} />}
          theme="borderless"
          type="danger"
          size="small"
          aria-label={`Delete ${title}`}
        />
      </Popconfirm>
    </div>
  );
}
