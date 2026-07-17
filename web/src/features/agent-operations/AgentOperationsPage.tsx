import { Button } from "@douyinfe/semi-ui";
import { ArrowRight, Bot, MessageSquareCode, Radio, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listAgentSessions } from "../../shared/api/agentSessions";
import { listAgents } from "../../shared/api/agents";
import { showApiError } from "../../shared/api/feedback";
import type { AgentInfo, AgentSessionSummary } from "../../shared/api/types";
import { AsyncContent } from "../../shared/components/AsyncContent";
import { MetricStrip } from "../../shared/components/ResourcePageShell";
import { useAdminResourceHeader } from "../../shared/hooks/useAdminResourceHeader";
import { formatDateTime } from "../../shared/lib/date";
import { useAgentSessionContext } from "../playground/AgentSessionProvider";
import { EmptyOperationalState, OperationalSection, OperationalTag } from "../operations/OperationalUi";

type AgentOperationsData = { agents: AgentInfo[]; sessions: AgentSessionSummary[]; total: number };

export function AgentOperationsPage() {
  const navigate = useNavigate();
  const { selectSession } = useAgentSessionContext();
  const [data, setData] = useState<AgentOperationsData>({ agents: [], sessions: [], total: 0 });
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [agentResponse, sessionResponse] = await Promise.all([
        listAgents(),
        listAgentSessions({ page: 1, size: 100, include_scoped: true }),
      ]);
      setData({
        agents: agentResponse.data?.items ?? [],
        sessions: sessionResponse.data?.items ?? [],
        total: sessionResponse.data?.total ?? 0,
      });
    } catch (error) {
      showApiError(error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useAdminResourceHeader({
    refreshLabel: "Refresh agent operations",
    loading,
    onRefresh: load,
    extraActions: <Button icon={<MessageSquareCode size={16} />} theme="solid" type="primary" onClick={() => { selectSession(null); navigate("/playground"); }}>New chat</Button>,
  });

  const metrics = useMemo(() => [
    { label: "Expert Agents", value: data.agents.length },
    { label: "Running Sessions", value: data.sessions.filter((session) => session.is_running).length },
    { label: "Incident Sessions", value: data.sessions.filter((session) => session.incident_id != null).length },
    { label: "Automated", value: data.sessions.filter((session) => session.is_automated).length },
  ], [data]);

  const openSession = (session: AgentSessionSummary) => {
    selectSession(session.session_id);
    navigate("/playground", { state: { sessionId: session.session_id } });
  };

  return (
    <section className="agent-operations-page">
      <MetricStrip metrics={metrics} />
      <OperationalSection title="Defense Team" count={data.agents.length}>
        <AsyncContent loading={loading} empty={data.agents.length === 0} emptyContent={<EmptyOperationalState icon={<Bot size={26} />} label="No agents registered" />}>
          <div className="agent-operation-grid">
            {data.agents.map((agent) => {
              const sessions = data.sessions.filter((session) => (session.runtime_agent_code || session.agent_code) === agent.code);
              const running = sessions.filter((session) => session.is_running).length;
              return (
                <article key={agent.code}>
                  <span className="agent-operation-avatar"><Bot size={22} /></span>
                  <div><small>{agent.code.toUpperCase()}</small><strong>{agent.name}</strong><p>{agent.description || "Security specialist"}</p></div>
                  <footer><span><Radio size={13} /> {running} running</span><span>{sessions.length} sessions</span></footer>
                </article>
              );
            })}
          </div>
        </AsyncContent>
      </OperationalSection>
      <OperationalSection title="Session Activity" count={data.total}>
        {data.sessions.length === 0 ? <EmptyOperationalState icon={<MessageSquareCode size={24} />} label="No agent sessions" /> : (
          <div className="session-operations-table">
            <div className="session-operations-row session-operations-head"><span>Session</span><span>Agent</span><span>Context</span><span>State</span><span>Messages</span><span>Updated</span><span /></div>
            {data.sessions.map((session) => (
              <div className="session-operations-row" key={session.session_id}>
                <div><strong>{session.title || "Untitled session"}</strong><small>{session.session_id.slice(0, 12)}</small></div>
                <code>{(session.runtime_agent_code || session.agent_code || "-").toUpperCase()}</code>
                <span>{session.incident_id
                  ? `Incident ${session.incident_id}`
                  : session.environment_id
                    ? `Environment ${session.environment_id}`
                    : "Operator chat"}</span>
                <span>{session.is_running ? <OperationalTag value="running" /> : session.run_error ? <OperationalTag value="failed" /> : <span className="session-idle"><ShieldCheck size={13} /> Idle</span>}</span>
                <strong>{session.message_count}</strong>
                <small>{formatDateTime(session.updated_at)}</small>
                <Button icon={<ArrowRight size={14} />} theme="borderless" aria-label={`Open ${session.title || "session"}`} onClick={() => openSession(session)} />
              </div>
            ))}
          </div>
        )}
      </OperationalSection>
    </section>
  );
}
