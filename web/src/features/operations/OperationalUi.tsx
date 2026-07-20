import { Tag } from "@douyinfe/semi-ui";
import type { ReactNode } from "react";
import { EmptyState } from "../../shared/components/EmptyState";
import { formatEnumLabel } from "../../shared/lib/labels";
import {
  DECEPTION_ENVIRONMENT_STATUS,
  DETECTION_RULE_DEPLOYMENT_STATUS,
  SANDBOX_ASYNC_JOB_STATUS,
  SANDBOX_CONTAINER_STATUS,
} from "../../shared/api/generated/constants";

type OperationalTagColor = "amber" | "blue" | "cyan" | "green" | "grey" | "red";

const TAG_COLORS: Record<string, OperationalTagColor> = {
  active: "green",
  adapting: "cyan",
  applied: "green",
  blocked: "amber",
  canceled: "grey",
  closed: "grey",
  complete: "green",
  completed: "green",
  confirmed: "red",
  contained: "green",
  changes_requested: "amber",
  degraded: "amber",
  [DETECTION_RULE_DEPLOYMENT_STATUS.DEPLOYING]: "blue",
  critical: "red",
  detected: "amber",
  draft: "grey",
  engaging: "cyan",
  error: "red",
  executing: "blue",
  failed: "red",
  final: "green",
  high: "red",
  [DETECTION_RULE_DEPLOYMENT_STATUS.HEALTH_CHECK]: "cyan",
  healthy: "green",
  hypothesis: "amber",
  info: "grey",
  investigating: "blue",
  low: "blue",
  malicious: "red",
  medium: "amber",
  paused: "amber",
  pending_approval: "amber",
  planned: "blue",
  [SANDBOX_ASYNC_JOB_STATUS.QUEUED]: "grey",
  review: "cyan",
  rejected: "red",
  [DECEPTION_ENVIRONMENT_STATUS.RECOVERY_REQUIRED]: "red",
  [SANDBOX_CONTAINER_STATUS.REMOVED]: "grey",
  [DETECTION_RULE_DEPLOYMENT_STATUS.PENDING]: "grey",
  [DETECTION_RULE_DEPLOYMENT_STATUS.ROLLED_BACK]: "grey",
  [DETECTION_RULE_DEPLOYMENT_STATUS.ROLLBACK_FAILED]: "red",
  [DETECTION_RULE_DEPLOYMENT_STATUS.ROLLING_BACK]: "amber",
  running: "green",
  supported: "green",
  suspicious: "amber",
  superseded: "grey",
  triaging: "cyan",
  unconfigured: "grey",
  validated: "green",
  validation_failed: "red",
};

export function OperationalTag({ value }: { value: string }) {
  return <Tag color={TAG_COLORS[value] ?? "grey"}>{formatEnumLabel(value)}</Tag>;
}

export function OperationalSection({
  title,
  count,
  actions,
  children,
  className = "",
}: {
  title: string;
  count?: number;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`operational-section ${className}`.trim()}>
      <header className="operational-section-header">
        <div>
          <h2>{title}</h2>
          {count !== undefined ? <span>{count}</span> : null}
        </div>
        {actions ? <div className="operational-section-actions">{actions}</div> : null}
      </header>
      <div className="operational-section-body">{children}</div>
    </section>
  );
}

export function EmptyOperationalState({ icon, label }: { icon: ReactNode; label: string }) {
  return <EmptyState className="operational-empty" compact icon={icon} title={label} />;
}

export function RiskScore({ value }: { value: number }) {
  const bounded = Math.max(0, Math.min(100, value));
  return (
    <div className="risk-score" aria-label={`Risk score ${bounded}`}>
      <strong>{bounded}</strong>
      <span><i style={{ width: `${bounded}%` }} /></span>
    </div>
  );
}
