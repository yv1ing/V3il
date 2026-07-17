import { Empty } from "@douyinfe/semi-ui";
import type { ReactNode } from "react";
import { cx } from "../lib/className";

type EmptyStateProps = {
  icon: ReactNode;
  title: string;
  description?: ReactNode;
  className?: string;
  compact?: boolean;
};

export function EmptyState({
  icon,
  title,
  description = "",
  className,
  compact = false,
}: EmptyStateProps) {
  return (
    <div className={cx("app-empty-state", compact && "app-empty-state-compact", className)}>
      <Empty image={icon} title={title} description={description} />
    </div>
  );
}
