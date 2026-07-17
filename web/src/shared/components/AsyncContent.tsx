import { Spin } from "@douyinfe/semi-ui";
import type { ReactNode } from "react";
import { cx } from "../lib/className";
import { EmptyState } from "./EmptyState";

type AsyncContentProps = {
  loading: boolean;
  empty: boolean;
  children: ReactNode;
  emptyContent?: ReactNode;
  emptyIcon?: ReactNode;
  emptyTitle?: string;
  retainContentWhileLoading?: boolean;
  wrapperClassName?: string;
};

export function AsyncContent({
  loading,
  empty,
  children,
  emptyContent,
  emptyIcon,
  emptyTitle = "No data",
  retainContentWhileLoading = true,
  wrapperClassName,
}: AsyncContentProps) {
  const hideContent = loading && (empty || !retainContentWhileLoading);
  const content = hideContent ? (
    <div className="async-content-placeholder" aria-hidden="true" />
  ) : empty ? (
    emptyContent ?? <EmptyState icon={emptyIcon} title={emptyTitle} />
  ) : children;

  return (
    <Spin spinning={loading} wrapperClassName={cx("async-content", wrapperClassName)}>
      {content}
    </Spin>
  );
}
