import { Tag } from "@douyinfe/semi-ui";
import { Box } from "lucide-react";
import type { ReactNode } from "react";
import type { SandboxContainer } from "../../shared/api/types";
import { OptionListSelect } from "../../shared/components/OptionListSelect";
import type { OptionListResult } from "../../shared/hooks/useOptionList";
import { cx } from "../../shared/lib/className";
import { SANDBOX_CONTAINER_STATUS_COLOR, SANDBOX_CONTAINER_STATUS_LABEL } from "../../shared/lib/labels";

type SandboxSelectorProps = {
  containers: SandboxContainer[];
  source: OptionListResult<SandboxContainer>;
  value: number | null;
  className?: string;
  disabled?: boolean;
  prefix?: ReactNode;
  placeholder?: string;
  emptyContent?: string;
  ariaLabel?: string;
  onChange: (containerId: number | null) => void;
};

const CONTAINER_ID_PREVIEW_LENGTH = 12;

export function SandboxSelector({
  containers,
  source,
  value,
  className = "",
  disabled = false,
  prefix = <Box size={15} />,
  placeholder = "Select sandbox",
  emptyContent = "No sandbox",
  ariaLabel = "Select sandbox",
  onChange,
}: SandboxSelectorProps) {
  const optionList = containers.map((container) => ({
    label: renderContainerOption(container),
    value: container.id,
  }));
  const selectedContainer = source.knownItems.find((container) => container.id === value) ?? null;

  return (
    <div className={cx("sandbox-selector", className)} title={ariaLabel}>
      <OptionListSelect
        source={source}
        aria-label={ariaLabel}
        prefix={prefix}
        value={value ?? undefined}
        optionList={optionList}
        renderSelectedItem={() => selectedContainer?.container_name ?? renderContainerId(selectedContainer?.container_hash ?? "")}
        placeholder={source.busy ? "Loading sandboxes" : placeholder}
        emptyContent={emptyContent}
        disabled={disabled || containers.length === 0}
        showClear={!disabled}
        onClear={() => onChange(null)}
        onChange={(nextValue) => onChange(typeof nextValue === "number" ? nextValue : null)}
      />
    </div>
  );
}

function renderContainerOption(container: SandboxContainer) {
  return (
    <div className="sandbox-selector-option">
      <span>{container.container_name}</span>
      <small>Container ID: {renderContainerId(container.container_hash)}</small>
      <Tag color={SANDBOX_CONTAINER_STATUS_COLOR[container.status]}>
        {SANDBOX_CONTAINER_STATUS_LABEL[container.status]}
      </Tag>
    </div>
  );
}

function renderContainerId(containerHash: string) {
  if (!containerHash) return "Pending create";
  return containerHash.slice(0, CONTAINER_ID_PREVIEW_LENGTH);
}
