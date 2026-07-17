import {
  SANDBOX_CONTAINER_EGRESS_MODE_VALUES,
  SANDBOX_CONTAINER_STATUS,
  SANDBOX_CONTAINER_STATUS_VALUES,
  SYSTEM_USER_ROLE,
  SYSTEM_USER_ROLE_VALUES,
} from "../api/generated/constants";
import type {
  SandboxContainerEgressMode,
  SandboxContainerStatus,
  SystemUserRole,
} from "../api/types";

type SemiTagColor = "amber" | "green" | "red" | "grey" | "blue" | "cyan";

export const SYSTEM_USER_ROLE_LABEL = labelsFromEnum<SystemUserRole>(SYSTEM_USER_ROLE_VALUES);
export const SANDBOX_CONTAINER_EGRESS_MODE_LABEL = labelsFromEnum<SandboxContainerEgressMode>(SANDBOX_CONTAINER_EGRESS_MODE_VALUES);
export const SANDBOX_CONTAINER_STATUS_LABEL = labelsFromEnum<SandboxContainerStatus>(SANDBOX_CONTAINER_STATUS_VALUES);

export const SYSTEM_USER_ROLE_COLOR = colorsFromEnum<SystemUserRole>(SYSTEM_USER_ROLE_VALUES, {
  [SYSTEM_USER_ROLE.ADMIN]: "red",
  [SYSTEM_USER_ROLE.USER]: "blue",
});
export const SANDBOX_CONTAINER_STATUS_COLOR = colorsFromEnum<SandboxContainerStatus>(SANDBOX_CONTAINER_STATUS_VALUES, {
  [SANDBOX_CONTAINER_STATUS.CREATED]: "blue",
  [SANDBOX_CONTAINER_STATUS.RUNNING]: "green",
  [SANDBOX_CONTAINER_STATUS.PAUSED]: "amber",
  [SANDBOX_CONTAINER_STATUS.STOPPED]: "grey",
  [SANDBOX_CONTAINER_STATUS.ERROR]: "red",
});

function labelsFromEnum<T extends string>(
  values: readonly T[],
  overrides: Partial<Record<T, string>> = {},
): Record<T, string> {
  return Object.fromEntries(values.map((value) => [value, overrides[value] ?? formatEnumLabel(value)])) as Record<T, string>;
}

function colorsFromEnum<T extends string>(
  values: readonly T[],
  colors: Partial<Record<T, SemiTagColor>>,
): Record<T, SemiTagColor> {
  return Object.fromEntries(values.map((value) => [value, colors[value] ?? "grey"])) as Record<T, SemiTagColor>;
}

export function formatEnumLabel(value: string): string {
  return value.split("_").map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(" ");
}
