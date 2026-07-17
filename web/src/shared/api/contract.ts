import {
  SYSTEM_USER_ROLE_VALUES,
} from "./generated/constants";
import type { SystemUserRole } from "./types";

const SYSTEM_USER_ROLE_SET = new Set<string>(SYSTEM_USER_ROLE_VALUES);

export function getSystemUserRoles(): SystemUserRole[] {
  return [...SYSTEM_USER_ROLE_VALUES];
}

export function isSystemUserRole(value: unknown): value is SystemUserRole {
  return typeof value === "string" && SYSTEM_USER_ROLE_SET.has(value);
}
