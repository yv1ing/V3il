export const DEFAULT_ADMIN_PATH = "/command-center";
export const LOGIN_PATH = "/login";
export const AGENT_CONSOLE_PATH = "/playground";

export function agentSessionPath(sessionId: string) {
  return `${AGENT_CONSOLE_PATH}/session/${encodeURIComponent(sessionId)}`;
}
