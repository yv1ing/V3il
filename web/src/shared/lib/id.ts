let clientIdCounter = 0;

export function createClientId(scope: string): string {
  clientIdCounter += 1;
  return `v3il-${scope}-${Date.now().toString(36)}-${clientIdCounter.toString(36)}`;
}
