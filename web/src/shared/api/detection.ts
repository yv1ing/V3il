import { defineJsonEndpoint } from "./client";
import { buildQuery } from "./query";
import type {
  ConfigureManagedHostSensorRequest,
  ConfigureManagedHostSensorResponse,
  CreateDetectionRuleRequest,
  CreateDetectionRuleResponse,
  CreateDetectionRuleVersionRequest,
  CreateDetectionRuleVersionResponse,
  DecideDetectionRuleChangeRequest,
  DetectionRuleChangeResponse,
  DetectionRuleVersionResponse,
  QueryBehaviorDecisionsParams,
  QueryBehaviorDecisionsResponse,
  QueryBehaviorSignalsParams,
  QueryBehaviorSignalsResponse,
  QueryDetectionDeploymentsParams,
  QueryDetectionDeploymentsResponse,
  QueryDetectionRuleChangesParams,
  QueryDetectionRuleChangesResponse,
  QueryDetectionRulesParams,
  QueryDetectionRulesResponse,
  QueryDetectionRuleVersionsParams,
  QueryDetectionRuleVersionsResponse,
  QueryManagedHostSensorsParams,
  QueryManagedHostSensorsResponse,
  ReplayDetectionRuleRequest,
  SubmitDetectionRuleChangeRequest,
} from "./types";

const BASE = "/api/detection";

export const queryDetectionRules = defineJsonEndpoint<[params: QueryDetectionRulesParams], QueryDetectionRulesResponse>(
  "GET", (params) => `${BASE}/rules${buildQuery(params)}`,
);
export const createDetectionRule = defineJsonEndpoint<[payload: CreateDetectionRuleRequest], CreateDetectionRuleResponse>(
  "POST", () => `${BASE}/rules`, (payload) => payload,
);
export const queryDetectionRuleVersions = defineJsonEndpoint<
  [ruleId: number, params: QueryDetectionRuleVersionsParams], QueryDetectionRuleVersionsResponse
>("GET", (ruleId, params) => `${BASE}/rules/${ruleId}/versions${buildQuery(params)}`);
export const createDetectionRuleVersion = defineJsonEndpoint<
  [ruleId: number, payload: CreateDetectionRuleVersionRequest], CreateDetectionRuleVersionResponse
>("POST", (ruleId) => `${BASE}/rules/${ruleId}/versions`, (_, payload) => payload);
export const validateDetectionRuleVersion = defineJsonEndpoint<
  [ruleId: number, versionId: number], DetectionRuleVersionResponse
>("POST", (ruleId, versionId) => `${BASE}/rules/${ruleId}/versions/${versionId}/validate`);
export const replayDetectionRuleVersion = defineJsonEndpoint<
  [ruleId: number, versionId: number, payload: ReplayDetectionRuleRequest], DetectionRuleVersionResponse
>("POST", (ruleId, versionId) => `${BASE}/rules/${ruleId}/versions/${versionId}/replay`, (_ruleId, _versionId, payload) => payload);
export const submitDetectionRuleChange = defineJsonEndpoint<
  [ruleId: number, payload: SubmitDetectionRuleChangeRequest], DetectionRuleChangeResponse
>("POST", (ruleId) => `${BASE}/rules/${ruleId}/changes`, (_, payload) => payload);
export const queryDetectionRuleChanges = defineJsonEndpoint<
  [params: QueryDetectionRuleChangesParams], QueryDetectionRuleChangesResponse
>("GET", (params) => `${BASE}/changes${buildQuery(params)}`);
export const decideDetectionRuleChange = defineJsonEndpoint<
  [changeId: number, payload: DecideDetectionRuleChangeRequest], DetectionRuleChangeResponse
>("POST", (changeId) => `${BASE}/changes/${changeId}/decision`, (_, payload) => payload);
export const queryDetectionDeployments = defineJsonEndpoint<
  [changeId: number, params: QueryDetectionDeploymentsParams], QueryDetectionDeploymentsResponse
>("GET", (changeId, params) => `${BASE}/changes/${changeId}/deployments${buildQuery(params)}`);
export const queryManagedHostSensors = defineJsonEndpoint<
  [params: QueryManagedHostSensorsParams], QueryManagedHostSensorsResponse
>("GET", (params) => `${BASE}/sensors${buildQuery(params)}`);
export const configureManagedHostSensor = defineJsonEndpoint<
  [payload: ConfigureManagedHostSensorRequest], ConfigureManagedHostSensorResponse
>("PUT", () => `${BASE}/sensors`, (payload) => payload);
export const queryBehaviorSignals = defineJsonEndpoint<[params: QueryBehaviorSignalsParams], QueryBehaviorSignalsResponse>(
  "GET", (params) => `${BASE}/signals${buildQuery(params)}`,
);
export const queryBehaviorDecisions = defineJsonEndpoint<[params: QueryBehaviorDecisionsParams], QueryBehaviorDecisionsResponse>(
  "GET", (params) => `${BASE}/decisions${buildQuery(params)}`,
);
