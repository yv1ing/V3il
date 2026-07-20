import { apiForm, defineJsonEndpoint } from "./client";
import { buildQuery } from "./query";
import type {
  ApproveDeceptionRevisionResponse,
  CreateDeceptionEnvironmentRequest,
  CreateDeceptionEnvironmentResponse,
  CreateObservedWorkloadRequest,
  CreateObservedWorkloadResponse,
  DeceptionRevisionDecisionRequest,
  ExecuteDeceptionRevisionResponse,
  GetDeceptionEnvironmentResponse,
  GetDeceptionEnvironmentSessionResponse,
  GetDeceptionReferencesResponse,
  ListObservedWorkloadsResponse,
  PauseDeceptionEnvironmentResponse,
  PlanDeceptionRevisionRequest,
  PlanDeceptionRevisionResponse,
  QueryBehaviorEventsParams,
  QueryBehaviorEventsResponse,
  QueryDeceptionEnvironmentsParams,
  QueryDeceptionEnvironmentsResponse,
  QueryDeceptionRevisionsParams,
  QueryDeceptionRevisionsResponse,
  RejectDeceptionRevisionResponse,
  RecoverDeceptionRevisionResponse,
  ResumeDeceptionEnvironmentResponse,
  RetireDeceptionEnvironmentResponse,
  StopObservedWorkloadResponse,
  UpdateDeceptionEnvironmentRequest,
  UpdateDeceptionEnvironmentResponse,
} from "./types";

const DECEPTION_ENVIRONMENTS_PATH = "/api/deception-environments";

export const queryDeceptionEnvironments = defineJsonEndpoint<
  [params: QueryDeceptionEnvironmentsParams],
  QueryDeceptionEnvironmentsResponse
>("GET", (params) => `${DECEPTION_ENVIRONMENTS_PATH}${buildQuery(params)}`);

export function createDeceptionEnvironment(payload: CreateDeceptionEnvironmentRequest) {
  const form = new FormData();
  form.set("name", payload.name);
  form.set("description", payload.description);
  if (payload.sandbox_container_id) form.set("sandbox_container_id", String(payload.sandbox_container_id));
  form.set("host_id", String(payload.host_id));
  form.set("image_id", String(payload.image_id));
  form.set("egress_mode", payload.egress_mode);
  form.set("adaptation_mode", payload.adaptation_mode);
  if (payload.egress_proxy_id) form.set("egress_proxy_id", String(payload.egress_proxy_id));
  payload.reference_urls?.forEach((url) => form.append("reference_urls", url));
  payload.files?.forEach((file) => form.append("files", file));
  return apiForm<CreateDeceptionEnvironmentResponse>(DECEPTION_ENVIRONMENTS_PATH, form);
}

export const getDeceptionEnvironment = defineJsonEndpoint<
  [environmentId: number],
  GetDeceptionEnvironmentResponse
>("GET", (environmentId) => `${DECEPTION_ENVIRONMENTS_PATH}/${environmentId}`);

export const getDeceptionReferences = defineJsonEndpoint<
  [environmentId: number],
  GetDeceptionReferencesResponse
>("GET", (environmentId) => `${DECEPTION_ENVIRONMENTS_PATH}/${environmentId}/references`);

export const getDeceptionEnvironmentSession = defineJsonEndpoint<
  [environmentId: number],
  GetDeceptionEnvironmentSessionResponse
>("GET", (environmentId) => `${DECEPTION_ENVIRONMENTS_PATH}/${environmentId}/session`);

export const updateDeceptionEnvironment = defineJsonEndpoint<
  [environmentId: number, payload: UpdateDeceptionEnvironmentRequest],
  UpdateDeceptionEnvironmentResponse
>("PATCH", (environmentId) => `${DECEPTION_ENVIRONMENTS_PATH}/${environmentId}`, (_, payload) => payload);

export const pauseDeceptionEnvironment = defineJsonEndpoint<
  [environmentId: number],
  PauseDeceptionEnvironmentResponse
>("POST", (environmentId) => `${DECEPTION_ENVIRONMENTS_PATH}/${environmentId}/pause`);

export const resumeDeceptionEnvironment = defineJsonEndpoint<
  [environmentId: number],
  ResumeDeceptionEnvironmentResponse
>("POST", (environmentId) => `${DECEPTION_ENVIRONMENTS_PATH}/${environmentId}/resume`);

export const retireDeceptionEnvironment = defineJsonEndpoint<
  [environmentId: number],
  RetireDeceptionEnvironmentResponse
>("POST", (environmentId) => `${DECEPTION_ENVIRONMENTS_PATH}/${environmentId}/retire`);

export const queryDeceptionRevisions = defineJsonEndpoint<
  [environmentId: number, params: QueryDeceptionRevisionsParams],
  QueryDeceptionRevisionsResponse
>("GET", (environmentId, params) => `${DECEPTION_ENVIRONMENTS_PATH}/${environmentId}/revisions${buildQuery(params)}`);

export const planDeceptionRevision = defineJsonEndpoint<
  [environmentId: number, payload: PlanDeceptionRevisionRequest],
  PlanDeceptionRevisionResponse
>("POST", (environmentId) => `${DECEPTION_ENVIRONMENTS_PATH}/${environmentId}/revisions`, (_, payload) => payload);

export const approveDeceptionRevision = defineJsonEndpoint<
  [environmentId: number, revisionId: number, payload: DeceptionRevisionDecisionRequest],
  ApproveDeceptionRevisionResponse
>(
  "POST",
  (environmentId, revisionId) => `${DECEPTION_ENVIRONMENTS_PATH}/${environmentId}/revisions/${revisionId}/approve`,
  (_, __, payload) => payload,
);

export const rejectDeceptionRevision = defineJsonEndpoint<
  [environmentId: number, revisionId: number, payload: DeceptionRevisionDecisionRequest],
  RejectDeceptionRevisionResponse
>(
  "POST",
  (environmentId, revisionId) => `${DECEPTION_ENVIRONMENTS_PATH}/${environmentId}/revisions/${revisionId}/reject`,
  (_, __, payload) => payload,
);

export const executeDeceptionRevision = defineJsonEndpoint<
  [environmentId: number, revisionId: number],
  ExecuteDeceptionRevisionResponse
>("POST", (environmentId, revisionId) => (
  `${DECEPTION_ENVIRONMENTS_PATH}/${environmentId}/revisions/${revisionId}/execute`
));

export const recoverDeceptionRevision = defineJsonEndpoint<
  [environmentId: number, revisionId: number],
  RecoverDeceptionRevisionResponse
>("POST", (environmentId, revisionId) => (
  `${DECEPTION_ENVIRONMENTS_PATH}/${environmentId}/revisions/${revisionId}/recover`
));

export const queryBehaviorEvents = defineJsonEndpoint<
  [environmentId: number, params: QueryBehaviorEventsParams],
  QueryBehaviorEventsResponse
>("GET", (environmentId, params) => (
  `${DECEPTION_ENVIRONMENTS_PATH}/${environmentId}/behavior-events${buildQuery(params)}`
));

export const listObservedWorkloads = defineJsonEndpoint<
  [environmentId: number],
  ListObservedWorkloadsResponse
>("GET", (environmentId) => `${DECEPTION_ENVIRONMENTS_PATH}/${environmentId}/workloads`);

export const startObservedWorkload = defineJsonEndpoint<
  [environmentId: number, payload: CreateObservedWorkloadRequest],
  CreateObservedWorkloadResponse
>("POST", (environmentId) => `${DECEPTION_ENVIRONMENTS_PATH}/${environmentId}/workloads`, (_, payload) => payload);

export const stopObservedWorkload = defineJsonEndpoint<
  [environmentId: number, runId: string],
  StopObservedWorkloadResponse
>("POST", (environmentId, runId) => (
  `${DECEPTION_ENVIRONMENTS_PATH}/${environmentId}/workloads/${encodeURIComponent(runId)}/stop`
));
