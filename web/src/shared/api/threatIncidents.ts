import { apiBlob, defineJsonEndpoint } from "./client";
import { THREAT_INCIDENT_ACTION } from "./generated/constants";
import { buildQuery } from "./query";
import type {
  ActivateInvestigationTaskResponse,
  BlockInvestigationTaskRequest,
  BlockInvestigationTaskResponse,
  CreateInvestigationEvidenceRequest,
  CreateInvestigationEvidenceResponse,
  CreateInvestigationTaskRequest,
  CreateInvestigationTaskResponse,
  EnsureThreatIncidentSessionResponse,
  GetThreatIncidentSessionResponse,
  GetThreatIncidentResponse,
  GetThreatIncidentTimelineParams,
  GetThreatIncidentTimelineResponse,
  GetThreatIncidentWorkspaceResponse,
  QueryAuditEventsParams,
  QueryAuditEventsResponse,
  QueryIncidentBehaviorEventsParams,
  QueryIncidentBehaviorEventsResponse,
  QueryInvestigationEvidenceParams,
  QueryInvestigationEvidenceResponse,
  QueryInvestigationTasksParams,
  QueryInvestigationTasksResponse,
  QueryThreatIncidentsParams,
  QueryThreatIncidentsResponse,
  ReviewInvestigationTaskRequest,
  ReviewInvestigationTaskResponse,
  SubmitInvestigationTaskRequest,
  SubmitInvestigationTaskResponse,
  TransitionThreatIncidentRequest,
  TransitionThreatIncidentResponse,
  UpdateThreatIncidentRequest,
  UpdateThreatIncidentResponse,
} from "./types";

const THREAT_INCIDENTS_PATH = "/api/threat-incidents";

export type ThreatIncidentAction =
  (typeof THREAT_INCIDENT_ACTION)[keyof typeof THREAT_INCIDENT_ACTION];

export const queryThreatIncidents = defineJsonEndpoint<
  [params: QueryThreatIncidentsParams],
  QueryThreatIncidentsResponse
>("GET", (params) => `${THREAT_INCIDENTS_PATH}${buildQuery(params)}`);

export const getThreatIncident = defineJsonEndpoint<[incidentId: number], GetThreatIncidentResponse>(
  "GET",
  (incidentId) => `${THREAT_INCIDENTS_PATH}/${incidentId}`,
);

export const getThreatIncidentWorkspace = defineJsonEndpoint<
  [incidentId: number],
  GetThreatIncidentWorkspaceResponse
>("GET", (incidentId) => `${THREAT_INCIDENTS_PATH}/${incidentId}/workspace`);

export const getThreatIncidentTimeline = defineJsonEndpoint<
  [incidentId: number, params: GetThreatIncidentTimelineParams],
  GetThreatIncidentTimelineResponse
>("GET", (incidentId, params) => `${THREAT_INCIDENTS_PATH}/${incidentId}/timeline${buildQuery(params)}`);

export const updateThreatIncident = defineJsonEndpoint<
  [incidentId: number, payload: UpdateThreatIncidentRequest],
  UpdateThreatIncidentResponse
>("PATCH", (incidentId) => `${THREAT_INCIDENTS_PATH}/${incidentId}`, (_, payload) => payload);

export const transitionThreatIncident = defineJsonEndpoint<
  [incidentId: number, action: ThreatIncidentAction, payload: TransitionThreatIncidentRequest],
  TransitionThreatIncidentResponse
>("POST", (incidentId, action) => `${THREAT_INCIDENTS_PATH}/${incidentId}/${action}`, (_, __, payload) => payload);

export const queryIncidentBehaviorEvents = defineJsonEndpoint<
  [incidentId: number, params: QueryIncidentBehaviorEventsParams],
  QueryIncidentBehaviorEventsResponse
>("GET", (incidentId, params) => `${THREAT_INCIDENTS_PATH}/${incidentId}/behavior-events${buildQuery(params)}`);

export const queryInvestigationTasks = defineJsonEndpoint<
  [incidentId: number, params: QueryInvestigationTasksParams],
  QueryInvestigationTasksResponse
>("GET", (incidentId, params) => `${THREAT_INCIDENTS_PATH}/${incidentId}/investigation-tasks${buildQuery(params)}`);

export const createInvestigationTask = defineJsonEndpoint<
  [incidentId: number, payload: CreateInvestigationTaskRequest],
  CreateInvestigationTaskResponse
>("POST", (incidentId) => `${THREAT_INCIDENTS_PATH}/${incidentId}/investigation-tasks`, (_, payload) => payload);

export const activateInvestigationTask = defineJsonEndpoint<
  [incidentId: number, taskId: number],
  ActivateInvestigationTaskResponse
>("POST", (incidentId, taskId) => `${THREAT_INCIDENTS_PATH}/${incidentId}/investigation-tasks/${taskId}/activate`);

export const blockInvestigationTask = defineJsonEndpoint<
  [incidentId: number, taskId: number, payload: BlockInvestigationTaskRequest],
  BlockInvestigationTaskResponse
>("POST", (incidentId, taskId) => `${THREAT_INCIDENTS_PATH}/${incidentId}/investigation-tasks/${taskId}/block`, (_, __, payload) => payload);

export const submitInvestigationTask = defineJsonEndpoint<
  [incidentId: number, taskId: number, payload: SubmitInvestigationTaskRequest],
  SubmitInvestigationTaskResponse
>("POST", (incidentId, taskId) => `${THREAT_INCIDENTS_PATH}/${incidentId}/investigation-tasks/${taskId}/submit`, (_, __, payload) => payload);

export const reviewInvestigationTask = defineJsonEndpoint<
  [incidentId: number, taskId: number, payload: ReviewInvestigationTaskRequest],
  ReviewInvestigationTaskResponse
>("POST", (incidentId, taskId) => `${THREAT_INCIDENTS_PATH}/${incidentId}/investigation-tasks/${taskId}/review`, (_, __, payload) => payload);

export const createInvestigationEvidence = defineJsonEndpoint<
  [incidentId: number, taskId: number, payload: CreateInvestigationEvidenceRequest],
  CreateInvestigationEvidenceResponse
>("POST", (incidentId, taskId) => `${THREAT_INCIDENTS_PATH}/${incidentId}/investigation-tasks/${taskId}/evidence`, (_, __, payload) => payload);

export const queryInvestigationEvidence = defineJsonEndpoint<
  [incidentId: number, params: QueryInvestigationEvidenceParams],
  QueryInvestigationEvidenceResponse
>("GET", (incidentId, params) => `${THREAT_INCIDENTS_PATH}/${incidentId}/investigation-evidence${buildQuery(params)}`);

export const queryAuditEvents = defineJsonEndpoint<
  [incidentId: number, params: QueryAuditEventsParams],
  QueryAuditEventsResponse
>("GET", (incidentId, params) => `${THREAT_INCIDENTS_PATH}/${incidentId}/audit-events${buildQuery(params)}`);

export const getThreatIncidentSession = defineJsonEndpoint<
  [incidentId: number],
  GetThreatIncidentSessionResponse
>("GET", (incidentId) => `${THREAT_INCIDENTS_PATH}/${incidentId}/session`);

export const ensureThreatIncidentSession = defineJsonEndpoint<
  [incidentId: number],
  EnsureThreatIncidentSessionResponse
>("PUT", (incidentId) => `${THREAT_INCIDENTS_PATH}/${incidentId}/session`);

export const downloadThreatIncidentReport = (incidentId: number, reportId: number) => (
  apiBlob(`${THREAT_INCIDENTS_PATH}/${incidentId}/reports/${reportId}/download`)
);
