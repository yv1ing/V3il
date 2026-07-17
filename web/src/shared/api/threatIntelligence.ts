import { defineJsonEndpoint } from "./client";
import { buildQuery } from "./query";
import type {
  CreateAttackChainRequest,
  CreateAttackChainResponse,
  CreateAttackerProfileRequest,
  CreateAttackerProfileResponse,
  CreateIntelligenceReportRequest,
  CreateIntelligenceReportResponse,
  CreateIntentAssessmentRequest,
  CreateIntentAssessmentResponse,
  CreateRiskAssessmentRequest,
  CreateRiskAssessmentResponse,
  CreateThreatIndicatorRequest,
  CreateThreatIndicatorResponse,
  QueryAttackChainsParams,
  QueryAttackChainsResponse,
  QueryAttackerProfilesParams,
  QueryAttackerProfilesResponse,
  QueryIntelligenceReportsParams,
  QueryIntelligenceReportsResponse,
  QueryIntentAssessmentsParams,
  QueryIntentAssessmentsResponse,
  QueryRiskAssessmentsParams,
  QueryRiskAssessmentsResponse,
  QueryThreatIndicatorsParams,
  QueryThreatIndicatorsResponse,
} from "./types";

const THREAT_INCIDENTS_PATH = "/api/threat-incidents";

export const queryIntentAssessments = defineJsonEndpoint<
  [incidentId: number, params: QueryIntentAssessmentsParams],
  QueryIntentAssessmentsResponse
>("GET", (incidentId, params) => `${THREAT_INCIDENTS_PATH}/${incidentId}/intent-assessments${buildQuery(params)}`);

export const createIntentAssessment = defineJsonEndpoint<
  [incidentId: number, payload: CreateIntentAssessmentRequest],
  CreateIntentAssessmentResponse
>("POST", (incidentId) => `${THREAT_INCIDENTS_PATH}/${incidentId}/intent-assessments`, (_, payload) => payload);

export const queryAttackChains = defineJsonEndpoint<
  [incidentId: number, params: QueryAttackChainsParams],
  QueryAttackChainsResponse
>("GET", (incidentId, params) => `${THREAT_INCIDENTS_PATH}/${incidentId}/attack-chains${buildQuery(params)}`);

export const createAttackChain = defineJsonEndpoint<
  [incidentId: number, payload: CreateAttackChainRequest],
  CreateAttackChainResponse
>("POST", (incidentId) => `${THREAT_INCIDENTS_PATH}/${incidentId}/attack-chains`, (_, payload) => payload);

export const queryThreatIndicators = defineJsonEndpoint<
  [incidentId: number, params: QueryThreatIndicatorsParams],
  QueryThreatIndicatorsResponse
>("GET", (incidentId, params) => `${THREAT_INCIDENTS_PATH}/${incidentId}/indicators${buildQuery(params)}`);

export const createThreatIndicator = defineJsonEndpoint<
  [incidentId: number, payload: CreateThreatIndicatorRequest],
  CreateThreatIndicatorResponse
>("POST", (incidentId) => `${THREAT_INCIDENTS_PATH}/${incidentId}/indicators`, (_, payload) => payload);

export const queryAttackerProfiles = defineJsonEndpoint<
  [incidentId: number, params: QueryAttackerProfilesParams],
  QueryAttackerProfilesResponse
>("GET", (incidentId, params) => `${THREAT_INCIDENTS_PATH}/${incidentId}/attacker-profiles${buildQuery(params)}`);

export const createAttackerProfile = defineJsonEndpoint<
  [incidentId: number, payload: CreateAttackerProfileRequest],
  CreateAttackerProfileResponse
>("POST", (incidentId) => `${THREAT_INCIDENTS_PATH}/${incidentId}/attacker-profiles`, (_, payload) => payload);

export const queryRiskAssessments = defineJsonEndpoint<
  [incidentId: number, params: QueryRiskAssessmentsParams],
  QueryRiskAssessmentsResponse
>("GET", (incidentId, params) => `${THREAT_INCIDENTS_PATH}/${incidentId}/risk-assessments${buildQuery(params)}`);

export const createRiskAssessment = defineJsonEndpoint<
  [incidentId: number, payload: CreateRiskAssessmentRequest],
  CreateRiskAssessmentResponse
>("POST", (incidentId) => `${THREAT_INCIDENTS_PATH}/${incidentId}/risk-assessments`, (_, payload) => payload);

export const queryIntelligenceReports = defineJsonEndpoint<
  [incidentId: number, params: QueryIntelligenceReportsParams],
  QueryIntelligenceReportsResponse
>("GET", (incidentId, params) => `${THREAT_INCIDENTS_PATH}/${incidentId}/intelligence-reports${buildQuery(params)}`);

export const createIntelligenceReport = defineJsonEndpoint<
  [incidentId: number, payload: CreateIntelligenceReportRequest],
  CreateIntelligenceReportResponse
>("POST", (incidentId) => `${THREAT_INCIDENTS_PATH}/${incidentId}/intelligence-reports`, (_, payload) => payload);
