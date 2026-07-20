import type { components, paths } from "./generated/schema";

type JsonRequestBody<Operation> = Operation extends {
  requestBody: { content: { "application/json": infer Body } };
}
  ? Body
  : never;

type MultipartRequestBody<Operation> = Operation extends {
  requestBody: { content: { "multipart/form-data": infer Body } };
}
  ? Body
  : never;

type JsonContent<Response> = Response extends {
  content: { "application/json": infer Payload };
}
  ? Payload
  : never;

type JsonResponse<Operation> = Operation extends { responses: infer Responses }
  ? {
      [Status in keyof Responses]: `${Status & (string | number)}` extends `2${string}`
        ? JsonContent<Responses[Status]>
        : never;
    }[keyof Responses]
  : never;

type QueryParameters<Operation> = Operation extends { parameters: { query?: infer Query } } ? Query : never;
type PathParameters<Operation> = Operation extends { parameters: { path?: infer Params } } ? Params : never;

export type CommonResponsePayload = components["schemas"]["CommonResponse"];
export type ProblemDetails = components["schemas"]["ProblemDetails"];

export type LoginRequest = JsonRequestBody<paths["/api/system-users/login"]["post"]>;
export type LoginResponse = JsonResponse<paths["/api/system-users/login"]["post"]>;

export type QuerySystemUsersParams = QueryParameters<paths["/api/system-users"]["get"]>;
export type QuerySystemUsersResponse = JsonResponse<paths["/api/system-users"]["get"]>;
export type SystemUser = NonNullable<QuerySystemUsersResponse["data"]>["items"][number];
export type SystemUserRole = components["schemas"]["SystemUserRole"];

export type CreateSystemUserRequest = JsonRequestBody<paths["/api/system-users"]["post"]>;
export type CreateSystemUserResponse = JsonResponse<paths["/api/system-users"]["post"]>;

export type SystemUserPathParams = PathParameters<paths["/api/system-users/{id}"]["patch"]>;
export type UpdateSystemUserRequest = JsonRequestBody<paths["/api/system-users/{id}"]["patch"]>;
export type UpdateSystemUserResponse = JsonResponse<paths["/api/system-users/{id}"]["patch"]>;
export type RetireSystemUserResponse = JsonResponse<paths["/api/system-users/{id}/retire"]["post"]>;

export type QueryManagedHostsParams = QueryParameters<paths["/api/hosts"]["get"]>;
export type QueryManagedHostsResponse = JsonResponse<paths["/api/hosts"]["get"]>;
export type ManagedHost = NonNullable<QueryManagedHostsResponse["data"]>["items"][number];

export type CreateManagedHostRequest = JsonRequestBody<paths["/api/hosts"]["post"]>;
export type CreateManagedHostResponse = JsonResponse<paths["/api/hosts"]["post"]>;

export type ManagedHostPathParams = PathParameters<paths["/api/hosts/{id}"]["patch"]>;
export type UpdateManagedHostRequest = JsonRequestBody<paths["/api/hosts/{id}"]["patch"]>;
export type UpdateManagedHostResponse = JsonResponse<paths["/api/hosts/{id}"]["patch"]>;
export type RetireManagedHostResponse = JsonResponse<paths["/api/hosts/{id}/retire"]["post"]>;

export type RemoveManagedHostImageRequest = JsonRequestBody<paths["/api/hosts/{id}/images/remove"]["post"]>;
export type RemoveManagedHostImageResponse = JsonResponse<paths["/api/hosts/{id}/images/remove"]["post"]>;

export type QueryEgressProxiesParams = QueryParameters<paths["/api/egress-proxies"]["get"]>;
export type QueryEgressProxiesResponse = JsonResponse<paths["/api/egress-proxies"]["get"]>;
export type EgressProxy = NonNullable<QueryEgressProxiesResponse["data"]>["items"][number];
export type EgressProxyType = components["schemas"]["EgressProxyType"];

export type CreateEgressProxyRequest = JsonRequestBody<paths["/api/egress-proxies"]["post"]>;
export type CreateEgressProxyResponse = JsonResponse<paths["/api/egress-proxies"]["post"]>;

export type EgressProxyPathParams = PathParameters<paths["/api/egress-proxies/{id}"]["patch"]>;
export type UpdateEgressProxyRequest = JsonRequestBody<paths["/api/egress-proxies/{id}"]["patch"]>;
export type UpdateEgressProxyResponse = JsonResponse<paths["/api/egress-proxies/{id}"]["patch"]>;
export type RetireEgressProxyResponse = JsonResponse<paths["/api/egress-proxies/{id}/retire"]["post"]>;
export type TestEgressProxyPathParams = PathParameters<paths["/api/egress-proxies/{id}/test"]["post"]>;
export type TestEgressProxyResponse = JsonResponse<paths["/api/egress-proxies/{id}/test"]["post"]>;

export type InstanceConfig = components["schemas"]["InstanceConfigSchema"];
export type AgentConfig = components["schemas"]["AgentConfig"];
export type AgentRuntimeConfig = components["schemas"]["AgentRuntimeConfig"];
export type BehaviorCaptureConfig = components["schemas"]["BehaviorCaptureConfig"];
export type ThreatAutomationConfig = components["schemas"]["ThreatAutomationConfig"];
export type LightRAGConfig = components["schemas"]["LightRAGConfig"];
export type GetInstanceConfigResponse = JsonResponse<paths["/api/system-config/instance"]["get"]>;
export type UpdateInstanceConfigRequest = JsonRequestBody<paths["/api/system-config/instance"]["patch"]>;
export type UpdateInstanceConfigResponse = JsonResponse<paths["/api/system-config/instance"]["patch"]>;
export type QueryKnowledgeDocumentsParams = QueryParameters<paths["/api/knowledges/documents"]["get"]>;
export type QueryKnowledgeDocumentsResponse = JsonResponse<paths["/api/knowledges/documents"]["get"]>;
export type QueryKnowledgeDocumentsData = NonNullable<QueryKnowledgeDocumentsResponse["data"]>;
export type KnowledgeDocument = QueryKnowledgeDocumentsData["items"][number];
export type KnowledgeDocumentStatus = KnowledgeDocument["status"];
export type KnowledgeDocumentStatusCounts = QueryKnowledgeDocumentsData["status_counts"];
export type UploadKnowledgeDocumentsResponse = JsonResponse<paths["/api/knowledges/documents"]["post"]>;
export type KnowledgeDocumentPathParams = PathParameters<paths["/api/knowledges/documents/{document_id}"]["get"]>;
export type GetKnowledgeDocumentResponse = JsonResponse<paths["/api/knowledges/documents/{document_id}"]["get"]>;
export type KnowledgeDocumentDetail = NonNullable<GetKnowledgeDocumentResponse["data"]>;
export type DeleteKnowledgeDocumentResponse = JsonResponse<paths["/api/knowledges/documents/{document_id}"]["delete"]>;
export type QueryKnowledgeVectorsParams = QueryParameters<paths["/api/knowledges/vectors"]["get"]>;
export type QueryKnowledgeVectorsResponse = JsonResponse<paths["/api/knowledges/vectors"]["get"]>;
export type KnowledgeVector = NonNullable<QueryKnowledgeVectorsResponse["data"]>["items"][number];
export type KnowledgeVectorPathParams = PathParameters<paths["/api/knowledges/vectors/{vector_id}"]["get"]>;
export type GetKnowledgeVectorResponse = JsonResponse<paths["/api/knowledges/vectors/{vector_id}"]["get"]>;
export type KnowledgeVectorDetail = NonNullable<GetKnowledgeVectorResponse["data"]>;
export type GetKnowledgeGraphParams = QueryParameters<paths["/api/knowledges/graph"]["get"]>;
export type GetKnowledgeGraphResponse = JsonResponse<paths["/api/knowledges/graph"]["get"]>;
export type SearchKnowledgeGraphParams = QueryParameters<paths["/api/knowledges/graph/search"]["get"]>;
export type SearchKnowledgeGraphResponse = JsonResponse<paths["/api/knowledges/graph/search"]["get"]>;
export type KnowledgeGraph = NonNullable<GetKnowledgeGraphResponse["data"]>;
export type KnowledgeGraphNode = KnowledgeGraph["nodes"][number];

export type QuerySandboxImagesParams = QueryParameters<paths["/api/sandbox-images"]["get"]>;
export type QuerySandboxImagesResponse = JsonResponse<paths["/api/sandbox-images"]["get"]>;
export type SandboxImage = NonNullable<QuerySandboxImagesResponse["data"]>["items"][number];

export type CreateSandboxImageRequest = JsonRequestBody<paths["/api/sandbox-images"]["post"]>;
export type CreateSandboxImageResponse = JsonResponse<paths["/api/sandbox-images"]["post"]>;

export type SandboxImagePathParams = PathParameters<paths["/api/sandbox-images/{id}/retire"]["post"]>;
export type RetireSandboxImageResponse = JsonResponse<paths["/api/sandbox-images/{id}/retire"]["post"]>;

export type ListManagedHostImagesResponse = JsonResponse<paths["/api/hosts/{id}/images"]["get"]>;
export type ManagedHostImage = NonNullable<ListManagedHostImagesResponse["data"]>["items"][number];
export type PullManagedHostImagesRequest = JsonRequestBody<paths["/api/hosts/{id}/images/pull"]["post"]>;
export type PullManagedHostImagesResponse = JsonResponse<paths["/api/hosts/{id}/images/pull"]["post"]>;

export type QuerySandboxContainersParams = QueryParameters<paths["/api/sandbox-containers"]["get"]>;
export type QuerySandboxContainersResponse = JsonResponse<paths["/api/sandbox-containers"]["get"]>;
export type SandboxContainer = NonNullable<QuerySandboxContainersResponse["data"]>["items"][number];
export type QueryAvailableSandboxContainersParams = QueryParameters<paths["/api/sandbox-containers/available"]["get"]>;
export type QueryAvailableSandboxContainersResponse = JsonResponse<paths["/api/sandbox-containers/available"]["get"]>;
export type SandboxContainerStatus = components["schemas"]["SandboxContainerStatus"];
export type SandboxContainerProtocol = components["schemas"]["SandboxContainerProtocol"];
export type SandboxContainerEgressMode = components["schemas"]["SandboxContainerEgressMode"];
export type SandboxContainerPortMapping = components["schemas"]["SandboxContainerPortMapping"];
export type SandboxContainerHostOption = components["schemas"]["SandboxContainerHostOptionSchema"];
export type QuerySandboxContainerHostOptionsParams = QueryParameters<paths["/api/sandbox-containers/create-options/hosts"]["get"]>;
export type QuerySandboxContainerHostOptionsResponse = JsonResponse<paths["/api/sandbox-containers/create-options/hosts"]["get"]>;
export type QuerySandboxContainerImageOptionsParams = QueryParameters<paths["/api/sandbox-containers/create-options/images"]["get"]>;
export type QuerySandboxContainerImageOptionsResponse = JsonResponse<paths["/api/sandbox-containers/create-options/images"]["get"]>;

export type CreateSandboxContainerRequest = JsonRequestBody<paths["/api/sandbox-containers"]["post"]>;
export type CreateSandboxContainerResponse = JsonResponse<paths["/api/sandbox-containers"]["post"]>;

export type SandboxContainerPathParams = PathParameters<paths["/api/sandbox-containers/{id}/remove"]["post"]>;
export type RemoveSandboxContainerResponse = JsonResponse<paths["/api/sandbox-containers/{id}/remove"]["post"]>;
export type StartSandboxContainerPathParams = PathParameters<paths["/api/sandbox-containers/{id}/start"]["post"]>;
export type StartSandboxContainerResponse = JsonResponse<paths["/api/sandbox-containers/{id}/start"]["post"]>;
export type StopSandboxContainerPathParams = PathParameters<paths["/api/sandbox-containers/{id}/stop"]["post"]>;
export type StopSandboxContainerResponse = JsonResponse<paths["/api/sandbox-containers/{id}/stop"]["post"]>;
export type PauseSandboxContainerPathParams = PathParameters<paths["/api/sandbox-containers/{id}/pause"]["post"]>;
export type PauseSandboxContainerResponse = JsonResponse<paths["/api/sandbox-containers/{id}/pause"]["post"]>;
export type ResumeSandboxContainerPathParams = PathParameters<paths["/api/sandbox-containers/{id}/resume"]["post"]>;
export type ResumeSandboxContainerResponse = JsonResponse<paths["/api/sandbox-containers/{id}/resume"]["post"]>;
export type UpdateSandboxContainerEgressPathParams = PathParameters<paths["/api/sandbox-containers/{id}/egress"]["patch"]>;
export type UpdateSandboxContainerEgressRequest = JsonRequestBody<paths["/api/sandbox-containers/{id}/egress"]["patch"]>;
export type UpdateSandboxContainerEgressResponse = JsonResponse<paths["/api/sandbox-containers/{id}/egress"]["patch"]>;

export type ListContainerFilesParams = QueryParameters<paths["/api/sandbox-containers/{id}/files"]["get"]>;
export type ListContainerFilesResponse = JsonResponse<paths["/api/sandbox-containers/{id}/files"]["get"]>;
export type ContainerFileInfo = components["schemas"]["ContainerFileInfo"];
export type ContainerFileType = components["schemas"]["ContainerFileType"];

export type ReadContainerFileParams = QueryParameters<paths["/api/sandbox-containers/{id}/files/read"]["get"]>;
export type ReadContainerFileResponse = JsonResponse<paths["/api/sandbox-containers/{id}/files/read"]["get"]>;

export type ContainerFileWriteRequest = JsonRequestBody<paths["/api/sandbox-containers/{id}/files/write"]["post"]>;
export type ContainerFileWriteResponse = JsonResponse<paths["/api/sandbox-containers/{id}/files/write"]["post"]>;
export type ContainerFileUploadRequest = MultipartRequestBody<paths["/api/sandbox-containers/{id}/files/upload"]["post"]>;
export type ContainerFileUploadResponse = JsonResponse<paths["/api/sandbox-containers/{id}/files/upload"]["post"]>;
export type DownloadContainerFilesParams = QueryParameters<paths["/api/sandbox-containers/{id}/files/download"]["get"]>;
export type ContainerFileCopyRequest = JsonRequestBody<paths["/api/sandbox-containers/{id}/files/copy"]["post"]>;
export type ContainerFileCopyResponse = JsonResponse<paths["/api/sandbox-containers/{id}/files/copy"]["post"]>;
export type ContainerFileMoveRequest = JsonRequestBody<paths["/api/sandbox-containers/{id}/files/move"]["post"]>;
export type ContainerFileMoveResponse = JsonResponse<paths["/api/sandbox-containers/{id}/files/move"]["post"]>;
export type ContainerFileDeleteRequest = JsonRequestBody<paths["/api/sandbox-containers/{id}/files/delete"]["post"]>;
export type ContainerFileDeleteResponse = JsonResponse<paths["/api/sandbox-containers/{id}/files/delete"]["post"]>;
export type ContainerFileMkdirRequest = JsonRequestBody<paths["/api/sandbox-containers/{id}/files/mkdir"]["post"]>;
export type ContainerFileMkdirResponse = JsonResponse<paths["/api/sandbox-containers/{id}/files/mkdir"]["post"]>;

export type DeceptionEnvironment = components["schemas"]["DeceptionEnvironmentSchema"];
export type DeceptionEnvironmentStatus = components["schemas"]["DeceptionEnvironmentStatus"];
export type DeceptionAdaptationMode = components["schemas"]["DeceptionAdaptationMode"];
export type DeceptionReferenceBundle = components["schemas"]["DeceptionReferenceBundleSchema"];
export type DeceptionReferenceFile = components["schemas"]["DeceptionReferenceFileSchema"];
export type DeceptionReferenceFileState = components["schemas"]["DeceptionReferenceFileState"];
export type DeceptionRevision = components["schemas"]["DeceptionRevisionSchema"];
export type DeceptionRevisionStatus = components["schemas"]["DeceptionRevisionStatus"];
export type DeceptionRevisionStep = components["schemas"]["DeceptionRevisionStepSchema"];
export type DeceptionServiceSpec = components["schemas"]["DeceptionServiceSpec"];
export type DeceptionContainerSpec = components["schemas"]["DeceptionContainerSpec"];
export type ObservedWorkload = components["schemas"]["ObservedWorkloadSchema"];
export type BehaviorEvent = components["schemas"]["BehaviorEventSchema"];
export type BehaviorEventCategory = components["schemas"]["BehaviorEventCategory"];
export type QueryDeceptionEnvironmentsParams = QueryParameters<paths["/api/deception-environments"]["get"]>;
export type QueryDeceptionEnvironmentsResponse = JsonResponse<paths["/api/deception-environments"]["get"]>;
type CreateDeceptionEnvironmentMultipart = MultipartRequestBody<paths["/api/deception-environments"]["post"]>;
export type CreateDeceptionEnvironmentRequest = Omit<CreateDeceptionEnvironmentMultipart, "files"> & {
  files?: File[] | null;
};
export type CreateDeceptionEnvironmentResponse = JsonResponse<paths["/api/deception-environments"]["post"]>;
export type DeceptionEnvironmentPathParams = PathParameters<paths["/api/deception-environments/{id}"]["get"]>;
export type GetDeceptionEnvironmentResponse = JsonResponse<paths["/api/deception-environments/{id}"]["get"]>;
export type GetDeceptionReferencesResponse = JsonResponse<paths["/api/deception-environments/{id}/references"]["get"]>;
export type GetDeceptionEnvironmentSessionResponse = JsonResponse<paths["/api/deception-environments/{id}/session"]["get"]>;
export type UpdateDeceptionEnvironmentRequest = JsonRequestBody<paths["/api/deception-environments/{id}"]["patch"]>;
export type UpdateDeceptionEnvironmentResponse = JsonResponse<paths["/api/deception-environments/{id}"]["patch"]>;
export type PauseDeceptionEnvironmentResponse = JsonResponse<paths["/api/deception-environments/{id}/pause"]["post"]>;
export type ResumeDeceptionEnvironmentResponse = JsonResponse<paths["/api/deception-environments/{id}/resume"]["post"]>;
export type RetireDeceptionEnvironmentResponse = JsonResponse<paths["/api/deception-environments/{id}/retire"]["post"]>;
export type QueryDeceptionRevisionsParams = QueryParameters<paths["/api/deception-environments/{id}/revisions"]["get"]>;
export type QueryDeceptionRevisionsResponse = JsonResponse<paths["/api/deception-environments/{id}/revisions"]["get"]>;
export type PlanDeceptionRevisionRequest = JsonRequestBody<paths["/api/deception-environments/{id}/revisions"]["post"]>;
export type PlanDeceptionRevisionResponse = JsonResponse<paths["/api/deception-environments/{id}/revisions"]["post"]>;
export type DeceptionRevisionDecisionRequest = JsonRequestBody<paths["/api/deception-environments/{id}/revisions/{revision_id}/approve"]["post"]>;
export type ApproveDeceptionRevisionResponse = JsonResponse<paths["/api/deception-environments/{id}/revisions/{revision_id}/approve"]["post"]>;
export type RejectDeceptionRevisionResponse = JsonResponse<paths["/api/deception-environments/{id}/revisions/{revision_id}/reject"]["post"]>;
export type ExecuteDeceptionRevisionResponse = JsonResponse<paths["/api/deception-environments/{id}/revisions/{revision_id}/execute"]["post"]>;
export type RecoverDeceptionRevisionResponse = JsonResponse<paths["/api/deception-environments/{id}/revisions/{revision_id}/recover"]["post"]>;
export type QueryBehaviorEventsParams = QueryParameters<paths["/api/deception-environments/{environment_id}/behavior-events"]["get"]>;
export type QueryBehaviorEventsResponse = JsonResponse<paths["/api/deception-environments/{environment_id}/behavior-events"]["get"]>;
export type ListObservedWorkloadsResponse = JsonResponse<paths["/api/deception-environments/{id}/workloads"]["get"]>;
export type CreateObservedWorkloadRequest = JsonRequestBody<paths["/api/deception-environments/{id}/workloads"]["post"]>;
export type CreateObservedWorkloadResponse = JsonResponse<paths["/api/deception-environments/{id}/workloads"]["post"]>;
export type StopObservedWorkloadResponse = JsonResponse<paths["/api/deception-environments/{id}/workloads/{run_id}/stop"]["post"]>;

export type ManagedHostSensor = components["schemas"]["ManagedHostSensorSchema"];
export type DetectionRule = components["schemas"]["DetectionRuleSchema"];
export type DetectionRuleVersion = components["schemas"]["DetectionRuleVersionSchema"];
export type DetectionRuleChange = components["schemas"]["DetectionRuleChangeRequestSchema"];
export type DetectionRuleDeployment = components["schemas"]["DetectionRuleDeploymentSchema"];
export type BehaviorDecision = components["schemas"]["BehaviorDecisionSchema"];
export type BehaviorSignal = components["schemas"]["BehaviorSignalSchema"];
export type DetectionRuleType = components["schemas"]["DetectionRuleType"];
export type DetectionRuleScope = components["schemas"]["DetectionRuleScope"];
export type DetectionRuleChangeAction = components["schemas"]["DetectionRuleChangeAction"];
export type DetectionRuleChangeDecision = components["schemas"]["DetectionRuleChangeDecision"];
export type ConfigureManagedHostSensorRequest = JsonRequestBody<paths["/api/detection/sensors"]["put"]>;
export type ConfigureManagedHostSensorResponse = JsonResponse<paths["/api/detection/sensors"]["put"]>;
export type QueryManagedHostSensorsParams = QueryParameters<paths["/api/detection/sensors"]["get"]>;
export type QueryManagedHostSensorsResponse = JsonResponse<paths["/api/detection/sensors"]["get"]>;
export type CreateDetectionRuleRequest = JsonRequestBody<paths["/api/detection/rules"]["post"]>;
export type CreateDetectionRuleResponse = JsonResponse<paths["/api/detection/rules"]["post"]>;
export type QueryDetectionRulesParams = QueryParameters<paths["/api/detection/rules"]["get"]>;
export type QueryDetectionRulesResponse = JsonResponse<paths["/api/detection/rules"]["get"]>;
export type CreateDetectionRuleVersionRequest = JsonRequestBody<paths["/api/detection/rules/{rule_id}/versions"]["post"]>;
export type CreateDetectionRuleVersionResponse = JsonResponse<paths["/api/detection/rules/{rule_id}/versions"]["post"]>;
export type QueryDetectionRuleVersionsParams = QueryParameters<paths["/api/detection/rules/{rule_id}/versions"]["get"]>;
export type QueryDetectionRuleVersionsResponse = JsonResponse<paths["/api/detection/rules/{rule_id}/versions"]["get"]>;
export type ReplayDetectionRuleRequest = JsonRequestBody<paths["/api/detection/rules/{rule_id}/versions/{version_id}/replay"]["post"]>;
export type DetectionRuleVersionResponse = JsonResponse<paths["/api/detection/rules/{rule_id}/versions/{version_id}/validate"]["post"]>;
export type SubmitDetectionRuleChangeRequest = JsonRequestBody<paths["/api/detection/rules/{rule_id}/changes"]["post"]>;
export type DetectionRuleChangeResponse = JsonResponse<paths["/api/detection/rules/{rule_id}/changes"]["post"]>;
export type QueryDetectionRuleChangesParams = QueryParameters<paths["/api/detection/changes"]["get"]>;
export type QueryDetectionRuleChangesResponse = JsonResponse<paths["/api/detection/changes"]["get"]>;
export type DecideDetectionRuleChangeRequest = JsonRequestBody<paths["/api/detection/changes/{change_id}/decision"]["post"]>;
export type QueryDetectionDeploymentsParams = QueryParameters<paths["/api/detection/changes/{change_id}/deployments"]["get"]>;
export type QueryDetectionDeploymentsResponse = JsonResponse<paths["/api/detection/changes/{change_id}/deployments"]["get"]>;
export type QueryBehaviorSignalsParams = QueryParameters<paths["/api/detection/signals"]["get"]>;
export type QueryBehaviorSignalsResponse = JsonResponse<paths["/api/detection/signals"]["get"]>;
export type QueryBehaviorDecisionsParams = QueryParameters<paths["/api/detection/decisions"]["get"]>;
export type QueryBehaviorDecisionsResponse = JsonResponse<paths["/api/detection/decisions"]["get"]>;

export type ThreatIncident = components["schemas"]["ThreatIncidentSchema"];
export type ThreatIncidentStatus = components["schemas"]["ThreatIncidentStatus"];
export type ThreatSeverity = components["schemas"]["ThreatSeverity"];
export type ThreatConfidence = components["schemas"]["ThreatConfidence"];
export type InvestigationTask = components["schemas"]["InvestigationTaskSchema"];
export type InvestigationTaskStatus = components["schemas"]["InvestigationTaskStatus"];
export type InvestigationEvidence = components["schemas"]["InvestigationEvidenceSchema"];
export type AuditEvent = components["schemas"]["AuditEventSchema"];
export type IntentAssessment = components["schemas"]["IntentAssessmentSchema"];
export type AttackChain = components["schemas"]["AttackChainSchema"];
export type ThreatIndicator = components["schemas"]["ThreatIndicatorSchema"];
export type AttackerProfile = components["schemas"]["AttackerProfileSchema"];
export type RiskAssessment = components["schemas"]["RiskAssessmentSchema"];
export type IntelligenceReport = components["schemas"]["IntelligenceReportSchema"];
export type ThreatIncidentWorkspace = components["schemas"]["ThreatIncidentWorkspaceSchema"];
export type ThreatTimelineItem = components["schemas"]["ThreatTimelineResponse"]["items"][number];
export type ThreatTimelineCursor = components["schemas"]["ThreatTimelineCursor"];
export type QueryThreatIncidentsParams = QueryParameters<paths["/api/threat-incidents"]["get"]>;
export type QueryThreatIncidentsResponse = JsonResponse<paths["/api/threat-incidents"]["get"]>;
export type ThreatIncidentPathParams = PathParameters<paths["/api/threat-incidents/{id}"]["get"]>;
export type GetThreatIncidentResponse = JsonResponse<paths["/api/threat-incidents/{id}"]["get"]>;
export type UpdateThreatIncidentRequest = JsonRequestBody<paths["/api/threat-incidents/{id}"]["patch"]>;
export type UpdateThreatIncidentResponse = JsonResponse<paths["/api/threat-incidents/{id}"]["patch"]>;
export type TransitionThreatIncidentRequest = JsonRequestBody<paths["/api/threat-incidents/{id}/start-investigation"]["post"]>;
export type TransitionThreatIncidentResponse = JsonResponse<paths["/api/threat-incidents/{id}/start-investigation"]["post"]>;
export type GetThreatIncidentWorkspaceResponse = JsonResponse<paths["/api/threat-incidents/{id}/workspace"]["get"]>;
export type GetThreatIncidentTimelineParams = QueryParameters<paths["/api/threat-incidents/{id}/timeline"]["get"]>;
export type GetThreatIncidentTimelineResponse = JsonResponse<paths["/api/threat-incidents/{id}/timeline"]["get"]>;
export type QueryIncidentBehaviorEventsParams = QueryParameters<paths["/api/threat-incidents/{id}/behavior-events"]["get"]>;
export type QueryIncidentBehaviorEventsResponse = JsonResponse<paths["/api/threat-incidents/{id}/behavior-events"]["get"]>;
export type QueryInvestigationTasksParams = QueryParameters<paths["/api/threat-incidents/{id}/investigation-tasks"]["get"]>;
export type QueryInvestigationTasksResponse = JsonResponse<paths["/api/threat-incidents/{id}/investigation-tasks"]["get"]>;
export type CreateInvestigationTaskRequest = JsonRequestBody<paths["/api/threat-incidents/{id}/investigation-tasks"]["post"]>;
export type CreateInvestigationTaskResponse = JsonResponse<paths["/api/threat-incidents/{id}/investigation-tasks"]["post"]>;
export type QueryInvestigationEvidenceParams = QueryParameters<paths["/api/threat-incidents/{id}/investigation-evidence"]["get"]>;
export type QueryInvestigationEvidenceResponse = JsonResponse<paths["/api/threat-incidents/{id}/investigation-evidence"]["get"]>;
export type CreateInvestigationEvidenceRequest = JsonRequestBody<paths["/api/threat-incidents/{id}/investigation-tasks/{task_id}/evidence"]["post"]>;
export type CreateInvestigationEvidenceResponse = JsonResponse<paths["/api/threat-incidents/{id}/investigation-tasks/{task_id}/evidence"]["post"]>;
export type QueryAuditEventsParams = QueryParameters<paths["/api/threat-incidents/{id}/audit-events"]["get"]>;
export type QueryAuditEventsResponse = JsonResponse<paths["/api/threat-incidents/{id}/audit-events"]["get"]>;
export type ActivateInvestigationTaskResponse = JsonResponse<paths["/api/threat-incidents/{id}/investigation-tasks/{task_id}/activate"]["post"]>;
export type BlockInvestigationTaskRequest = JsonRequestBody<paths["/api/threat-incidents/{id}/investigation-tasks/{task_id}/block"]["post"]>;
export type BlockInvestigationTaskResponse = JsonResponse<paths["/api/threat-incidents/{id}/investigation-tasks/{task_id}/block"]["post"]>;
export type SubmitInvestigationTaskRequest = JsonRequestBody<paths["/api/threat-incidents/{id}/investigation-tasks/{task_id}/submit"]["post"]>;
export type SubmitInvestigationTaskResponse = JsonResponse<paths["/api/threat-incidents/{id}/investigation-tasks/{task_id}/submit"]["post"]>;
export type ReviewInvestigationTaskRequest = JsonRequestBody<paths["/api/threat-incidents/{id}/investigation-tasks/{task_id}/review"]["post"]>;
export type ReviewInvestigationTaskResponse = JsonResponse<paths["/api/threat-incidents/{id}/investigation-tasks/{task_id}/review"]["post"]>;
export type GetThreatIncidentSessionResponse = JsonResponse<paths["/api/threat-incidents/{id}/session"]["get"]>;
export type EnsureThreatIncidentSessionResponse = JsonResponse<paths["/api/threat-incidents/{id}/session"]["put"]>;

export type QueryIntentAssessmentsParams = QueryParameters<paths["/api/threat-incidents/{id}/intent-assessments"]["get"]>;
export type QueryIntentAssessmentsResponse = JsonResponse<paths["/api/threat-incidents/{id}/intent-assessments"]["get"]>;
export type CreateIntentAssessmentRequest = JsonRequestBody<paths["/api/threat-incidents/{id}/intent-assessments"]["post"]>;
export type CreateIntentAssessmentResponse = JsonResponse<paths["/api/threat-incidents/{id}/intent-assessments"]["post"]>;
export type QueryAttackChainsParams = QueryParameters<paths["/api/threat-incidents/{id}/attack-chains"]["get"]>;
export type QueryAttackChainsResponse = JsonResponse<paths["/api/threat-incidents/{id}/attack-chains"]["get"]>;
export type CreateAttackChainRequest = JsonRequestBody<paths["/api/threat-incidents/{id}/attack-chains"]["post"]>;
export type CreateAttackChainResponse = JsonResponse<paths["/api/threat-incidents/{id}/attack-chains"]["post"]>;
export type QueryThreatIndicatorsParams = QueryParameters<paths["/api/threat-incidents/{id}/indicators"]["get"]>;
export type QueryThreatIndicatorsResponse = JsonResponse<paths["/api/threat-incidents/{id}/indicators"]["get"]>;
export type CreateThreatIndicatorRequest = JsonRequestBody<paths["/api/threat-incidents/{id}/indicators"]["post"]>;
export type CreateThreatIndicatorResponse = JsonResponse<paths["/api/threat-incidents/{id}/indicators"]["post"]>;
export type QueryAttackerProfilesParams = QueryParameters<paths["/api/threat-incidents/{id}/attacker-profiles"]["get"]>;
export type QueryAttackerProfilesResponse = JsonResponse<paths["/api/threat-incidents/{id}/attacker-profiles"]["get"]>;
export type CreateAttackerProfileRequest = JsonRequestBody<paths["/api/threat-incidents/{id}/attacker-profiles"]["post"]>;
export type CreateAttackerProfileResponse = JsonResponse<paths["/api/threat-incidents/{id}/attacker-profiles"]["post"]>;
export type QueryRiskAssessmentsParams = QueryParameters<paths["/api/threat-incidents/{id}/risk-assessments"]["get"]>;
export type QueryRiskAssessmentsResponse = JsonResponse<paths["/api/threat-incidents/{id}/risk-assessments"]["get"]>;
export type CreateRiskAssessmentRequest = JsonRequestBody<paths["/api/threat-incidents/{id}/risk-assessments"]["post"]>;
export type CreateRiskAssessmentResponse = JsonResponse<paths["/api/threat-incidents/{id}/risk-assessments"]["post"]>;
export type QueryIntelligenceReportsParams = QueryParameters<paths["/api/threat-incidents/{id}/intelligence-reports"]["get"]>;
export type QueryIntelligenceReportsResponse = JsonResponse<paths["/api/threat-incidents/{id}/intelligence-reports"]["get"]>;
export type CreateIntelligenceReportRequest = JsonRequestBody<paths["/api/threat-incidents/{id}/intelligence-reports"]["post"]>;
export type CreateIntelligenceReportResponse = JsonResponse<paths["/api/threat-incidents/{id}/intelligence-reports"]["post"]>;

export type AgentSessionSummary = components["schemas"]["AgentSessionSummarySchema"];
export type AgentCode = components["schemas"]["AgentCode"];
export type SessionType = components["schemas"]["SessionType"];

export type AgentInfo = components["schemas"]["AgentInfoSchema"];
export type ListAgentsResponse = JsonResponse<paths["/api/agents"]["get"]>;

export type ListAgentSessionsResponse = JsonResponse<paths["/api/agent-sessions"]["get"]>;
export type ListAgentSessionsParams = QueryParameters<paths["/api/agent-sessions"]["get"]>;
export type GetAgentSessionResponse = JsonResponse<paths["/api/agent-sessions/{session_id}"]["get"]>;

export type CreateAgentSessionTurnRequest = JsonRequestBody<paths["/api/agent-sessions/turns"]["post"]>;
export type SubmitAgentSessionTurnRequest = JsonRequestBody<paths["/api/agent-sessions/{session_id}/turns"]["post"]>;
export type AgentTurnData = components["schemas"]["AgentTurnResponse"];
export type CreateAgentSessionTurnResponse = JsonResponse<paths["/api/agent-sessions/turns"]["post"]>;
export type SubmitAgentSessionTurnResponse = JsonResponse<paths["/api/agent-sessions/{session_id}/turns"]["post"]>;
export type InterruptAgentSessionResponse = JsonResponse<paths["/api/agent-sessions/{session_id}/interrupt"]["post"]>;
export type CancelAllAgentSessionTasksResponse = JsonResponse<paths["/api/agent-sessions/{session_id}/cancel-all"]["post"]>;

export type ListAgentEventsResponse = JsonResponse<paths["/api/agent-sessions/{session_id}/events"]["get"]>;
export type ListAgentEventsParams = QueryParameters<paths["/api/agent-sessions/{session_id}/events"]["get"]>;
export type DownloadAgentReportPathParams = PathParameters<paths["/api/agent-sessions/reports/{report_id}/download"]["get"]>;
export type UpdateAgentSessionTitleRequest = JsonRequestBody<paths["/api/agent-sessions/{session_id}/title"]["patch"]>;
export type UpdateAgentSessionTitleResponse = JsonResponse<paths["/api/agent-sessions/{session_id}/title"]["patch"]>;
export type UpdateAgentSessionSandboxContainerRequest = JsonRequestBody<paths["/api/agent-sessions/{session_id}/sandbox-container"]["patch"]>;
export type UpdateAgentSessionSandboxContainerResponse = JsonResponse<paths["/api/agent-sessions/{session_id}/sandbox-container"]["patch"]>;
export type ArchiveAgentSessionResponse = JsonResponse<paths["/api/agent-sessions/{session_id}/archive"]["post"]>;

export type ListAgentToolInvocationRecoveriesResponse = JsonResponse<paths["/api/agent-sessions/{session_id}/tool-invocations/recovery"]["get"]>;
export type ResolveAgentToolInvocationRequest = JsonRequestBody<paths["/api/agent-sessions/{session_id}/tool-invocations/{invocation_id}/resolve"]["post"]>;
export type ResolveAgentToolInvocationResponse = JsonResponse<paths["/api/agent-sessions/{session_id}/tool-invocations/{invocation_id}/resolve"]["post"]>;
export type ListSandboxAsyncJobRecoveriesResponse = JsonResponse<paths["/api/agent-sessions/{session_id}/sandbox-jobs/recovery"]["get"]>;
export type ResolveSandboxAsyncJobRequest = JsonRequestBody<paths["/api/agent-sessions/{session_id}/sandbox-jobs/{job_id}/resolve"]["post"]>;
export type ResolveSandboxAsyncJobResponse = JsonResponse<paths["/api/agent-sessions/{session_id}/sandbox-jobs/{job_id}/resolve"]["post"]>;

export type UserMessageEvent = components["schemas"]["UserMessageEvent"];
export type RunTransitionEvent = components["schemas"]["RunTransitionEvent"];
export type AttemptTransitionEvent = components["schemas"]["AttemptTransitionEvent"];
export type SegmentCompletedEvent = components["schemas"]["SegmentCompletedEvent"];
export type ToolCallEvent = components["schemas"]["ToolCallEvent"];
export type ToolResultEvent = components["schemas"]["ToolResultEvent"];
export type ToolRecoveryEvent = components["schemas"]["ToolRecoveryEvent"];
export type SandboxRecoveryEvent = components["schemas"]["SandboxRecoveryEvent"];
export type DelegationEvent = components["schemas"]["DelegationEvent"];
export type AgentErrorEvent = components["schemas"]["AgentErrorEvent"];
export type AgentInputPart = components["schemas"]["AgentTextInputPart"] | components["schemas"]["AgentImageInputPart"];
export type AgentTextInputPart = components["schemas"]["AgentTextInputPart"];
export type AgentImageInputPart = components["schemas"]["AgentImageInputPart"];
export type AgentRun = components["schemas"]["AgentRunSchema"];
export type AgentToolInvocation = components["schemas"]["AgentToolInvocationSchema"];
export type SandboxAsyncJobSnapshot = components["schemas"]["SandboxAsyncJobSnapshot"];
export type AgentDurableEvent = components["schemas"]["AgentDurableEvent"];
export type AgentSegmentSnapshot = components["schemas"]["AgentSegmentSnapshot"];
export type AgentServerFrame = components["schemas"]["AgentServerFrame"];
export type AgentClientFrame = components["schemas"]["AgentClientFrame"];
