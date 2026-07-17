from fastapi import APIRouter, Depends, Query

from handler.detection.rules import (
    configure_sensor_handler,
    create_rule_handler,
    create_rule_version_handler,
    decide_rule_change_handler,
    query_decisions_handler,
    query_deployments_handler,
    query_rule_changes_handler,
    query_rule_versions_handler,
    query_rules_handler,
    query_sensors_handler,
    query_signals_handler,
    replay_rule_version_handler,
    submit_rule_change_handler,
    validate_rule_version_handler,
)
from middleware.system_user import AuthUser, require_admin, require_user
from router.common.responses import COMMON_ERROR_RESPONSES
from schema.common.responses import CommonResponse
from schema.detection.rules import (
    BehaviorClassification,
    BehaviorSignalStatus,
    ConfigureManagedHostSensorRequest,
    CreateDetectionRuleRequest,
    CreateDetectionRuleResponse,
    CreateDetectionRuleVersionRequest,
    DecideDetectionRuleChangeRequest,
    DetectionRuleChangeRequestSchema,
    DetectionRuleDeploymentSchema,
    DetectionRuleVersionSchema,
    ManagedHostSensorSchema,
    QueryBehaviorDecisionsResponse,
    QueryBehaviorSignalsResponse,
    QueryDetectionRulesResponse,
    QueryManagedHostSensorsResponse,
    QueryRuleChangesResponse,
    QueryRuleDeploymentsResponse,
    QueryRuleVersionsResponse,
    DetectionRuleChangeStatus,
    DetectionRuleScope,
    DetectionRuleType,
    ManagedHostSensorStatus,
    ReplayDetectionRuleRequest,
    SubmitDetectionRuleChangeRequest,
)
from service.common.pagination import RESOURCE_PAGE_MAX_SIZE, RESOURCE_PAGE_SIZE


router = APIRouter(prefix="/detection", tags=["detection"], dependencies=[Depends(require_user)])


@router.put("/sensors", response_model=CommonResponse[ManagedHostSensorSchema], dependencies=[Depends(require_admin)], responses=COMMON_ERROR_RESPONSES)
async def configure_sensor_route(request: ConfigureManagedHostSensorRequest):
    return await configure_sensor_handler(request)


@router.get("/sensors", response_model=CommonResponse[QueryManagedHostSensorsResponse], responses=COMMON_ERROR_RESPONSES)
async def query_sensors_route(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE),
    status: ManagedHostSensorStatus | None = Query(default=None),
    user: AuthUser = Depends(require_user),
):
    return await query_sensors_handler(page=page, size=size, status=status, user=user)


@router.post("/rules", response_model=CommonResponse[CreateDetectionRuleResponse], responses=COMMON_ERROR_RESPONSES)
async def create_rule_route(request: CreateDetectionRuleRequest, user: AuthUser = Depends(require_user)):
    return await create_rule_handler(request, user)


@router.get("/rules", response_model=CommonResponse[QueryDetectionRulesResponse], responses=COMMON_ERROR_RESPONSES)
async def query_rules_route(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE),
    keyword: str = Query(default=""),
    type: DetectionRuleType | None = Query(default=None),
    scope: DetectionRuleScope | None = Query(default=None),
    user: AuthUser = Depends(require_user),
):
    return await query_rules_handler(page=page, size=size, keyword=keyword, type=type, scope=scope, user=user)


@router.post("/rules/{rule_id}/versions", response_model=CommonResponse[DetectionRuleVersionSchema], responses=COMMON_ERROR_RESPONSES)
async def create_rule_version_route(rule_id: int, request: CreateDetectionRuleVersionRequest, user: AuthUser = Depends(require_user)):
    return await create_rule_version_handler(rule_id, request, user)


@router.get("/rules/{rule_id}/versions", response_model=CommonResponse[QueryRuleVersionsResponse], responses=COMMON_ERROR_RESPONSES)
async def query_rule_versions_route(
    rule_id: int,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE),
    user: AuthUser = Depends(require_user),
):
    return await query_rule_versions_handler(rule_id, page=page, size=size, user=user)


@router.post("/rules/{rule_id}/versions/{version_id}/validate", response_model=CommonResponse[DetectionRuleVersionSchema], responses=COMMON_ERROR_RESPONSES)
async def validate_rule_version_route(rule_id: int, version_id: int, user: AuthUser = Depends(require_user)):
    return await validate_rule_version_handler(rule_id, version_id, user)


@router.post("/rules/{rule_id}/versions/{version_id}/replay", response_model=CommonResponse[DetectionRuleVersionSchema], responses=COMMON_ERROR_RESPONSES)
async def replay_rule_version_route(rule_id: int, version_id: int, request: ReplayDetectionRuleRequest, user: AuthUser = Depends(require_user)):
    return await replay_rule_version_handler(rule_id, version_id, request, user)


@router.post("/rules/{rule_id}/changes", response_model=CommonResponse[DetectionRuleChangeRequestSchema], responses=COMMON_ERROR_RESPONSES)
async def submit_rule_change_route(rule_id: int, request: SubmitDetectionRuleChangeRequest, user: AuthUser = Depends(require_user)):
    return await submit_rule_change_handler(rule_id, request, user)


@router.get("/changes", response_model=CommonResponse[QueryRuleChangesResponse], responses=COMMON_ERROR_RESPONSES)
async def query_rule_changes_route(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE),
    status: DetectionRuleChangeStatus | None = Query(default=None),
    user: AuthUser = Depends(require_user),
):
    return await query_rule_changes_handler(page=page, size=size, status=status, user=user)


@router.post("/changes/{change_id}/decision", response_model=CommonResponse[DetectionRuleChangeRequestSchema], responses=COMMON_ERROR_RESPONSES)
async def decide_rule_change_route(change_id: int, request: DecideDetectionRuleChangeRequest, user: AuthUser = Depends(require_user)):
    return await decide_rule_change_handler(change_id, request, user)


@router.get("/changes/{change_id}/deployments", response_model=CommonResponse[QueryRuleDeploymentsResponse], responses=COMMON_ERROR_RESPONSES)
async def query_deployments_route(
    change_id: int,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE),
    user: AuthUser = Depends(require_user),
):
    return await query_deployments_handler(change_id, page=page, size=size, user=user)


@router.get("/decisions", response_model=CommonResponse[QueryBehaviorDecisionsResponse], responses=COMMON_ERROR_RESPONSES)
async def query_decisions_route(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE),
    classification: BehaviorClassification | None = Query(default=None),
    environment_id: int | None = Query(default=None, gt=0),
    user: AuthUser = Depends(require_user),
):
    return await query_decisions_handler(page=page, size=size, classification=classification, environment_id=environment_id, user=user)


@router.get("/signals", response_model=CommonResponse[QueryBehaviorSignalsResponse], responses=COMMON_ERROR_RESPONSES)
async def query_signals_route(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE),
    status: BehaviorSignalStatus | None = Query(default=None),
    environment_id: int | None = Query(default=None, gt=0),
    user: AuthUser = Depends(require_user),
):
    return await query_signals_handler(page=page, size=size, status=status, environment_id=environment_id, user=user)
