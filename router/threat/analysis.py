from fastapi import APIRouter, Depends, Query

from handler.threat.analysis import (
    create_attacker_profile_handler,
    create_intent_assessment_handler,
    create_risk_assessment_handler,
    query_attacker_profiles_handler,
    query_intent_assessments_handler,
    query_risk_assessments_handler,
)
from middleware.system_user import AuthUser, require_user
from router.common.responses import COMMON_ERROR_RESPONSES, CONFLICT_RESPONSE, FORBIDDEN_RESPONSE, not_found_response
from schema.common.responses import CommonResponse
from schema.threat.analysis import (
    CreateIntentAssessmentRequest,
    CreateAttackerProfileRequest,
    CreateRiskAssessmentRequest,
    AttackerProfileSchema,
    IntentAssessmentSchema,
    QueryAttackerProfilesResponse,
    QueryIntentAssessmentsResponse,
    QueryRiskAssessmentsResponse,
    RiskAssessmentSchema,
)
from service.common.pagination import RESOURCE_PAGE_MAX_SIZE, RESOURCE_PAGE_SIZE


NOT_FOUND_RESPONSE = not_found_response("Threat incident")

router = APIRouter(
    prefix="/threat-incidents",
    tags=["intent-assessments"],
    dependencies=[Depends(require_user)],
)


async def create_intent_assessment_route(
    id: int,
    request: CreateIntentAssessmentRequest,
    user: AuthUser = Depends(require_user),
) -> CommonResponse[IntentAssessmentSchema]:
    return await create_intent_assessment_handler(id, request, user)


async def query_intent_assessments_route(
    id: int,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE),
    user: AuthUser = Depends(require_user),
) -> CommonResponse[QueryIntentAssessmentsResponse]:
    return await query_intent_assessments_handler(id, page=page, size=size, user=user)


async def create_attacker_profile_route(
    id: int,
    request: CreateAttackerProfileRequest,
    user: AuthUser = Depends(require_user),
) -> CommonResponse[AttackerProfileSchema]:
    return await create_attacker_profile_handler(id, request, user)


async def query_attacker_profiles_route(
    id: int,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE),
    user: AuthUser = Depends(require_user),
) -> CommonResponse[QueryAttackerProfilesResponse]:
    return await query_attacker_profiles_handler(id, page=page, size=size, user=user)


async def create_risk_assessment_route(
    id: int,
    request: CreateRiskAssessmentRequest,
    user: AuthUser = Depends(require_user),
) -> CommonResponse[RiskAssessmentSchema]:
    return await create_risk_assessment_handler(id, request, user)


async def query_risk_assessments_route(
    id: int,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE),
    user: AuthUser = Depends(require_user),
) -> CommonResponse[QueryRiskAssessmentsResponse]:
    return await query_risk_assessments_handler(id, page=page, size=size, user=user)


router.add_api_route(
    "/{id}/intent-assessments",
    create_intent_assessment_route,
    methods=["POST"],
    response_model=CommonResponse[IntentAssessmentSchema],
    responses={**COMMON_ERROR_RESPONSES, **FORBIDDEN_RESPONSE, **CONFLICT_RESPONSE, **NOT_FOUND_RESPONSE},
)
router.add_api_route(
    "/{id}/attacker-profiles",
    create_attacker_profile_route,
    methods=["POST"],
    response_model=CommonResponse[AttackerProfileSchema],
    responses={**COMMON_ERROR_RESPONSES, **FORBIDDEN_RESPONSE, **CONFLICT_RESPONSE, **NOT_FOUND_RESPONSE},
)
router.add_api_route(
    "/{id}/attacker-profiles",
    query_attacker_profiles_route,
    methods=["GET"],
    response_model=CommonResponse[QueryAttackerProfilesResponse],
    responses={**COMMON_ERROR_RESPONSES, **NOT_FOUND_RESPONSE},
)
router.add_api_route(
    "/{id}/risk-assessments",
    create_risk_assessment_route,
    methods=["POST"],
    response_model=CommonResponse[RiskAssessmentSchema],
    responses={**COMMON_ERROR_RESPONSES, **FORBIDDEN_RESPONSE, **CONFLICT_RESPONSE, **NOT_FOUND_RESPONSE},
)
router.add_api_route(
    "/{id}/risk-assessments",
    query_risk_assessments_route,
    methods=["GET"],
    response_model=CommonResponse[QueryRiskAssessmentsResponse],
    responses={**COMMON_ERROR_RESPONSES, **NOT_FOUND_RESPONSE},
)
router.add_api_route(
    "/{id}/intent-assessments",
    query_intent_assessments_route,
    methods=["GET"],
    response_model=CommonResponse[QueryIntentAssessmentsResponse],
    responses={**COMMON_ERROR_RESPONSES, **NOT_FOUND_RESPONSE},
)
