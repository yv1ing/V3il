from http import HTTPStatus

from handler.common.http import raise_api_error
from middleware.system_user import AuthUser
from schema.common.responses import CommonResponse
from schema.threat.analysis import (
    CreateAttackerProfileRequest,
    CreateIntentAssessmentRequest,
    CreateRiskAssessmentRequest,
    QueryAttackerProfilesResponse,
    QueryIntentAssessmentsResponse,
    QueryRiskAssessmentsResponse,
)
from service.common.pagination import paginated_payload
from service.threat.analysis import (
    IntentAssessmentMutationResult,
    create_intent_assessment,
    create_attacker_profile,
    create_risk_assessment,
    query_attacker_profiles_for_user,
    query_intent_assessments_for_user,
    query_risk_assessments_for_user,
)


def _raise_assessment_error(result: IntentAssessmentMutationResult) -> None:
    if result.not_found:
        raise_api_error(HTTPStatus.NOT_FOUND, result.message or "threat incident not found")
    if result.forbidden:
        raise_api_error(HTTPStatus.FORBIDDEN, result.message or "threat incident is not accessible by user")
    if result.conflict:
        raise_api_error(HTTPStatus.CONFLICT, result.message or "intent assessment conflict")
    raise RuntimeError("intent assessment failed without an error classification")


async def create_intent_assessment_handler(
    incident_id: int,
    request: CreateIntentAssessmentRequest,
    user: AuthUser,
) -> CommonResponse:
    result = await create_intent_assessment(
        incident_id,
        request,
        user_id=user.id,
        user_role=user.role,
    )
    if result.assessment is None:
        _raise_assessment_error(result)
    return CommonResponse(message="intent assessment created", data=result.assessment)


async def query_intent_assessments_handler(
    incident_id: int,
    *,
    page: int,
    size: int,
    user: AuthUser,
) -> CommonResponse:
    assessments = await query_intent_assessments_for_user(
        incident_id,
        page=page,
        size=size,
        user_id=user.id,
        user_role=user.role,
    )
    if assessments is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "threat incident not found")
    return CommonResponse(data=QueryIntentAssessmentsResponse(
        **paginated_payload(assessments, assessments.items),
    ))


async def create_attacker_profile_handler(incident_id: int, request: CreateAttackerProfileRequest, user: AuthUser) -> CommonResponse:
    result = await create_attacker_profile(incident_id, request, user_id=user.id, user_role=user.role)
    if result.profile is None:
        _raise_assessment_error(result)
    return CommonResponse(message="attacker profile created", data=result.profile)


async def query_attacker_profiles_handler(incident_id: int, *, page: int, size: int, user: AuthUser) -> CommonResponse:
    result = await query_attacker_profiles_for_user(incident_id, page=page, size=size, user_id=user.id, user_role=user.role)
    if result is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "threat incident not found")
    return CommonResponse(data=QueryAttackerProfilesResponse(**paginated_payload(result, result.items)))


async def create_risk_assessment_handler(incident_id: int, request: CreateRiskAssessmentRequest, user: AuthUser) -> CommonResponse:
    result = await create_risk_assessment(incident_id, request, user_id=user.id, user_role=user.role)
    if result.risk is None:
        _raise_assessment_error(result)
    return CommonResponse(message="risk assessment created", data=result.risk)


async def query_risk_assessments_handler(incident_id: int, *, page: int, size: int, user: AuthUser) -> CommonResponse:
    result = await query_risk_assessments_for_user(incident_id, page=page, size=size, user_id=user.id, user_role=user.role)
    if result is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "threat incident not found")
    return CommonResponse(data=QueryRiskAssessmentsResponse(**paginated_payload(result, result.items)))
