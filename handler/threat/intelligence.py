from http import HTTPStatus

from handler.common.http import raise_api_error
from middleware.system_user import AuthUser
from schema.common.responses import CommonResponse
from schema.threat.intelligence import (
    CreateIntelligenceReportRequest,
    CreateThreatIndicatorRequest,
    QueryIntelligenceReportsResponse,
    QueryThreatIndicatorsResponse,
)
from service.common.pagination import paginated_payload
from service.threat.intelligence import (
    IntelligenceReportMutationResult,
    ThreatIndicatorMutationResult,
    create_intelligence_report,
    create_threat_indicator,
    query_intelligence_reports_for_user,
    query_threat_indicators_for_user,
)


def _raise_indicator_error(result: ThreatIndicatorMutationResult) -> None:
    if result.not_found:
        raise_api_error(HTTPStatus.NOT_FOUND, result.message or "threat incident not found")
    if result.forbidden:
        raise_api_error(HTTPStatus.FORBIDDEN, result.message or "threat incident is not accessible by user")
    if result.conflict:
        raise_api_error(HTTPStatus.CONFLICT, result.message or "threat indicator conflict")
    raise RuntimeError("threat indicator failed without an error classification")


def _raise_report_error(result: IntelligenceReportMutationResult) -> None:
    if result.not_found:
        raise_api_error(HTTPStatus.NOT_FOUND, result.message or "threat incident not found")
    if result.forbidden:
        raise_api_error(HTTPStatus.FORBIDDEN, result.message or "threat incident is not accessible by user")
    if result.conflict:
        raise_api_error(HTTPStatus.CONFLICT, result.message or "intelligence report conflict")
    raise RuntimeError("intelligence report failed without an error classification")


async def create_threat_indicator_handler(
    incident_id: int,
    request: CreateThreatIndicatorRequest,
    user: AuthUser,
) -> CommonResponse:
    result = await create_threat_indicator(
        incident_id,
        request,
        user_id=user.id,
        user_role=user.role,
    )
    if result.indicator is None:
        _raise_indicator_error(result)
    return CommonResponse(message="threat indicator created", data=result.indicator)


async def query_threat_indicators_handler(
    incident_id: int,
    *,
    page: int,
    size: int,
    type,
    keyword: str,
    user: AuthUser,
) -> CommonResponse:
    indicators = await query_threat_indicators_for_user(
        incident_id,
        page=page,
        size=size,
        type=type,
        keyword=keyword,
        user_id=user.id,
        user_role=user.role,
    )
    if indicators is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "threat incident not found")
    return CommonResponse(data=QueryThreatIndicatorsResponse(
        **paginated_payload(indicators, indicators.items),
    ))


async def create_intelligence_report_handler(
    incident_id: int,
    request: CreateIntelligenceReportRequest,
    user: AuthUser,
) -> CommonResponse:
    result = await create_intelligence_report(
        incident_id,
        request,
        user_id=user.id,
        user_role=user.role,
    )
    if result.report is None:
        _raise_report_error(result)
    return CommonResponse(message="intelligence report created", data=result.report)


async def query_intelligence_reports_handler(
    incident_id: int,
    *,
    page: int,
    size: int,
    user: AuthUser,
) -> CommonResponse:
    reports = await query_intelligence_reports_for_user(
        incident_id,
        page=page,
        size=size,
        user_id=user.id,
        user_role=user.role,
    )
    if reports is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "threat incident not found")
    return CommonResponse(data=QueryIntelligenceReportsResponse(
        **paginated_payload(reports, reports.items),
    ))
