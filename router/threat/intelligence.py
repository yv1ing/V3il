from fastapi import APIRouter, Depends, Query

from handler.threat.intelligence import (
    create_intelligence_report_handler,
    create_threat_indicator_handler,
    query_intelligence_reports_handler,
    query_threat_indicators_handler,
)
from middleware.system_user import AuthUser, require_user
from router.common.responses import COMMON_ERROR_RESPONSES, CONFLICT_RESPONSE, FORBIDDEN_RESPONSE, not_found_response
from schema.common.responses import CommonResponse
from schema.threat.intelligence import (
    CreateIntelligenceReportRequest,
    CreateThreatIndicatorRequest,
    IntelligenceReportSchema,
    QueryIntelligenceReportsResponse,
    QueryThreatIndicatorsResponse,
    ThreatIndicatorSchema,
    ThreatIndicatorType,
)
from service.common.pagination import RESOURCE_PAGE_MAX_SIZE, RESOURCE_PAGE_SIZE


NOT_FOUND_RESPONSE = not_found_response("Threat incident")

router = APIRouter(
    prefix="/threat-incidents",
    tags=["threat-intelligence"],
    dependencies=[Depends(require_user)],
)


async def create_threat_indicator_route(
    id: int,
    request: CreateThreatIndicatorRequest,
    user: AuthUser = Depends(require_user),
) -> CommonResponse[ThreatIndicatorSchema]:
    return await create_threat_indicator_handler(id, request, user)


async def query_threat_indicators_route(
    id: int,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE),
    type: ThreatIndicatorType | None = Query(default=None),
    keyword: str = Query(default=""),
    user: AuthUser = Depends(require_user),
) -> CommonResponse[QueryThreatIndicatorsResponse]:
    return await query_threat_indicators_handler(
        id,
        page=page,
        size=size,
        type=type,
        keyword=keyword,
        user=user,
    )


async def create_intelligence_report_route(
    id: int,
    request: CreateIntelligenceReportRequest,
    user: AuthUser = Depends(require_user),
) -> CommonResponse[IntelligenceReportSchema]:
    return await create_intelligence_report_handler(id, request, user)


async def query_intelligence_reports_route(
    id: int,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE),
    user: AuthUser = Depends(require_user),
) -> CommonResponse[QueryIntelligenceReportsResponse]:
    return await query_intelligence_reports_handler(id, page=page, size=size, user=user)


router.add_api_route(
    "/{id}/indicators",
    create_threat_indicator_route,
    methods=["POST"],
    response_model=CommonResponse[ThreatIndicatorSchema],
    responses={**COMMON_ERROR_RESPONSES, **FORBIDDEN_RESPONSE, **CONFLICT_RESPONSE, **NOT_FOUND_RESPONSE},
)
router.add_api_route(
    "/{id}/indicators",
    query_threat_indicators_route,
    methods=["GET"],
    response_model=CommonResponse[QueryThreatIndicatorsResponse],
    responses={**COMMON_ERROR_RESPONSES, **NOT_FOUND_RESPONSE},
)
router.add_api_route(
    "/{id}/intelligence-reports",
    create_intelligence_report_route,
    methods=["POST"],
    response_model=CommonResponse[IntelligenceReportSchema],
    responses={**COMMON_ERROR_RESPONSES, **FORBIDDEN_RESPONSE, **CONFLICT_RESPONSE, **NOT_FOUND_RESPONSE},
)
router.add_api_route(
    "/{id}/intelligence-reports",
    query_intelligence_reports_route,
    methods=["GET"],
    response_model=CommonResponse[QueryIntelligenceReportsResponse],
    responses={**COMMON_ERROR_RESPONSES, **NOT_FOUND_RESPONSE},
)
