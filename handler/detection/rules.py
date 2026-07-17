from http import HTTPStatus

from handler.common.http import raise_api_error
from middleware.system_user import AuthUser
from schema.common.responses import CommonResponse
from schema.detection.rules import (
    ConfigureManagedHostSensorRequest,
    CreateDetectionRuleRequest,
    CreateDetectionRuleResponse,
    CreateDetectionRuleVersionRequest,
    DecideDetectionRuleChangeRequest,
    QueryBehaviorDecisionsResponse,
    QueryBehaviorSignalsResponse,
    QueryDetectionRulesResponse,
    QueryManagedHostSensorsResponse,
    QueryRuleChangesResponse,
    QueryRuleDeploymentsResponse,
    QueryRuleVersionsResponse,
    ReplayDetectionRuleRequest,
    SubmitDetectionRuleChangeRequest,
)
from service.common.pagination import paginated_payload
from service.detection.engine import query_decisions, query_signals
from service.detection.rules import (
    configure_sensor,
    create_rule,
    create_rule_version,
    decide_rule_change,
    query_deployments,
    query_rule_changes,
    query_rule_versions,
    query_rules,
    query_sensors,
    replay_rule_version,
    submit_rule_change,
    validate_rule_version,
)


async def configure_sensor_handler(request: ConfigureManagedHostSensorRequest) -> CommonResponse:
    try:
        sensor = await configure_sensor(request)
    except LookupError as exc:
        raise_api_error(HTTPStatus.NOT_FOUND, str(exc))
    return CommonResponse(message="detection sensor configured", data=sensor)


async def query_sensors_handler(*, page, size, status, user: AuthUser) -> CommonResponse:
    result = await query_sensors(page=page, size=size, status=status, user_id=user.id, user_role=user.role)
    return CommonResponse(data=QueryManagedHostSensorsResponse(
        **paginated_payload(result, result.items)
    ))


async def create_rule_handler(request: CreateDetectionRuleRequest, user: AuthUser) -> CommonResponse:
    try:
        rule, version = await create_rule(request, user_id=user.id, user_role=user.role)
    except Exception as exc:
        _raise_domain_error(exc)
    return CommonResponse(
        message="detection rule draft created",
        data=CreateDetectionRuleResponse(
            rule=rule,
            version=version,
        ),
    )


async def create_rule_version_handler(rule_id: int, request: CreateDetectionRuleVersionRequest, user: AuthUser) -> CommonResponse:
    try:
        version = await create_rule_version(
            rule_id,
            parent_version_id=request.parent_version_id,
            content=request.content,
            user_id=user.id,
            user_role=user.role,
        )
    except Exception as exc:
        _raise_domain_error(exc)
    return CommonResponse(message="detection rule version created", data=version)


async def validate_rule_version_handler(rule_id: int, version_id: int, user: AuthUser) -> CommonResponse:
    try:
        version = await validate_rule_version(rule_id, version_id, user_id=user.id, user_role=user.role)
    except Exception as exc:
        _raise_domain_error(exc)
    return CommonResponse(message="detection rule version validated", data=version)


async def replay_rule_version_handler(rule_id: int, version_id: int, request: ReplayDetectionRuleRequest, user: AuthUser) -> CommonResponse:
    try:
        version = await replay_rule_version(rule_id, version_id, request, user_id=user.id, user_role=user.role)
    except Exception as exc:
        _raise_domain_error(exc)
    return CommonResponse(message="detection rule replay completed", data=version)


async def submit_rule_change_handler(rule_id: int, request: SubmitDetectionRuleChangeRequest, user: AuthUser) -> CommonResponse:
    try:
        change = await submit_rule_change(rule_id, request, user_id=user.id, user_role=user.role)
    except Exception as exc:
        _raise_domain_error(exc)
    return CommonResponse(message="detection rule change submitted for approval", data=change)


async def decide_rule_change_handler(change_id: int, request: DecideDetectionRuleChangeRequest, user: AuthUser) -> CommonResponse:
    try:
        change = await decide_rule_change(
            change_id,
            decision=request.decision,
            reason=request.reason,
            user_id=user.id,
            user_role=user.role,
        )
    except Exception as exc:
        _raise_domain_error(exc)
    return CommonResponse(message="detection rule change decision recorded", data=change)


async def query_rules_handler(*, page, size, keyword, type, scope, user: AuthUser) -> CommonResponse:
    result = await query_rules(page=page, size=size, keyword=keyword, type=type, scope=scope, user_id=user.id, user_role=user.role)
    return CommonResponse(data=QueryDetectionRulesResponse(
        **paginated_payload(result, result.items)
    ))


async def query_rule_versions_handler(rule_id: int, *, page, size, user: AuthUser) -> CommonResponse:
    try:
        result = await query_rule_versions(rule_id, page=page, size=size, user_id=user.id, user_role=user.role)
    except Exception as exc:
        _raise_domain_error(exc)
    return CommonResponse(data=QueryRuleVersionsResponse(
        **paginated_payload(result, result.items)
    ))


async def query_rule_changes_handler(*, page, size, status, user: AuthUser) -> CommonResponse:
    result = await query_rule_changes(page=page, size=size, status=status, user_id=user.id, user_role=user.role)
    return CommonResponse(data=QueryRuleChangesResponse(
        **paginated_payload(result, result.items)
    ))


async def query_deployments_handler(change_id: int, *, page, size, user: AuthUser) -> CommonResponse:
    try:
        result = await query_deployments(change_id, page=page, size=size, user_id=user.id, user_role=user.role)
    except Exception as exc:
        _raise_domain_error(exc)
    return CommonResponse(data=QueryRuleDeploymentsResponse(
        **paginated_payload(result, result.items)
    ))


async def query_decisions_handler(*, page, size, classification, environment_id, user: AuthUser) -> CommonResponse:
    result = await query_decisions(page=page, size=size, classification=classification, environment_id=environment_id, user_id=user.id, user_role=user.role)
    return CommonResponse(data=QueryBehaviorDecisionsResponse(
        **paginated_payload(result, result.items)
    ))


async def query_signals_handler(*, page, size, status, environment_id, user: AuthUser) -> CommonResponse:
    result = await query_signals(page=page, size=size, status=status, environment_id=environment_id, user_id=user.id, user_role=user.role)
    return CommonResponse(data=QueryBehaviorSignalsResponse(
        **paginated_payload(result, result.items)
    ))


def _raise_domain_error(error: Exception) -> None:
    if isinstance(error, PermissionError):
        raise_api_error(HTTPStatus.FORBIDDEN, str(error))
    if isinstance(error, LookupError):
        raise_api_error(HTTPStatus.NOT_FOUND, str(error))
    if isinstance(error, ValueError):
        raise_api_error(HTTPStatus.CONFLICT, str(error))
    raise error
