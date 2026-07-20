from http import HTTPStatus

from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse

from logger import get_logger
from schema.common.problems import ProblemDetails, ProblemViolation


logger = get_logger(__name__)


def problem_response(
    problem: ProblemDetails,
    *,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=problem.status,
        content=problem.model_dump(mode="json"),
        headers=headers,
        media_type="application/problem+json",
    )


async def request_validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    problem = ProblemDetails(
        type="https://v3il.dev/problems/request-validation",
        title="Request validation failed",
        status=HTTPStatus.UNPROCESSABLE_ENTITY,
        detail="One or more request fields are invalid.",
        instance=request.url.path,
        error_code="request_validation_failed",
        violations=[ProblemViolation(
            location=list(error.get("loc", ())),
            message=str(error.get("msg", "invalid value")),
            code=str(error.get("type", "validation_error")),
        ) for error in exc.errors()],
    )
    return problem_response(problem)


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    try:
        status = HTTPStatus(exc.status_code)
        title = status.phrase
    except ValueError:
        title = "HTTP error"
    problem = ProblemDetails(
        type=f"https://v3il.dev/problems/http-{exc.status_code}",
        title=title,
        status=exc.status_code,
        detail=str(exc.detail),
        instance=request.url.path,
        error_code=f"http_{exc.status_code}",
    )
    return problem_response(problem, headers=exc.headers)


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(
        "unhandled request failed: %s %s",
        request.method,
        request.url.path,
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    problem = ProblemDetails(
        type="https://v3il.dev/problems/internal-error",
        title="Internal Server Error",
        status=HTTPStatus.INTERNAL_SERVER_ERROR,
        detail="The request could not be completed.",
        instance=request.url.path,
        error_code="internal_error",
    )
    return problem_response(problem)
