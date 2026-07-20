from schema.common.problems import ProblemDetails


COMMON_ERROR_RESPONSES = {
    401: {"description": "Unauthorized", "model": ProblemDetails},
    422: {"description": "Validation Error", "model": ProblemDetails},
    500: {"description": "Internal Server Error", "model": ProblemDetails},
}
BAD_REQUEST_RESPONSE = {400: {"description": "Bad Request", "model": ProblemDetails}}
FORBIDDEN_RESPONSE = {403: {"description": "Forbidden", "model": ProblemDetails}}
INTERNAL_ERROR_RESPONSE = {500: {"description": "Internal Server Error", "model": ProblemDetails}}
CONFLICT_RESPONSE = {409: {"description": "Conflict", "model": ProblemDetails}}


def not_found_response(resource: str) -> dict:
    return {404: {"description": f"{resource} not found", "model": ProblemDetails}}
