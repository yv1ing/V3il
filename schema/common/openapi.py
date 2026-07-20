from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi


_PROBLEM_SCHEMA_REF = "#/components/schemas/ProblemDetails"
_VALIDATION_SCHEMA_REF = "#/components/schemas/HTTPValidationError"


def build_openapi_contract(app: FastAPI) -> dict[str, Any]:
    if app.openapi_schema is not None:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        openapi_version=app.openapi_version,
        summary=app.summary,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags,
        servers=app.servers,
        separate_input_output_schemas=app.separate_input_output_schemas,
    )
    for path, path_item in schema.get("paths", {}).items():
        if not path.startswith("/api"):
            continue
        for operation in path_item.values():
            if not isinstance(operation, dict):
                continue
            responses = operation.get("responses")
            if not isinstance(responses, dict):
                continue
            validation_response = responses.get("422")
            if _response_schema_ref(validation_response) == _VALIDATION_SCHEMA_REF:
                responses["422"] = _problem_response("Request validation failed")
            for response in responses.values():
                if _response_schema_ref(response) != _PROBLEM_SCHEMA_REF:
                    continue
                content = response.setdefault("content", {})
                media = content.pop("application/json", None)
                if media is not None:
                    content["application/problem+json"] = media
    _apply_auth_contract(app, schema)
    components = schema.get("components", {}).get("schemas", {})
    if isinstance(components, dict):
        components.pop("HTTPValidationError", None)
        components.pop("ValidationError", None)
    app.openapi_schema = schema
    return schema


def _apply_auth_contract(app: FastAPI, schema: dict[str, Any]) -> None:
    from middleware.system_user.auth import ACCESS_TOKEN_HEADER, require_admin, require_user

    components = schema.setdefault("components", {})
    components.setdefault("securitySchemes", {})["AccessTokenAuth"] = {
        "type": "apiKey",
        "in": "header",
        "name": ACCESS_TOKEN_HEADER,
    }
    paths = schema.get("paths", {})
    for route in app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", None)
        dependant = getattr(route, "dependant", None)
        if not methods or path not in paths or dependant is None:
            continue
        dependencies = _dependency_functions(dependant)
        if require_user not in dependencies and require_admin not in dependencies:
            continue
        for method in methods:
            operation = paths[path].get(method.lower())
            if not isinstance(operation, dict):
                continue
            operation["security"] = [{"AccessTokenAuth": []}]
            responses = operation.setdefault("responses", {})
            responses.setdefault("401", _problem_response("Unauthorized"))
            if require_admin in dependencies:
                responses.setdefault("403", _problem_response("Forbidden"))


def _dependency_functions(dependant: Any) -> set[Any]:
    functions = {dependant.call} if dependant.call is not None else set()
    for child in dependant.dependencies:
        functions.update(_dependency_functions(child))
    return functions


def _response_schema_ref(response: object) -> str:
    if not isinstance(response, dict):
        return ""
    content = response.get("content")
    if not isinstance(content, dict):
        return ""
    for media in content.values():
        if isinstance(media, dict):
            item = media.get("schema")
            if isinstance(item, dict) and isinstance(item.get("$ref"), str):
                return item["$ref"]
    return ""


def _problem_response(description: str) -> dict[str, Any]:
    return {
        "description": description,
        "content": {
            "application/problem+json": {
                "schema": {"$ref": _PROBLEM_SCHEMA_REF},
            },
        },
    }
