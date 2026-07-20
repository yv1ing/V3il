"""Export deterministic HTTP and runtime contracts for the web application."""

import json
import sys
from pathlib import Path
from typing import Any


ROOT_PATH = Path(__file__).resolve().parents[1]
WEB_PATH = ROOT_PATH / "web"
OPENAPI_PATH = WEB_PATH / "openapi.json"
AGENT_STREAM_PATH = WEB_PATH / "agent-stream.schema.json"
CONTRACT_MANIFEST_PATH = WEB_PATH / "contract-manifest.json"

if str(ROOT_PATH) not in sys.path:
    sys.path.insert(0, str(ROOT_PATH))

from app import create_app
from schema.contract import (
    build_agent_stream_schema,
    build_contract_manifest,
    register_openapi_contract_schemas,
)


def export_contracts() -> tuple[Path, Path, Path]:
    app = create_app()
    openapi = app.openapi()
    register_openapi_contract_schemas(openapi)
    _validate_openapi(openapi)

    agent_stream = build_agent_stream_schema()
    manifest = build_contract_manifest(openapi)
    WEB_PATH.mkdir(parents=True, exist_ok=True)
    _write_json(OPENAPI_PATH, openapi)
    _write_json(AGENT_STREAM_PATH, agent_stream)
    _write_json(CONTRACT_MANIFEST_PATH, manifest)
    return OPENAPI_PATH, AGENT_STREAM_PATH, CONTRACT_MANIFEST_PATH


def _validate_openapi(openapi: dict[str, Any]) -> None:
    schemas = openapi.get("components", {}).get("schemas", {})
    if "HTTPValidationError" in schemas or "ValidationError" in schemas:
        raise RuntimeError("FastAPI validation schemas leaked into the canonical error contract")
    for path, path_item in openapi.get("paths", {}).items():
        for method, operation in path_item.items():
            if not isinstance(operation, dict):
                continue
            for status, response in operation.get("responses", {}).items():
                if status not in {"400", "401", "403", "404", "409", "422", "500"}:
                    continue
                content = response.get("content", {}) if isinstance(response, dict) else {}
                if "application/json" in content and _schema_ref(content["application/json"]) == (
                    "#/components/schemas/ProblemDetails"
                ):
                    raise RuntimeError(
                        f"Problem Details uses application/json at {method.upper()} {path} ({status})"
                    )


def _schema_ref(media: object) -> str:
    if not isinstance(media, dict):
        return ""
    schema = media.get("schema")
    return str(schema.get("$ref") or "") if isinstance(schema, dict) else ""


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    for path in export_contracts():
        print(f"Contract exported to {path.relative_to(ROOT_PATH)}")


if __name__ == "__main__":
    main()
