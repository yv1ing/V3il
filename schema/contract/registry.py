"""Canonical machine-readable contracts that are not expressed by HTTP routes."""

from enum import StrEnum
from typing import Any

from pydantic import TypeAdapter

from middleware.system_user.auth import ACCESS_TOKEN_HEADER
from schema.agent.capabilities import AGENT_CAPABILITIES
from schema.agent.events import (
    MAX_AGENT_IMAGE_BYTES,
    MAX_AGENT_IMAGES,
    MAX_AGENT_TEXT_INPUT_CHARS,
    MAX_AGENT_TOTAL_IMAGE_BYTES,
    AgentClientFrameType,
    AgentClientFrame,
    AgentDurableEventType,
    AgentDurableEvent,
    AgentInputPartType,
    AgentServerFrameType,
    AgentServerFrame,
)
from schema.agent.types import (
    AGENT_ATTEMPT_STATUS_TRANSITIONS,
    AGENT_CONTEXT_ITEM_STATUS_TRANSITIONS,
    AGENT_RUN_STATUS_TRANSITIONS,
    AGENT_SEGMENT_STATUS_TRANSITIONS,
    AGENT_SESSION_STATUS_TRANSITIONS,
    AGENT_TOOL_INVOCATION_STATUS_TRANSITIONS,
    CANONICAL_AGENT_IDENTITIES,
    AgentCode,
)
from schema.common.resources import RESOURCE_LIFECYCLE_STATUS_TRANSITIONS
from schema.deception.environments import (
    DECEPTION_ENVIRONMENT_STATUS_TRANSITIONS,
    DECEPTION_REVISION_STATUS_TRANSITIONS,
    DECEPTION_REVISION_STEP_STATUS_TRANSITIONS,
    MAX_DECEPTION_REFERENCE_FILE_BYTES,
    MAX_DECEPTION_REFERENCE_FILES,
    MAX_DECEPTION_REFERENCE_TOTAL_BYTES,
    MAX_DECEPTION_REFERENCE_URL_LENGTH,
    MAX_DECEPTION_REFERENCE_URLS,
)
from schema.detection.rules import (
    DETECTION_RULE_CHANGE_STATUS_TRANSITIONS,
    DETECTION_RULE_DEPLOYMENT_STATUS_TRANSITIONS,
    DETECTION_RULE_VERSION_STATUS_TRANSITIONS,
)
from schema.knowledge.resources import (
    KNOWLEDGE_DOCUMENT_INFLIGHT_STATUSES,
    KNOWLEDGE_DOCUMENT_STATUS_TRANSITIONS,
)
from schema.runtime import OutboxPayload
from schema.sandbox.async_jobs import SANDBOX_ASYNC_JOB_STATUS_TRANSITIONS
from schema.sandbox.containers import SANDBOX_CONTAINER_STATUS_TRANSITIONS
from schema.threat.behaviors import (
    MAX_BEHAVIOR_ATTRIBUTE_DEPTH,
    MAX_BEHAVIOR_ATTRIBUTE_ITEMS,
    MAX_BEHAVIOR_ATTRIBUTE_STRING_LENGTH,
    MAX_BEHAVIOR_ATTRIBUTES_BYTES,
    MAX_BEHAVIOR_BATCH_BYTES,
)
from schema.threat.incidents import THREAT_INCIDENT_STATUS_TRANSITIONS, ThreatIncidentAction
from schema.threat.investigations import INVESTIGATION_TASK_STATUS_TRANSITIONS
from service.common.pagination import RESOURCE_PAGE_MAX_SIZE, RESOURCE_PAGE_SIZE
from service.knowledge.constants import (
    KNOWLEDGE_GRAPH_EXPANSION_BATCH_SIZE,
    KNOWLEDGE_GRAPH_MAX_NODES,
    MAX_KNOWLEDGE_DOCUMENT_BATCH_SIZE,
    MAX_KNOWLEDGE_DOCUMENT_BYTES,
    MAX_KNOWLEDGE_FILENAME_BYTES,
    SUPPORTED_KNOWLEDGE_DOCUMENT_SUFFIXES,
)


_ROOT_SCHEMAS: dict[str, Any] = {
    "AgentServerFrame": AgentServerFrame,
    "AgentClientFrame": AgentClientFrame,
    "AgentDurableEvent": AgentDurableEvent,
    "OutboxPayload": OutboxPayload,
}

_EXPLICIT_ENUMS = (
    AgentInputPartType,
    AgentDurableEventType,
    AgentServerFrameType,
    AgentClientFrameType,
    ThreatIncidentAction,
)

_STATUS_TRANSITIONS = {
    "agent_session": AGENT_SESSION_STATUS_TRANSITIONS,
    "agent_run": AGENT_RUN_STATUS_TRANSITIONS,
    "agent_attempt": AGENT_ATTEMPT_STATUS_TRANSITIONS,
    "agent_segment": AGENT_SEGMENT_STATUS_TRANSITIONS,
    "agent_context_item": AGENT_CONTEXT_ITEM_STATUS_TRANSITIONS,
    "agent_tool_invocation": AGENT_TOOL_INVOCATION_STATUS_TRANSITIONS,
    "sandbox_async_job": SANDBOX_ASYNC_JOB_STATUS_TRANSITIONS,
    "sandbox_container": SANDBOX_CONTAINER_STATUS_TRANSITIONS,
    "deception_environment": DECEPTION_ENVIRONMENT_STATUS_TRANSITIONS,
    "deception_revision": DECEPTION_REVISION_STATUS_TRANSITIONS,
    "deception_revision_step": DECEPTION_REVISION_STEP_STATUS_TRANSITIONS,
    "detection_rule_version": DETECTION_RULE_VERSION_STATUS_TRANSITIONS,
    "detection_rule_change": DETECTION_RULE_CHANGE_STATUS_TRANSITIONS,
    "detection_rule_deployment": DETECTION_RULE_DEPLOYMENT_STATUS_TRANSITIONS,
    "threat_incident": THREAT_INCIDENT_STATUS_TRANSITIONS,
    "investigation_task": INVESTIGATION_TASK_STATUS_TRANSITIONS,
    "knowledge_document": KNOWLEDGE_DOCUMENT_STATUS_TRANSITIONS,
    "resource_lifecycle": RESOURCE_LIFECYCLE_STATUS_TRANSITIONS,
}

_CONSTRAINT_NAMES = (
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "pattern",
    "format",
)


def register_openapi_contract_schemas(openapi: dict[str, Any]) -> None:
    schemas = openapi.setdefault("components", {}).setdefault("schemas", {})
    for root_name, root_type in _ROOT_SCHEMAS.items():
        body = TypeAdapter(root_type).json_schema(ref_template="#/components/schemas/{model}")
        definitions = body.pop("$defs", {})
        for name, definition in definitions.items():
            schemas.setdefault(name, definition)
        schemas[root_name] = body


def build_agent_stream_schema() -> dict[str, Any]:
    definitions: dict[str, Any] = {}
    roots: dict[str, str] = {}
    for root_name, root_type in _ROOT_SCHEMAS.items():
        body = TypeAdapter(root_type).json_schema(ref_template="#/$defs/{model}")
        definitions.update(body.pop("$defs", {}))
        definitions[root_name] = body
        roots[root_name] = f"#/$defs/{root_name}"
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "V3il Agent Runtime Contract",
        "description": "Bidirectional stream frames, durable events, and runtime Outbox commands.",
        "oneOf": [
            {"$ref": roots["AgentServerFrame"]},
            {"$ref": roots["AgentClientFrame"]},
        ],
        "$defs": definitions,
        "x-v3il-roots": roots,
    }


def build_contract_manifest(openapi: dict[str, Any]) -> dict[str, Any]:
    transitions = {
        name: _transition_values(mapping)
        for name, mapping in sorted(_STATUS_TRANSITIONS.items())
    }
    enums = _openapi_enums(openapi)
    for enum_class in _EXPLICIT_ENUMS:
        enums[enum_class.__name__] = [item.value for item in enum_class]
    for mapping in _STATUS_TRANSITIONS.values():
        enum_type = next(iter(mapping), None)
        if enum_type is not None:
            enum_class = type(enum_type)
            enums.setdefault(enum_class.__name__, [item.value for item in enum_class])
    return {
        "contract_version": 3,
        "agent": {
            "default_code": AgentCode.CSO.value,
            "identities": {
                code.value: {"name": identity[0], "role": identity[1]}
                for code, identity in CANONICAL_AGENT_IDENTITIES.items()
            },
            "capabilities": {
                code.value: [capability.value for capability in capabilities]
                for code, capabilities in AGENT_CAPABILITIES.items()
            },
        },
        "auth": {"access_token_header": ACCESS_TOKEN_HEADER},
        "enums": dict(sorted(enums.items())),
        "field_constraints": _field_constraints(openapi),
        "field_defaults": _field_defaults(openapi),
        "limits": {
            "pagination": {
                "default_page_size": RESOURCE_PAGE_SIZE,
                "maximum_page_size": RESOURCE_PAGE_MAX_SIZE,
            },
            "agent_input": {
                "maximum_images": MAX_AGENT_IMAGES,
                "maximum_image_bytes": MAX_AGENT_IMAGE_BYTES,
                "maximum_total_image_bytes": MAX_AGENT_TOTAL_IMAGE_BYTES,
                "maximum_text_characters": MAX_AGENT_TEXT_INPUT_CHARS,
            },
            "behavior_ingestion": {
                "maximum_attributes_bytes": MAX_BEHAVIOR_ATTRIBUTES_BYTES,
                "maximum_attribute_depth": MAX_BEHAVIOR_ATTRIBUTE_DEPTH,
                "maximum_attribute_items": MAX_BEHAVIOR_ATTRIBUTE_ITEMS,
                "maximum_attribute_string_length": MAX_BEHAVIOR_ATTRIBUTE_STRING_LENGTH,
                "maximum_batch_bytes": MAX_BEHAVIOR_BATCH_BYTES,
            },
            "deception_references": {
                "maximum_urls": MAX_DECEPTION_REFERENCE_URLS,
                "maximum_url_length": MAX_DECEPTION_REFERENCE_URL_LENGTH,
                "maximum_files": MAX_DECEPTION_REFERENCE_FILES,
                "maximum_file_bytes": MAX_DECEPTION_REFERENCE_FILE_BYTES,
                "maximum_total_bytes": MAX_DECEPTION_REFERENCE_TOTAL_BYTES,
            },
            "knowledge": {
                "maximum_document_bytes": MAX_KNOWLEDGE_DOCUMENT_BYTES,
                "maximum_batch_size": MAX_KNOWLEDGE_DOCUMENT_BATCH_SIZE,
                "maximum_filename_bytes": MAX_KNOWLEDGE_FILENAME_BYTES,
                "graph_expansion_batch_size": KNOWLEDGE_GRAPH_EXPANSION_BATCH_SIZE,
                "graph_maximum_nodes": KNOWLEDGE_GRAPH_MAX_NODES,
            },
        },
        "knowledge": {
            "accepted_suffixes": sorted(SUPPORTED_KNOWLEDGE_DOCUMENT_SUFFIXES),
            "document_accept": ",".join(sorted(SUPPORTED_KNOWLEDGE_DOCUMENT_SUFFIXES)),
            "inflight_statuses": [status.value for status in KNOWLEDGE_DOCUMENT_INFLIGHT_STATUSES],
        },
        "status_transitions": transitions,
    }


def _transition_values(mapping: dict[StrEnum, tuple[StrEnum, ...]]) -> dict[str, list[str]]:
    return {
        status.value: [next_status.value for next_status in next_statuses]
        for status, next_statuses in mapping.items()
    }


def _openapi_enums(openapi: dict[str, Any]) -> dict[str, list[str]]:
    schemas = openapi.get("components", {}).get("schemas", {})
    return {
        name: list(body["enum"])
        for name, body in schemas.items()
        if isinstance(body, dict)
        and isinstance(body.get("enum"), list)
        and body["enum"]
        and all(isinstance(value, str) for value in body["enum"])
    }


def _field_constraints(openapi: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    result: dict[str, dict[str, dict[str, Any]]] = {}
    schemas = openapi.get("components", {}).get("schemas", {})
    for schema_name, body in sorted(schemas.items()):
        properties = body.get("properties") if isinstance(body, dict) else None
        if not isinstance(properties, dict):
            continue
        constrained = {
            field_name: {
                name: field_schema[name]
                for name in _CONSTRAINT_NAMES
                if name in field_schema
            }
            for field_name, field_schema in sorted(properties.items())
            if isinstance(field_schema, dict)
            and any(name in field_schema for name in _CONSTRAINT_NAMES)
        }
        if constrained:
            result[schema_name] = constrained
    return result


def _field_defaults(openapi: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    schemas = openapi.get("components", {}).get("schemas", {})
    for schema_name, body in sorted(schemas.items()):
        properties = body.get("properties") if isinstance(body, dict) else None
        if not isinstance(properties, dict):
            continue
        defaults = {
            field_name: field_schema["default"]
            for field_name, field_schema in sorted(properties.items())
            if isinstance(field_schema, dict) and "default" in field_schema
        }
        if defaults:
            result[schema_name] = defaults
    return result
