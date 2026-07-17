from __future__ import annotations

import json
import re
from typing import Any

from schema.detection.rules import (
    CentralRuleDefinition,
    DetectionRuleType,
    SuppressionRuleDefinition,
)


_FORBIDDEN_ZEEK_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"(?im)^\s*@load\s+(?!base/|policy/)", "only approved base/ and policy/ modules may be loaded"),
    (r"(?i)\b(system|exec|popen)\s*\(", "external command execution is forbidden"),
    (r"(?i)\b(open|open_for_append)\s*\(", "arbitrary file access is forbidden"),
    (r"(?im)^\s*@load-plugin\b", "dynamic plugin loading is forbidden"),
    (r"(?i)Log::create_stream\s*\([^)]*path\s*=\s*[^\"']", "dynamic log paths are forbidden"),
)


def validate_rule_content(rule_type: DetectionRuleType, content: str) -> dict[str, Any]:
    normalized = content.strip()
    errors: list[str] = []
    parsed: dict[str, Any] | None = None
    if not normalized:
        errors.append("rule content is empty")
    elif rule_type == DetectionRuleType.CENTRAL_RULE:
        parsed, errors = _validate_json_model(normalized, CentralRuleDefinition)
    elif rule_type == DetectionRuleType.SUPPRESSION:
        parsed, errors = _validate_json_model(normalized, SuppressionRuleDefinition)
    elif rule_type == DetectionRuleType.ZEEK_SCRIPT:
        errors.extend(_validate_zeek_script(normalized))
    elif rule_type == DetectionRuleType.ZEEK_SIGNATURE:
        errors.extend(_validate_zeek_signature(normalized))
    return {
        "valid": not errors,
        "errors": errors,
        "normalized": parsed,
        "validator": "v3il-static-detection-v1",
        "sensor_validation_required": rule_type in {
            DetectionRuleType.ZEEK_SCRIPT,
            DetectionRuleType.ZEEK_SIGNATURE,
        },
    }


def parsed_rule_content(rule_type: DetectionRuleType, content: str) -> dict[str, Any]:
    if rule_type not in {DetectionRuleType.CENTRAL_RULE, DetectionRuleType.SUPPRESSION}:
        return {}
    result = validate_rule_content(rule_type, content)
    if not result["valid"] or not isinstance(result["normalized"], dict):
        raise ValueError("rule content is not valid")
    return result["normalized"]


def _validate_json_model(content: str, model) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        payload = json.loads(content)
        item = model.model_validate(payload)
    except (json.JSONDecodeError, ValueError) as exc:
        return None, [str(exc)]
    return item.model_dump(mode="json"), []


def _validate_zeek_script(content: str) -> list[str]:
    errors = [message for pattern, message in _FORBIDDEN_ZEEK_PATTERNS if re.search(pattern, content)]
    if len(content.encode("utf-8")) > 256_000:
        errors.append("Zeek script exceeds 256000 bytes")
    if content.count("{") != content.count("}"):
        errors.append("Zeek script braces are unbalanced")
    if len(re.findall(r"(?i)\bschedule\b", content)) > 32:
        errors.append("Zeek script contains too many schedules")
    if len(re.findall(r"(?i)\b(table|set)\s*\[", content)) > 128:
        errors.append("Zeek script declares too many tables or sets")
    for regex_literal in re.findall(r"/(.*?)(?<!\\)/", content, flags=re.DOTALL):
        if len(regex_literal) > 4096:
            errors.append("Zeek regular expression exceeds 4096 characters")
            break
    return errors


def _validate_zeek_signature(content: str) -> list[str]:
    errors: list[str] = []
    if not re.search(r"(?m)^\s*signature\s+[A-Za-z0-9_.:-]+\s*\{", content):
        errors.append("Zeek signature content must contain a signature block")
    if content.count("{") != content.count("}"):
        errors.append("Zeek signature braces are unbalanced")
    if len(content.encode("utf-8")) > 256_000:
        errors.append("Zeek signature exceeds 256000 bytes")
    return errors
