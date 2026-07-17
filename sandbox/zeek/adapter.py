#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


SENSOR_ID = os.environ["V3IL_SENSOR_ID"]
TOKEN = os.environ["V3IL_ADAPTER_TOKEN"]
SENSOR_HMAC_TOKEN = os.environ["V3IL_SENSOR_HMAC_TOKEN"]
LOG_DIR = Path(os.getenv("V3IL_ZEEK_LOG_DIR", "/var/log/zeek"))
STATE_DIR = Path(os.getenv("V3IL_ZEEK_STATE_DIR", "/var/lib/v3il-zeek"))
LISTEN = os.getenv("V3IL_ADAPTER_LISTEN", "127.0.0.1:8765")
MAX_PAGE_SIZE = 1000
MAX_REQUEST_BYTES = 2_000_000

STATE_DIR.mkdir(parents=True, exist_ok=True)
(STATE_DIR / "bundles").mkdir(parents=True, exist_ok=True)
JOURNAL_PATH = STATE_DIR / "events.jsonl"
ADAPTER_STATE_PATH = STATE_DIR / "adapter-state.json"
DESIRED_BUNDLE_PATH = STATE_DIR / "desired-bundle"
ZEEK_HEALTH_PATH = STATE_DIR / "zeek-health.json"

_lock = threading.RLock()
_state = {"journal_sequence": 0, "offsets": {}, "chains": {}, "last_error": ""}
_active_bundle: dict = {}


def _load_state() -> None:
    global _state
    if ADAPTER_STATE_PATH.exists():
        loaded = json.loads(ADAPTER_STATE_PATH.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            _state.update(loaded)
    _recover_journal_state()
    active = ""
    try:
        health = json.loads(ZEEK_HEALTH_PATH.read_text(encoding="utf-8")) if ZEEK_HEALTH_PATH.exists() else {}
        active = str(health.get("active_bundle_hash") or "")
    except (OSError, json.JSONDecodeError):
        pass
    _load_bundle(active)


def _recover_journal_state() -> None:
    if not JOURNAL_PATH.exists():
        return
    recovered_sequence = 0
    recovered_chains = {}
    recovered_offsets = dict(_state.get("offsets") or {})
    valid_bytes = 0
    with JOURNAL_PATH.open("rb") as journal:
        while True:
            line = journal.readline()
            if not line:
                break
            next_offset = journal.tell()
            try:
                item = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                if next_offset != JOURNAL_PATH.stat().st_size:
                    raise RuntimeError("Zeek Adapter journal contains a corrupt non-terminal record")
                break
            sequence = int(item.get("journal_sequence") or 0)
            if sequence != recovered_sequence + 1:
                raise RuntimeError("Zeek Adapter journal sequence is not contiguous")
            event = item.get("event")
            environment_id = int(item.get("environment_id") or 0)
            if environment_id <= 0 or not isinstance(event, dict):
                raise RuntimeError("Zeek Adapter journal record is missing its environment event")
            chain_key = str(environment_id)
            expected_chain_sequence = int(recovered_chains.get(chain_key, {}).get("sequence") or 0) + 1
            if int(event.get("sequence") or 0) != expected_chain_sequence:
                raise RuntimeError("Zeek Adapter environment chain sequence is not contiguous")
            recovered_chains[chain_key] = {
                "sequence": expected_chain_sequence,
                "last_hash": str(event.get("sensor_event_hash") or ""),
            }
            log_path = item.get("log_path")
            log_offset = item.get("log_offset")
            if isinstance(log_path, str) and isinstance(log_offset, int) and log_offset >= 0:
                recovered_offsets[log_path] = max(int(recovered_offsets.get(log_path, 0)), log_offset)
            recovered_sequence = sequence
            valid_bytes = next_offset
    if valid_bytes != JOURNAL_PATH.stat().st_size:
        with JOURNAL_PATH.open("r+b") as journal:
            journal.truncate(valid_bytes)
            journal.flush()
            os.fsync(journal.fileno())
    _state["journal_sequence"] = recovered_sequence
    _state["chains"] = recovered_chains
    _state["offsets"] = recovered_offsets


def _save_state() -> None:
    temporary = ADAPTER_STATE_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(_state, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.replace(temporary, ADAPTER_STATE_PATH)


def _load_bundle(bundle_hash: str) -> None:
    global _active_bundle
    path = STATE_DIR / "bundles" / f"{bundle_hash}.json"
    _active_bundle = json.loads(path.read_text(encoding="utf-8")) if bundle_hash and path.exists() else {}


def _hash_bundle(bundle: dict) -> str:
    payload = dict(bundle)
    payload.pop("bundle_hash", None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonical_sensor_event(event: dict) -> str:
    payload = dict(event)
    payload.pop("sensor_event_hash", None)
    optional_strings = (
        "source_ip", "destination_ip", "protocol", "process_name", "command_line",
        "file_path", "username", "service_name", "summary", "raw_reference",
        "network_session_id", "sensor_bundle_hash", "sensor_previous_hash",
    )
    optional_integers = (
        "source_port", "destination_port", "process_id", "parent_process_id",
        "deception_artifact_id",
    )
    for field in optional_strings:
        if not payload.get(field):
            payload.pop(field, None)
    for field in optional_integers:
        if payload.get(field) in (None, 0):
            payload.pop(field, None)
    if not payload.get("attributes"):
        payload.pop("attributes", None)
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return canonical.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def _sensor_hash(event: dict) -> str:
    key = hashlib.sha256(f"v3il-sensor-hmac:{SENSOR_HMAC_TOKEN}".encode()).digest()
    return hmac.new(key, _canonical_sensor_event(event).encode("utf-8"), hashlib.sha256).hexdigest()


def _event_time(value) -> str:
    try:
        moment = datetime.fromtimestamp(float(value), timezone.utc)
    except (TypeError, ValueError, OSError):
        moment = datetime.now(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _target_for(bundle: dict, data: dict) -> dict | None:
    port = data.get("id.resp_p")
    protocol = str(data.get("proto") or "tcp").lower()
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    for target in bundle.get("targets", []):
        if target.get("host_port") == port and target.get("protocol") == protocol:
            return target
    return None


def _artifact_for(bundle: dict, environment_id: int, data: dict) -> int | None:
    searchable = json.dumps(data, ensure_ascii=False, sort_keys=True)
    for artifact in bundle.get("artifacts", []):
        fingerprint = str(artifact.get("fingerprint") or "")
        if artifact.get("environment_id") == environment_id and fingerprint and fingerprint in searchable:
            return int(artifact["id"])
    return None


def _normalize(bundle: dict, log_type: str, data: dict, target: dict) -> dict:
    source_ip = str(data.get("id.orig_h") or "")
    destination_ip = str(data.get("id.resp_h") or "")
    source_port = data.get("id.orig_p")
    destination_port = data.get("id.resp_p")
    uid = str(data.get("uid") or "")
    protocol = str(data.get("proto") or "tcp")
    attributes = {str(key): value for key, value in data.items() if key not in {"ts"}}
    category = "network"
    action = f"zeek_{log_type}"
    service_name = str(data.get("service") or log_type)
    outcome = "unknown"
    summary = f"Zeek {log_type} activity"
    if log_type == "conn":
        action = "network_connection"
        state = str(data.get("conn_state") or "")
        outcome = "success" if state in {"SF", "S1"} else "failure" if state in {"REJ", "RSTO", "RSTR"} else "unknown"
        summary = f"{protocol.upper()} connection {source_ip}:{source_port} to {destination_ip}:{destination_port} ({state or 'unknown'})"
    elif log_type == "http":
        method = str(data.get("method") or "")
        uri = str(data.get("uri") or "")
        status = data.get("status_code")
        authentication_failure = status in {401, 403}
        category = "authentication" if authentication_failure else "service"
        action = "http_authentication" if authentication_failure else "http_request"
        outcome = "failure" if authentication_failure else "success" if isinstance(status, int) and status < 400 else "failure" if status else "unknown"
        summary = f"{method or 'HTTP'} {uri or '/'} status={status or 'unknown'}"
        attributes["uri"] = uri
    elif log_type == "dns":
        action = "dns_query"
        summary = f"DNS query {data.get('query') or ''} type={data.get('qtype_name') or data.get('qtype') or ''}".strip()
    elif log_type in {"ssl", "x509"}:
        category = "service"
        action = "tls_session"
        summary = f"TLS session server={data.get('server_name') or ''} version={data.get('version') or ''}".strip()
    elif log_type == "ssh":
        category = "authentication"
        action = "ssh_authentication"
        outcome = "success" if data.get("auth_success") is True else "failure" if data.get("auth_success") is False else "unknown"
        summary = f"SSH session client={data.get('client') or ''} server={data.get('server') or ''}".strip()
    elif log_type == "notice":
        category = "service"
        action = "zeek_notice"
        summary = f"Zeek notice {data.get('note') or ''}: {data.get('msg') or ''}".strip()
    elif log_type == "weird":
        category = "service"
        action = "zeek_weird"
        summary = f"Zeek weird {data.get('name') or ''}: {data.get('addl') or ''}".strip()
    environment_id = int(target["environment_id"])
    artifact_id = _artifact_for(bundle, environment_id, data)
    return {
        "observed_at": _event_time(data.get("ts")),
        "category": category,
        "action": action,
        "source": "sensor",
        "direction": "inbound",
        "outcome": outcome,
        "source_ip": source_ip,
        "source_port": int(source_port) if source_port else None,
        "destination_ip": destination_ip,
        "destination_port": int(destination_port) if destination_port else None,
        "protocol": protocol,
        "service_name": service_name,
        "username": str(data.get("username") or data.get("user") or ""),
        "network_session_id": uid,
        "sensor_bundle_hash": str(bundle.get("bundle_hash") or ""),
        "deception_artifact_id": artifact_id,
        "summary": summary[:4000],
        "attributes": attributes,
    }


def _append_normalized(bundle: dict, log_type: str, data: dict, log_path: str, log_offset: int) -> None:
    target = _target_for(bundle, data)
    if target is None:
        return
    environment_id = int(target["environment_id"])
    chain_key = str(environment_id)
    chain = _state["chains"].setdefault(chain_key, {"sequence": 0, "last_hash": ""})
    event = _normalize(bundle, log_type, data, target)
    event["sequence"] = int(chain["sequence"]) + 1
    event["raw_reference"] = f"zeek://{SENSOR_ID}/{log_type}/{_state['journal_sequence'] + 1}"
    event["sensor_previous_hash"] = str(chain["last_hash"])
    event["sensor_event_hash"] = _sensor_hash(event)
    wrapper = {
        "journal_sequence": int(_state["journal_sequence"]) + 1,
        "environment_id": environment_id,
        "chain_sensor_id": f"zeek:{SENSOR_ID}:env:{environment_id}",
        "log_path": log_path,
        "log_offset": log_offset,
        "event": event,
    }
    with JOURNAL_PATH.open("a", encoding="utf-8") as journal:
        journal.write(json.dumps(wrapper, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
        journal.flush()
        os.fsync(journal.fileno())
    _state["journal_sequence"] = wrapper["journal_sequence"]
    chain["sequence"] = event["sequence"]
    chain["last_hash"] = event["sensor_event_hash"]


def _scan_logs() -> None:
    while True:
        try:
            with _lock:
                try:
                    health = json.loads(ZEEK_HEALTH_PATH.read_text(encoding="utf-8")) if ZEEK_HEALTH_PATH.exists() else {}
                    active_hash = str(health.get("active_bundle_hash") or "")
                    if active_hash != str(_active_bundle.get("bundle_hash") or ""):
                        _load_bundle(active_hash)
                except (OSError, json.JSONDecodeError):
                    pass
                for path in sorted(LOG_DIR.glob("*/*.log")):
                    bundle_hash = path.parent.name
                    bundle_path = STATE_DIR / "bundles" / f"{bundle_hash}.json"
                    if not re.fullmatch(r"[0-9a-f]{64}", bundle_hash) or not bundle_path.exists():
                        continue
                    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
                    if _hash_bundle(bundle) != bundle_hash or bundle.get("bundle_hash") != bundle_hash:
                        raise RuntimeError("Zeek log directory references an invalid Bundle")
                    log_type = path.stem.split(".")[0]
                    key = str(path)
                    offset = int(_state["offsets"].get(key, 0))
                    size = path.stat().st_size
                    if size < offset:
                        offset = 0
                    with path.open("r", encoding="utf-8", errors="replace") as handle:
                        handle.seek(offset)
                        while True:
                            line = handle.readline()
                            if not line:
                                break
                            line_offset = handle.tell()
                            try:
                                data = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            if isinstance(data, dict):
                                _append_normalized(bundle, log_type, data, key, line_offset)
                        _state["offsets"][key] = handle.tell()
                _save_state()
                _state["last_error"] = ""
        except Exception as exc:
            with _lock:
                _state["last_error"] = str(exc)
                _save_state()
        time.sleep(1)


class Handler(BaseHTTPRequestHandler):
    server_version = "V3ilZeekAdapter/1.0"

    def do_GET(self):
        if not self._authorized():
            return
        parsed = urlparse(self.path)
        if parsed.path == "/v1/health":
            return self._health()
        if parsed.path == "/v1/events":
            query = parse_qs(parsed.query, keep_blank_values=True)
            try:
                after = self._query_integer(query, "after", default=0, minimum=0)
                limit = self._query_integer(query, "limit", default=MAX_PAGE_SIZE, minimum=1)
            except ValueError as exc:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return self._events(after, min(limit, MAX_PAGE_SIZE))
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_PUT(self):
        if not self._authorized():
            return
        match = re.fullmatch(r"/v1/bundles/([0-9a-f]{64})", urlparse(self.path).path)
        if not match:
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        bundle = self._body()
        if not isinstance(bundle, dict) or _hash_bundle(bundle) != match.group(1) or bundle.get("bundle_hash") != match.group(1):
            return self._json(HTTPStatus.CONFLICT, {"error": "bundle hash mismatch"})
        path = STATE_DIR / "bundles" / f"{match.group(1)}.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(bundle, ensure_ascii=False, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        os.replace(temporary, path)
        validation_path = STATE_DIR / f"validation-{match.group(1)}.json"
        validation_path.unlink(missing_ok=True)
        (STATE_DIR / f"validation-request-{match.group(1)}").touch()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not validation_path.exists():
            time.sleep(0.25)
        if not validation_path.exists():
            return self._json(HTTPStatus.GATEWAY_TIMEOUT, {"error": "Zeek isolated validation timed out"})
        try:
            validation = json.loads(validation_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return self._json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": "Zeek validation result is unreadable"})
        if not validation.get("valid"):
            return self._json(HTTPStatus.UNPROCESSABLE_ENTITY, validation)
        self._json(HTTPStatus.OK, {"bundle_hash": match.group(1), "staged": True, "validation": validation})

    def do_POST(self):
        if not self._authorized():
            return
        path = urlparse(self.path).path
        activate = re.fullmatch(r"/v1/bundles/([0-9a-f]{64})/activate", path)
        if activate:
            bundle_hash = activate.group(1)
            if not (STATE_DIR / "bundles" / f"{bundle_hash}.json").exists():
                return self._json(HTTPStatus.NOT_FOUND, {"error": "bundle not staged"})
            temporary = DESIRED_BUNDLE_PATH.with_suffix(".tmp")
            temporary.write_text(bundle_hash, encoding="utf-8")
            os.replace(temporary, DESIRED_BUNDLE_PATH)
            return self._json(HTTPStatus.ACCEPTED, {"bundle_hash": bundle_hash, "activating": True})
        if path == "/v1/bundles/rollback":
            body = self._body()
            bundle_hash = str(body.get("bundle_hash") or "") if isinstance(body, dict) else ""
            if bundle_hash and not (STATE_DIR / "bundles" / f"{bundle_hash}.json").exists():
                return self._json(HTTPStatus.NOT_FOUND, {"error": "rollback bundle not staged"})
            DESIRED_BUNDLE_PATH.write_text(bundle_hash, encoding="utf-8")
            return self._json(HTTPStatus.ACCEPTED, {"bundle_hash": bundle_hash, "rolling_back": True})
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def _health(self):
        zeek = {}
        try:
            zeek = json.loads(ZEEK_HEALTH_PATH.read_text(encoding="utf-8")) if ZEEK_HEALTH_PATH.exists() else {}
        except (OSError, json.JSONDecodeError):
            pass
        with _lock:
            desired = DESIRED_BUNDLE_PATH.read_text(encoding="utf-8").strip() if DESIRED_BUNDLE_PATH.exists() else ""
            active = str(zeek.get("active_bundle_hash") or "")
            error = str(zeek.get("error") or _state.get("last_error") or "")
            status = "healthy" if active == desired and not error else "degraded"
            self._json(HTTPStatus.OK, {
                "sensor_id": SENSOR_ID,
                "status": status,
                "active_bundle_hash": active,
                "desired_bundle_hash": desired,
                "sequence": _state["journal_sequence"],
                "error": error,
            })

    def _events(self, after: int, limit: int):
        events = []
        if JOURNAL_PATH.exists():
            with _lock, JOURNAL_PATH.open("r", encoding="utf-8") as journal:
                for line in journal:
                    item = json.loads(line)
                    if int(item.get("journal_sequence") or 0) > after:
                        events.append(item)
                        if len(events) >= max(1, limit):
                            break
        self._json(HTTPStatus.OK, {"sensor_id": SENSOR_ID, "events": events})

    def _authorized(self):
        provided = self.headers.get("Authorization", "").removeprefix("Bearer ")
        if hmac.compare_digest(provided, TOKEN):
            return True
        self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
        return False

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 0 or length > MAX_REQUEST_BYTES:
            return None
        try:
            return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _query_integer(self, query, name, *, default, minimum):
        values = query.get(name)
        if values is None:
            return default
        if len(values) != 1:
            raise ValueError(f"{name} must contain one integer")
        try:
            value = int(values[0])
        except ValueError as exc:
            raise ValueError(f"{name} must be an integer") from exc
        if value < minimum:
            raise ValueError(f"{name} must be at least {minimum}")
        return value

    def _json(self, status, payload):
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    _load_state()
    threading.Thread(target=_scan_logs, name="zeek-log-adapter", daemon=True).start()
    host, port = LISTEN.rsplit(":", 1)
    ThreadingHTTPServer((host, int(port)), Handler).serve_forever()
