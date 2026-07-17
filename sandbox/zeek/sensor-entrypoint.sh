#!/bin/sh
set -eu

STATE_DIR="${V3IL_ZEEK_STATE_DIR:-/var/lib/v3il-zeek}"
LOG_DIR="${V3IL_ZEEK_LOG_DIR:-/var/log/zeek}"
SITE_POLICY="${V3IL_ZEEK_SITE_POLICY:-/opt/v3il-zeek/local.zeek}"
mkdir -p "$STATE_DIR" "$LOG_DIR"

pid=""
active=""

stop_zeek() {
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    wait "$pid" || true
  fi
  pid=""
}

write_health() {
  bundle_hash="$1"
  error="$2"
  tmp="$STATE_DIR/zeek-health.tmp"
  printf '{"active_bundle_hash":"%s","error":"%s"}\n' "$bundle_hash" "$error" > "$tmp"
  mv "$tmp" "$STATE_DIR/zeek-health.json"
}

start_zeek() {
  bundle_hash="$1"
  bundle="$STATE_DIR/bundles/$bundle_hash.json"
  bundle_log_dir="$LOG_DIR/$bundle_hash"
  generated="$STATE_DIR/generated-$bundle_hash.zeek"
  signatures="$STATE_DIR/generated-$bundle_hash.sig"
  : > "$generated"
  : > "$signatures"
  mkdir -p "$bundle_log_dir"
  python3 - "$bundle" "$generated" "$signatures" <<'PY'
import json, pathlib, sys
bundle = json.loads(pathlib.Path(sys.argv[1]).read_text())
scripts, signatures = [], []
for rule in bundle.get("rules", []):
    if rule.get("type") == "zeek_script":
        scripts.append(rule.get("content", ""))
    elif rule.get("type") == "zeek_signature":
        signatures.append(rule.get("content", ""))
pathlib.Path(sys.argv[2]).write_text("\n\n".join(scripts), encoding="utf-8")
pathlib.Path(sys.argv[3]).write_text("\n\n".join(signatures), encoding="utf-8")
PY
  interface=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["capture_interface"])' "$bundle")
  filter=$(python3 - "$bundle" <<'PY'
import json, sys
b = json.load(open(sys.argv[1]))
ports = sorted({(t.get("protocol", "tcp"), int(t["host_port"])) for t in b.get("targets", [])})
excluded = {int(p) for p in b.get("excluded_ports", [])}
parts = [f"({proto} port {port})" for proto, port in ports if port not in excluded]
print(" or ".join(parts) or "port 0")
PY
)
  if [ -s "$signatures" ]; then
    set -- zeek -C -i "$interface" -f "$filter" -s "$signatures" "$SITE_POLICY" "$generated"
  else
    set -- zeek -C -i "$interface" -f "$filter" "$SITE_POLICY" "$generated"
  fi
  (cd "$bundle_log_dir" && exec "$@") &
  pid="$!"
  sleep 2
  if ! kill -0 "$pid" 2>/dev/null; then
    wait "$pid" || true
    pid=""
    write_health "" "Zeek failed to start"
    return 1
  fi
  active="$bundle_hash"
  write_health "$active" ""
}

trap 'stop_zeek; exit 0' INT TERM

while :; do
  for request in "$STATE_DIR"/validation-request-*; do
    [ -f "$request" ] || continue
    validation_hash=${request##*validation-request-}
    validation_bundle="$STATE_DIR/bundles/$validation_hash.json"
    validation_script="$STATE_DIR/validate-$validation_hash.zeek"
    validation_signatures="$STATE_DIR/validate-$validation_hash.sig"
    validation_output="$STATE_DIR/validation-$validation_hash.output"
    python3 - "$validation_bundle" "$validation_script" "$validation_signatures" <<'PY'
import json, pathlib, sys
bundle = json.loads(pathlib.Path(sys.argv[1]).read_text())
scripts, signatures = [], []
for rule in bundle.get("rules", []):
    if rule.get("type") == "zeek_script": scripts.append(rule.get("content", ""))
    elif rule.get("type") == "zeek_signature": signatures.append(rule.get("content", ""))
pathlib.Path(sys.argv[2]).write_text("\n\n".join(scripts), encoding="utf-8")
pathlib.Path(sys.argv[3]).write_text("\n\n".join(signatures), encoding="utf-8")
PY
    valid=true
    if [ -s "$validation_signatures" ]; then
      zeek -b -s "$validation_signatures" "$SITE_POLICY" "$validation_script" > "$validation_output" 2>&1 || valid=false
    else
      zeek -b "$SITE_POLICY" "$validation_script" > "$validation_output" 2>&1 || valid=false
    fi
    python3 - "$STATE_DIR/validation-$validation_hash.json" "$validation_output" "$valid" <<'PY'
import json, pathlib, sys
output = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace")[:16000]
target = pathlib.Path(sys.argv[1])
temporary = target.with_suffix(".tmp")
temporary.write_text(json.dumps({"valid": sys.argv[3] == "true", "output": output}, separators=(",", ":")), encoding="utf-8")
temporary.replace(target)
PY
    rm -f "$request" "$validation_output"
  done
  desired=""
  [ ! -f "$STATE_DIR/desired-bundle" ] || desired=$(cat "$STATE_DIR/desired-bundle")
  if [ "$desired" != "$active" ]; then
    stop_zeek
    active=""
    if [ -n "$desired" ]; then
      start_zeek "$desired" || true
    else
      write_health "" ""
    fi
  elif [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
    wait "$pid" || true
    pid=""
    active=""
    write_health "" "Zeek exited unexpectedly"
  fi
  sleep 1
done
