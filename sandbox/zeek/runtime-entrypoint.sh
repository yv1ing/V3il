#!/bin/sh
set -eu

: "${SANDBOX_CONTROL_PROXY_TOKEN:?SANDBOX_CONTROL_PROXY_TOKEN is required}"
: "${V3IL_SENSOR_ID:?V3IL_SENSOR_ID is required}"
: "${V3IL_ADAPTER_TOKEN:?V3IL_ADAPTER_TOKEN is required}"

STATE_DIR="${V3IL_ZEEK_STATE_DIR:-/var/lib/v3il-zeek}"
LOG_DIR="${V3IL_ZEEK_LOG_DIR:-/var/log/zeek}"
SITE_POLICY="${V3IL_ZEEK_SITE_POLICY:-/opt/v3il-zeek/local.zeek}"

mkdir -p "$STATE_DIR/bundles" "$LOG_DIR" /run/v3il /var/lib/v3il/telemetry
chown 0:10001 "$STATE_DIR" "$STATE_DIR/bundles" "$LOG_DIR" /run/v3il
chmod 0770 "$STATE_DIR" "$STATE_DIR/bundles" "$LOG_DIR"
chmod 0750 /run/v3il

adapter_pid=""
sensor_pid=""
proxy_pid=""

stop_runtime() {
  trap - INT TERM EXIT
  [ -z "$proxy_pid" ] || kill "$proxy_pid" 2>/dev/null || true
  [ -z "$adapter_pid" ] || kill "$adapter_pid" 2>/dev/null || true
  [ -z "$sensor_pid" ] || kill "$sensor_pid" 2>/dev/null || true
  [ -z "$proxy_pid" ] || wait "$proxy_pid" 2>/dev/null || true
  [ -z "$adapter_pid" ] || wait "$adapter_pid" 2>/dev/null || true
  [ -z "$sensor_pid" ] || wait "$sensor_pid" 2>/dev/null || true
}

trap 'stop_runtime; exit 0' INT TERM
trap 'stop_runtime' EXIT

setpriv --reuid=10001 --regid=10001 --init-groups \
  env -i \
  PATH="/opt/zeek/bin:/usr/local/bin:/usr/bin:/bin" \
  LANG=C.UTF-8 \
  V3IL_SENSOR_ID="$V3IL_SENSOR_ID" \
  V3IL_ADAPTER_TOKEN="$V3IL_ADAPTER_TOKEN" \
  V3IL_SENSOR_HMAC_TOKEN="$SANDBOX_CONTROL_PROXY_TOKEN" \
  V3IL_ZEEK_LOG_DIR="$LOG_DIR" \
  V3IL_ZEEK_STATE_DIR="$STATE_DIR" \
  V3IL_ADAPTER_LISTEN=127.0.0.1:8765 \
  /opt/v3il-zeek/adapter.py &
adapter_pid="$!"

env -i \
  PATH="/opt/zeek/bin:/usr/local/bin:/usr/bin:/bin" \
  LANG=C.UTF-8 \
  V3IL_ZEEK_LOG_DIR="$LOG_DIR" \
  V3IL_ZEEK_STATE_DIR="$STATE_DIR" \
  V3IL_ZEEK_SITE_POLICY="$SITE_POLICY" \
  /usr/local/bin/v3il-zeek-sensor &
sensor_pid="$!"

/usr/local/bin/sandbox-proxy &
proxy_pid="$!"

while kill -0 "$adapter_pid" 2>/dev/null \
  && kill -0 "$sensor_pid" 2>/dev/null \
  && kill -0 "$proxy_pid" 2>/dev/null; do
  sleep 1
done

exit 1
