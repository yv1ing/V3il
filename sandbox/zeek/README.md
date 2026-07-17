# V3il Zeek Runtime

The V3il sandbox image can run a dedicated Zeek detection service on each Managed Host. This service captures traffic from the selected host interface, applies the active detection bundle, converts Zeek output into V3il behavior events, and reports runtime health through the existing sandbox control channel.

## Components

- **Zeek Sensor:** Captures traffic and runs the active Zeek scripts and signatures.
- **Adapter:** Converts Zeek JSON logs into V3il behavior events and maintains event-chain state.
- **sandbox-proxy:** Authenticates control-plane requests and exposes the detection management API.

When the Zeek Adapter token is present, `sandbox-proxy` runs in the dedicated Sensor role. It exposes only the authenticated root, health, and `/detection/*` routes; shell, file, workload, telemetry, and egress-proxy routes are not registered, and port `8118` is not opened.

The runtime entrypoint is:

```text
/usr/local/bin/v3il-zeek-runtime
```

The standard `/entrypoint.sh` continues to launch a deception environment.

## Security Model

The Zeek process receives the capture interface and active rule bundle. Detection management is available through `sandbox-proxy`, while the Adapter remains on loopback. The control-plane token and the internal Proxy-to-Adapter token serve separate trust relationships.

Publish the existing sandbox control-proxy port for management. Do not publish the Adapter port.

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `SANDBOX_CONTROL_PROXY_TOKEN` | Authenticates control-plane requests and verifies the event chain. |
| `V3IL_SENSOR_ID` | Identifies the Managed Host sensor. |
| `V3IL_ADAPTER_TOKEN` | Authenticates loopback requests from the Proxy to the Adapter. |
| `V3IL_ZEEK_STATE_DIR` | Persistent state directory; defaults to `/var/lib/v3il-zeek`. |
| `V3IL_ZEEK_LOG_DIR` | Zeek JSON log root; defaults to `/var/log/zeek`. |
| `V3IL_ZEEK_SITE_POLICY` | Site policy path; defaults to `/opt/v3il-zeek/local.zeek`. |

Each active detection bundle writes to its own directory beneath `V3IL_ZEEK_LOG_DIR`.

## Deployment

The runtime needs packet-capture access to the Managed Host interface selected in V3il. Grant only the network namespace and capture capabilities required for that interface.

Deploy one detection runtime for each Managed Host that needs Zeek coverage. The main Compose files manage the V3il control plane and do not create host-specific detection runtimes.

For a Linux Managed Host, a minimal deployment uses the host network namespace so Zeek can capture the configured host interface and the control plane can reach Proxy port `8000`:

```text
docker run -d --name v3il-zeek-sensor \
  --network host \
  --cap-drop ALL \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  --entrypoint /usr/local/bin/v3il-zeek-runtime \
  -e SANDBOX_CONTROL_PROXY_TOKEN=<proxy-token> \
  -e V3IL_SENSOR_ID=<sensor-id> \
  -e V3IL_ADAPTER_TOKEN=<internal-adapter-token> \
  -v v3il-zeek-state:/var/lib/v3il-zeek \
  -v v3il-zeek-logs:/var/log/zeek \
  deception-runtime:latest
```

Configure V3il with the Managed Host-reachable Proxy URL such as `http://<managed-host-address>:8000` and the exact `SANDBOX_CONTROL_PROXY_TOKEN`. Never use `V3IL_ADAPTER_TOKEN` outside the container.
