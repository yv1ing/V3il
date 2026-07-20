# Quick Start

## Requirements

Prepare the following before deploying V3il:

- Linux with Docker Engine and Docker Compose;
- PostgreSQL;
- five OpenAI-compatible model endpoints for `cso`, `cth`, `cde`, `cie`, and `cir`;
- embedding and LLM endpoints for LightRAG;
- Docker hosts and networks for deception environments;
- a trusted management network and persistent storage.

## 1. Create The Configuration

```bash
cp .v3il/config.json.example .v3il/config.json
```

Edit `.v3il/config.json`:

- replace the JWT signing key and bootstrap administrator password;
- configure PostgreSQL;
- set the API endpoint, key, and model for each Agent;
- configure LightRAG embedding and LLM access;
- tune Agent runtime, behavior capture, and automation for the deployment size.

Check the PostgreSQL user, password, and database in Compose and keep them consistent with the application configuration.

## 2. Build The Runtime Image

```bash
cd sandbox
./build.sh
cd ..
```

Prepare the same image on each Managed Host that may run a deception environment, or distribute it through the team's existing image pipeline.

## 3. Start The Platform

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

The default address is `http://127.0.0.1:8000`.

## 4. Prepare Infrastructure

Sign in with the bootstrap administrator, then:

1. verify the local Docker host or register a remote host under Managed Hosts;
2. register the built image under Sandbox Images;
3. add an Egress Proxy if the environment requires proxy routing;
4. check host, image, and detection health.

## 5. Create The First Environment

Open Deception Environments and set the name, description, Managed Host, Sandbox Image, egress policy, and adaptation mode. You can attach reference URLs, source code, documents, or archives.

Continue in the environment Agent Console and describe:

- the business or system context;
- the services, identities, and data to present;
- attack paths worth observing;
- critical interactions and monitoring goals;
- the required realism and engagement depth.

Ph4ntom designs, deploys, and verifies the environment before it becomes active.

## 6. Verify The Operational Flow

Access the environment from an isolated test network and confirm that:

- the attacker-facing services match the design;
- behavior and detections appear in the environment workspace;
- related activity creates a ThreatIncident;
- Agent tasks and evidence begin to update;
- the Incident workspace presents the timeline and analysis;
- reporting and knowledge services are available.

## Deployment Notes

V3il requires Docker management access and handles model credentials, infrastructure credentials, and attacker behavior. Keep the Web console, API, PostgreSQL, Docker management network, and configuration inside a trusted network. Place attacker-facing environments on isolated networks without access to production assets or management endpoints.
