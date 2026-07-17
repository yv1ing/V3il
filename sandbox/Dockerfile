# syntax=docker/dockerfile:1.7

ARG DEBIAN_RELEASE=trixie
ARG ZEEK_REPOSITORY_RELEASE=Debian_13
ARG ZEEK_LTS_VERSION=8.0.9-0

FROM golang:1.26-${DEBIAN_RELEASE} AS proxy-builder

ENV CGO_ENABLED=0

WORKDIR /src/proxy
COPY proxy/ ./
RUN go build -trimpath -ldflags='-s -w' -o /sandbox-proxy .

FROM debian:${DEBIAN_RELEASE}-slim

ARG ZEEK_REPOSITORY_RELEASE
ARG ZEEK_LTS_VERSION

ENV HOME=/root \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH=/opt/zeek/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    TERM=xterm-256color \
    V3IL_TELEMETRY_SOCKET=/run/v3il/telemetry.sock \
    V3IL_TELEMETRY_PATH=/var/lib/v3il/telemetry/events.jsonl \
    V3IL_OBSERVER_PATHS=/home/v3il-deception,/srv,/var/www,/opt/deception,/tmp \
    V3IL_OBSERVER_EXCLUDED_PORTS=8000,8118

WORKDIR /root

ARG DEBIAN_FRONTEND=noninteractive

# Keep only utilities needed to construct, inspect, observe, and detect activity
# in the deception and dedicated Managed Host Sensor runtime roles.
RUN set -eux; \
    printf '%s\n' \
      'path-exclude=/usr/share/doc/*' \
      'path-exclude=/usr/share/man/*' \
      'path-exclude=/usr/share/info/*' \
      'path-exclude=/usr/share/lintian/*' \
      'path-exclude=/usr/share/locale/*' \
      'path-include=/usr/share/locale/locale.alias' \
      > /etc/dpkg/dpkg.cfg.d/01_nodoc; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      file \
      gpg \
      jq \
      netcat-openbsd \
      openssl \
      python3 \
      ripgrep \
      strace \
      tar \
      unzip \
      util-linux; \
    curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/${ZEEK_REPOSITORY_RELEASE}/Release.key" \
      | gpg --dearmor --yes --output /usr/share/keyrings/zeek.gpg; \
    printf 'deb [signed-by=/usr/share/keyrings/zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/%s/ /\n' \
      "$ZEEK_REPOSITORY_RELEASE" > /etc/apt/sources.list.d/zeek.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends "zeek-lts-core=${ZEEK_LTS_VERSION}"; \
    zeek --version; \
    printf '%s\n' 'v3il-deception:x:10001:' >> /etc/group; \
    printf '%s\n' 'v3il-deception:x:10001:10001:V3il deception runtime:/home/v3il-deception:/bin/bash' >> /etc/passwd; \
    mkdir -p /home/v3il-deception /opt/deception /run/v3il /srv /var/lib/v3il/telemetry /var/www; \
    chown -R 10001:10001 /home/v3il-deception /opt/deception /srv /var/www; \
    chown 0:10001 /run/v3il; \
    chmod 0750 /run/v3il; \
    chmod 0700 /var/lib/v3il/telemetry; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/log/apt/* /tmp/* /var/tmp/*

COPY --from=proxy-builder --chmod=755 /sandbox-proxy /usr/local/bin/sandbox-proxy
COPY --chmod=755 v3il-telemetry /usr/local/bin/v3il-telemetry
COPY --chmod=755 zeek/adapter.py /opt/v3il-zeek/adapter.py
COPY --chmod=755 zeek/sensor-entrypoint.sh /usr/local/bin/v3il-zeek-sensor
COPY --chmod=755 zeek/runtime-entrypoint.sh /usr/local/bin/v3il-zeek-runtime
COPY zeek/local.zeek /opt/v3il-zeek/local.zeek
COPY .agents/skills/ /root/.agents/skills/
COPY --chmod=755 entrypoint.sh /entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
