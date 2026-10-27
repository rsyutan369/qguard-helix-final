# syntax=docker/dockerfile:1.7
#
# QGuard Helix API — production image (Express API + scanner engines).
#
# The SPA is NOT in this image: it is built and served by Vercel. This image runs
# src/api-server/standalone.ts exactly as `npm start` does today (TypeScript
# executed by tsx), with the process under tini so SIGTERM reaches Node and the
# graceful drain in standalone.ts runs on every rolling update.
#
# Build (from the repo root):
#   docker build -t qguard-api:local .
# Run locally against your .env (never bake .env into the image):
#   docker run --rm -p 8080:8080 --env-file .env -e APP_ORIGIN=http://localhost:3000 \
#     -e QGUARD_CONTROL_PLANE_URL=https://api.qguardhelix.com qguard-api:local
#
# Node 24 is required, not just preferred: it links OpenSSL 3.5, which the TLS
# engine needs to offer the hybrid ML-KEM key-exchange groups (X25519MLKEM768
# etc.). On an older base the scanner silently reports hybrid PQC as "not
# testable" (src/lib/scanner/public-scan/engines/tls-engine.ts).

ARG NODE_VERSION=24

# ---------------------------------------------------------------------------
# deps — full, lockfile-exact install (dev tooling is needed to build the agent)
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION}-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund

# ---------------------------------------------------------------------------
# build — digest-verified agent runtime, then drop dev dependencies
# ---------------------------------------------------------------------------
FROM deps AS build
COPY tsconfig.json ./
COPY src ./src
COPY tools ./tools
COPY supabase/functions/billing ./supabase/functions/billing
# tools/qguard-agent/dist is gitignored and served by /api/v1/agent-installer;
# every replica must carry the same bytes (and therefore the same SHA-256).
RUN npm run agent:release \
 && test -f tools/qguard-agent/dist/qguard-agent.cjs \
 && test -f tools/qguard-agent/dist/manifest.json
RUN npm prune --omit=dev --no-audit --no-fund

# ---------------------------------------------------------------------------
# public-api — the public website's backend ONLY: the free Web assessment and
# the Request Demo email (src/api-server/public-api.ts). No agent runtime, no
# installer, no Supabase or payment credentials needed. Build it explicitly:
#   docker build --target public-api -t qguard-public-api .
#   docker run --rm -p 8080:8080 -e ALLOWED_ORIGINS=https://qguardhelix.com \
#     -e TRUSTED_CLIENT_IP_HEADER=cf-connecting-ip qguard-public-api
# It sits BEFORE `runtime` so a plain `docker build .` still produces the full
# platform image (the last stage is the default target).
# ---------------------------------------------------------------------------
FROM deps AS public-build
COPY tsconfig.json ./
COPY src ./src
RUN npm prune --omit=dev --no-audit --no-fund

FROM node:${NODE_VERSION}-bookworm-slim AS public-api

RUN apt-get update \
 && apt-get install -y --no-install-recommends tini ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production \
    QGUARD_ENVIRONMENT=production \
    PORT=8080 \
    NPM_CONFIG_UPDATE_NOTIFIER=false

WORKDIR /app
COPY --from=public-build --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json package-lock.json tsconfig.json ./
COPY --from=public-build --chown=node:node /app/src ./src

ARG APP_VERSION=""
ARG GIT_SHA=""
ENV APP_VERSION=${APP_VERSION} \
    GIT_SHA=${GIT_SHA}

LABEL org.opencontainers.image.title="qguard-public-api" \
      org.opencontainers.image.description="QGuard Helix public assessment and demo request API" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.version="${APP_VERSION}"

USER node
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/api/v1/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "--import", "tsx", "src/api-server/public-standalone.ts"]

# ---------------------------------------------------------------------------
# runtime — minimal, non-root
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION}-bookworm-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends tini ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production \
    QGUARD_ENVIRONMENT=production \
    PORT=8080 \
    SERVE_STATIC=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false

# WORKDIR must be the repository-root layout: tsx resolves the "@/*" path alias
# from ./tsconfig.json, and the agent runtime is located via process.cwd().
WORKDIR /app

COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json package-lock.json tsconfig.json ./
COPY --from=build --chown=node:node /app/src ./src
COPY --from=build --chown=node:node /app/supabase/functions/billing ./supabase/functions/billing
COPY --from=build --chown=node:node /app/tools/qguard-agent/dist ./tools/qguard-agent/dist
# Served ONLY through the entitlement-checked /api/v1/downloads route.
COPY --chown=node:node public/downloads/QGuard-Messaging-Setup.exe ./public/downloads/QGuard-Messaging-Setup.exe

ARG APP_VERSION=""
ARG GIT_SHA=""
ENV APP_VERSION=${APP_VERSION} \
    GIT_SHA=${GIT_SHA}

LABEL org.opencontainers.image.title="qguard-api" \
      org.opencontainers.image.description="QGuard Helix API and scanner engines" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.version="${APP_VERSION}"

USER node
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/api/v1/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "--import", "tsx", "src/api-server/standalone.ts"]
