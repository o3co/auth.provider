# The base image is pinned by digest, not just by tag: `node:24-alpine` is a
# moving pointer, so the same source produced a different image on every
# rebuild (#289). The digest is the multi-arch index, so amd64 and arm64 both
# resolve from it. Dependabot's `docker` ecosystem keeps the pair in step —
# bump the tag and the digest together, never the tag alone.
FROM node:26-alpine@sha256:2d984a15c9b54fd0aeb608b8e0d0d83529eb34d2966db27a1fb4f1edc3d298a3 AS node-base

ENV HOME=/home/node

# corepack is pinned too. `npm install -g corepack --force` resolved whatever
# was latest at build time, which is a mutable dependency of every build. The
# pnpm version itself comes from the `packageManager` field in package.json,
# which corepack reads.
RUN apk add --no-cache tini \
 && npm install -g corepack@0.35.0 --force \
 && corepack enable

WORKDIR /home/node

#############################################
FROM node-base AS deps

# pnpm-lock.yaml is a required build input: `create-auth-provider` generates
# it at scaffold time and the project commits it. Without it this COPY fails,
# which is the intended outcome — a build that silently re-resolves every
# dependency range is the thing this file stopped doing (#289).
#
# pnpm-workspace.yaml is required for the same reason and was missing (#407):
# the scaffolder generates it to carry bcrypt's `onlyBuiltDependencies`
# allowlist, and pnpm >= 10.29 reads that setting ONLY from this file, in
# single-package projects too (#360). Installing without it runs
# allowlist-less, so pnpm silently skips bcrypt's build hook — which costs
# nothing while an alpine prebuild exists, and re-creates #360 the day one
# is missing and the native addon has to compile.
COPY --chown=node:node package.json pnpm-lock.yaml pnpm-workspace.yaml ./

USER node

# --frozen-lockfile: install exactly what the lockfile pins, and fail if
# package.json and the lockfile disagree, rather than quietly rewriting it.
RUN pnpm install --frozen-lockfile

#############################################
FROM deps AS builder

# USER node inherited from deps stage; repeated here to make the builder
# hardening invariant obvious in Dockerfile reviews.
USER node

COPY --chown=node:node tsconfig.json ./
COPY --chown=node:node config/ ./config/
COPY --chown=node:node src/ ./src/

RUN pnpm run build

#############################################
# Dependencies are resolved once, in `deps`. This stage drops the dev half of
# that same tree instead of running a second `pnpm install --prod` in the
# runtime stage: a second install is a second resolution, and therefore a
# second chance for the runtime image to hold something the build never saw.
FROM deps AS prod-deps

USER node

RUN pnpm prune --prod

#############################################
FROM node-base AS runtime

ENV NODE_ENV=production

COPY --from=deps /home/node/package.json /home/node/pnpm-lock.yaml ./
COPY --from=prod-deps /home/node/node_modules/ ./node_modules/
COPY --from=builder /home/node/dist/ ./dist/
COPY --from=builder /home/node/config/ ./config/

USER node

ENV HTTP_PORT=3000
EXPOSE ${HTTP_PORT}

# Probes /_healthcheck (liveness), NOT /readyz. Docker has exactly one health
# signal, and on Swarm / ECS / autoheal-style supervisors an unhealthy
# container is stopped and replaced. Pointing it at /readyz would mean a 90s
# Redis failover marks every replica unhealthy and gets them all rescheduled —
# which reconnects nothing and adds cold starts to the incident. Losing Redis
# is a reason to stop routing to a replica, not to kill it.
#
# /readyz is the load-balancer / Kubernetes readinessProbe target; see the
# "Health endpoints" section of README.md. A compose file that genuinely wants
# `depends_on: condition: service_healthy` to mean "ready" can override this
# per-service, which keeps the restart-driving signal out of it.
#
# Use the shell form so ${HTTP_PORT} expands at probe time. The HOCON
# config reads `${?HTTP_PORT}` for `http.port`, so app.listen() and the
# probe stay in sync regardless of the operator's port choice.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null "http://localhost:${HTTP_PORT}/_healthcheck" || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["node", "dist/app.mjs"]

#############################################
FROM builder AS test

COPY --chown=node:node vitest.config.mts ./
COPY --chown=node:node tests/ ./tests/

CMD ["pnpm", "run", "test", "--", "--passWithNoTests"]

#############################################
FROM builder AS develop

CMD ["pnpm", "run", "debug"]
