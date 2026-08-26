FROM node:24-alpine AS node-base

ENV HOME=/home/node

RUN apk add --no-cache tini \
 && npm install -g corepack --force \
 && corepack enable

WORKDIR /home/node

#############################################
FROM node-base AS deps

COPY package.json ./

USER node

RUN pnpm install

#############################################
FROM deps AS builder

# USER node inherited from deps stage; repeated here to make the builder
# hardening invariant obvious in Dockerfile reviews.
USER node

COPY tsconfig.json ./
COPY config/ ./config/
COPY src/ ./src/

RUN pnpm run build

#############################################
FROM node-base AS runtime

ENV NODE_ENV=production

COPY --from=deps /home/node/package.json /home/node/pnpm-lock.yaml ./

USER node

RUN pnpm install --prod \
 && pnpm store prune

COPY --from=builder /home/node/dist/ ./dist/
COPY --from=builder /home/node/config/ ./config/

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

COPY vitest.config.mts ./
COPY tests/ ./tests/

CMD ["pnpm", "run", "test", "--", "--passWithNoTests"]

#############################################
FROM builder AS develop

CMD ["pnpm", "run", "debug"]
