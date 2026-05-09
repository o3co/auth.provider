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

# Use the shell form so ${HTTP_PORT} expands at probe time. The HOCON
# config reads `${?HTTP_PORT}` for `http.port`, so app.listen() and the
# healthcheck stay in sync regardless of the operator's port choice.
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
