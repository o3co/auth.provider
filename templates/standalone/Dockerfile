FROM node:25-alpine AS node-base

RUN apk add --no-cache tini \
 && npm install -g corepack --force \
 && corepack enable

WORKDIR /home/node

#############################################
FROM node-base AS deps

COPY package.json ./

RUN pnpm install

#############################################
FROM deps AS builder

COPY tsconfig.json ./
COPY config/ ./config/
COPY src/ ./src/

RUN pnpm run build

#############################################
FROM node-base AS runtime

ENV NODE_ENV=production

COPY --from=deps /home/node/package.json /home/node/pnpm-lock.yaml ./

RUN pnpm install --frozen-lockfile --prod

COPY --from=builder /home/node/dist/ ./dist/
COPY --from=builder /home/node/config/ ./config/

USER node

ENTRYPOINT ["tini", "--"]
CMD ["node", "dist/app.mjs"]

#############################################
FROM builder AS test

COPY vitest.config.mts ./
COPY tests/ ./tests/

CMD ["pnpm", "run", "test", "--", "--passWithNoTests"]

#############################################
FROM builder AS develop

USER node

CMD ["pnpm", "run", "debug"]
