FROM node:25-alpine AS base

RUN apk add --no-cache tini \
 && npm install -g corepack --force \
 && corepack enable

WORKDIR /home/node

COPY package.json ./

RUN pnpm install

#############################################
FROM base AS builder

COPY tsconfig.json ./
COPY config/ ./config/
COPY src/ ./src/

RUN pnpm run build

#############################################
FROM builder AS pre

RUN pnpm prune --prod

#############################################
FROM base AS runtime

ENV NODE_ENV=production

COPY --from=pre /home/node/node_modules ./node_modules/
COPY --from=pre /home/node/dist/ ./dist/
COPY --from=pre /home/node/config/ ./config/

USER node

ENTRYPOINT ["tini", "--"]
CMD ["node", "dist/app.mjs"]

#############################################
FROM builder AS test

COPY vitest.config.mts ./
COPY tests/ ./tests/

RUN pnpm run test

#############################################
FROM builder AS develop

CMD ["pnpm", "run", "debug"]
