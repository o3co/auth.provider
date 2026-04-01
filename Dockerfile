#############################################
FROM node:25-alpine AS base

RUN npm install -g corepack --force

ENV HOME=/home/node
ENV NODE_ENV=production

WORKDIR ${HOME}

ADD package.json pnpm-workspace.yaml pnpm-lock.yaml .npmrc* ./
ADD packages/core/package.json ./packages/core/
ADD templates/standalone/package.json ./templates/standalone/

RUN corepack enable

#############################################
FROM base AS builder

RUN pnpm install

COPY tsconfig.base.json ./
COPY packages/core/ ./packages/core/
COPY templates/standalone/src/ ./templates/standalone/src/
COPY templates/standalone/tsconfig.json ./templates/standalone/
COPY templates/standalone/config/ ./templates/standalone/config/

RUN pnpm -r run build

#############################################
FROM builder AS pre

RUN pnpm prune --prod

#############################################
FROM base AS runtime

COPY --from=pre /home/node/node_modules ./node_modules/
COPY --from=pre /home/node/packages/core/dist/ ./packages/core/dist/
COPY --from=pre /home/node/packages/core/node_modules/ ./packages/core/node_modules/
COPY --from=pre /home/node/packages/core/package.json ./packages/core/
COPY --from=pre /home/node/templates/standalone/dist/ ./templates/standalone/dist/
COPY --from=pre /home/node/templates/standalone/node_modules/ ./templates/standalone/node_modules/
COPY --from=pre /home/node/templates/standalone/package.json ./templates/standalone/
COPY --from=pre /home/node/templates/standalone/config/ ./templates/standalone/config/
RUN ln -s /home/node/templates/standalone/dist /home/node/templates/standalone/src

WORKDIR /home/node/templates/standalone

CMD ["node", "dist/app.mjs"]

##############################################
FROM builder AS develop

WORKDIR /home/node/templates/standalone

CMD ["pnpm", "run", "debug"]
