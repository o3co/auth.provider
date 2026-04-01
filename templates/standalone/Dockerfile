#############################################
FROM node:25-alpine AS base

RUN npm install -g corepack --force

ENV HOME=/home/node

WORKDIR ${HOME}

ADD package.json ./

RUN corepack enable

#############################################
FROM base AS builder

RUN pnpm install

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
RUN ln -s /home/node/dist /home/node/src

CMD ["node", "dist/app.mjs"]

##############################################
FROM builder AS develop

CMD ["pnpm", "run", "debug"]
