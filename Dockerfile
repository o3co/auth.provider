#############################################
FROM node:25-alpine AS base 

RUN npm install -g corepack --force

ENV HOME=/home/node
ENV NODE_ENV=production

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

COPY --from=pre /home/node/node_modules ./node_modules/
COPY --from=pre /home/node/dist/ ./dist/
COPY --from=pre /home/node/config/ ./config/

CMD ["pnpm", "run", "start"]

##############################################
FROM builder AS develop

CMD ["pnpm", "run", "debug"]

