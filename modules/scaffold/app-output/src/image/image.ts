/** The app's image: its Dockerfile and what its build context leaves out. */

import { envName } from "../fragments/contract.ts";
import type { Beside } from "../outside/contract.ts";

/**
 * One minor of Node 24: each build takes its patches and never a new minor. A minor gets no fixes once a
 * newer one is out, so the operator moves to the latest 24.x minor at each Node security release.
 */
const nodeImage = "node:24.22-alpine";
/** The corepack that gives the image the manifest's pnpm; pinned, so a build never takes the latest. */
const corepack = "0.36.0";
/** The image's build context leaves out git, every env file, the local layer, keys and the host's install. */
export const dockerIgnored = [
	".git",
	".env",
	".env.*",
	"config/local*.conf",
	"*.pem",
	"*.key",
	"node_modules/",
];

/**
 * The install stage's install: with packages outside the release, the lockfile held to what was
 * recorded before anything of theirs is there, and the install, running none of it, the one command
 * that reads a registry's credentials.
 */
const installed = (beside: Beside["image"]) =>
	beside === undefined
		? "RUN pnpm install --frozen-lockfile --prod"
		: `# The lockfile is held to what was recorded of the packages outside the release, before any is installed.
${beside.copy.map((file) => `COPY ${file} ./${file}`).join("\n")}
RUN ${beside.check}
# corepack fetches pnpm here, and pnpm its native binary, so neither download sees a credential below.
RUN pnpm --version
${beside.mount ? "# A registry's credentials come as a build secret, and stay in no layer.\n" : ""}RUN ${beside.mount ? `${beside.mount} ` : ""}pnpm install --frozen-lockfile --prod --ignore-scripts`;

/**
 * The app's Dockerfile: `http` says whether the app listens and answers its health check, `beside`
 * how the install stage installs packages outside the release, and `at` the port it listens on and
 * where the app's files lie.
 */
export function dockerfile(
	http: { readonly serves: boolean; readonly live: boolean },
	beside: Beside["image"],
	at: { readonly port: number; readonly application: string; readonly main: string },
): string {
	const port = envName("http.port");
	const listening = http.serves
		? `# Listens on every interface inside the container; the port is http's, which the health check follows.
ENV ${envName("http.host")}=0.0.0.0
ENV ${port}=${at.port}
`
		: "";
	const exposed = http.serves ? `EXPOSE \${${port}}\n` : "";
	const checked = http.live
		? `# Liveness, not readiness: the container is restarted only when the process stops answering.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["node", "-e", "fetch('http://127.0.0.1:' + process.env.${port} + '/_healthcheck').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
`
		: "";
	return `# syntax=docker/dockerfile:1
# One Node 24 minor, which gets no fixes once a newer one is out: at each Node security release, move both FROM lines to the latest 24.x minor. corepack pinned; pnpm is the manifest's packageManager.
FROM ${nodeImage} AS base
RUN npm install --global corepack@${corepack} && corepack enable
WORKDIR /app

FROM base AS deps
COPY package.json pnpm-lock.yaml pnpm-workspace.yam[l] ./
${installed(beside)}

# The image the app runs in starts from Node's own: the tools that install stay in the stages before.
FROM ${nodeImage} AS runtime
# Node's image takes Alpine's fixes later than Alpine publishes them, so this stage takes Alpine's current
# packages; build with --pull --no-cache-filter=runtime, as a cached layer keeps an earlier build's.
RUN apk upgrade --no-cache
# An init as process 1 passes signals on and reaps what node leaves behind.
RUN apk add --no-cache tini
# The app runs node alone, so no package manager but apk stays: the npm, npx, corepack and yarn Node's
# image bundles go, with the packages they bundle, which the app never loads.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-v* \\
      /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg
WORKDIR /app
ENV NODE_ENV=production
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY ${at.application} ./${at.application}
${listening}USER node
${exposed}${checked}ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "${at.main}"]
`;
}
