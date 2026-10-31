/** A deployment's project from a list of modules: configuration from their fragments, the image and a guide. */

import { entriesOf } from "./entries/contract.ts";
import {
	applicationConf,
	envExample,
	envName,
	localConfExample,
	type Setting,
	settingsOf,
	type Written,
	writtenOf,
} from "./fragments/contract.ts";
import { type Beside, besideRelease } from "./outside/contract.ts";
import type { Card, Packages, Release } from "./packages.ts";
import {
	filled,
	mainSource,
	manifestOf,
	vacant,
	withKernel,
	writeProject,
	zod,
} from "./project.ts";

/** The files the generated project names in its guide, each written where the guide says. */
const paths = {
	application: "config/application.conf",
	local: "config/local.conf",
	localExample: "config/local.conf.example",
	main: "src/main.ts",
};

/**
 * One minor of Node 24: each build takes its patches and never a new minor. A minor gets no fixes once a
 * newer one is out, so the operator moves to the latest 24.x minor at each Node security release.
 */
const nodeImage = "node:24.22-alpine";
/** The corepack that gives the image the manifest's pnpm; pinned, so a build never takes the latest. */
const corepack = "0.36.0";
/** http's default port: the image changes only the interface it listens on. */
const httpPort = 8080;
/** The module that listens: only an app composing it is given a port, in the image and the guide. */
const httpPackage = "@mod/http";
/** The module that answers `/_healthcheck` and `/readyz`: only an app composing it is checked for liveness. */
const opsPackage = "@mod/http-ops";

/** Secrets of any file name stay out of git: env files but their example, the local layer, keys. */
const gitIgnored = [
	"node_modules/",
	"config/local*.conf",
	".env",
	".env.*",
	"!.env.example",
	"*.pem",
	"*.key",
];
/** The image's build context leaves out git, every env file, the local layer, keys and the host's install. */
const dockerIgnored = [
	".git",
	".env",
	".env.*",
	"config/local*.conf",
	"*.pem",
	"*.key",
	"node_modules/",
];
const lines = (entries: readonly string[]) => `${entries.join("\n")}\n`;

/** A deployment's guide: a file of `templates/`, and the values for its marks beside those the output fills. */
export interface Readme {
	readonly template: string;
	readonly fill: Readonly<Record<string, string>>;
}

/** Writes the project assembling `modules` from `packages` into an empty target, its guide from `readme`. */
export async function writeDeployment(
	target: string,
	modules: readonly string[],
	packages: Packages,
	readme: Readme,
): Promise<void> {
	await vacant(target);
	const names = withKernel(modules);
	const fragments = await packages.fragments(names);
	const settings = settingsOf(fragments);
	// From what writes application.conf, so the refusals name only the variables it reads.
	const keys = {
		read: Object.fromEntries(settings.map((s) => [s.key, s.env])),
		severalLines: writtenOf(fragments)
			.filter((w) => w.severalLines)
			.map((w) => w.key),
		local: paths.local,
	};
	const http = { serves: names.includes(httpPackage), live: names.includes(opsPackage) };
	const run = (file: string) => `node --env-file-if-exists=.env ${file}`;
	const entries = await entriesOf(modules, packages.importOf, run, keys);
	const dependencies = packages.dependencies(names);
	// The one place a caller without packages outside the release is read as having none.
	const release = packages.release();
	const beside = besideRelease(packages.outside?.(names), {
		dependencies,
		version: release.version,
		zod,
		...(release.integrity ? { integrity: release.integrity } : {}),
	});
	await writeProject(target, {
		"package.json": manifestOf("node --env-file-if-exists=.env src/main.ts", dependencies, {
			...entries.scripts,
			...beside.scripts,
		}),
		...beside.files,
		[paths.main]: await mainSource(modules, packages.importOf, keys),
		...entries.files,
		[paths.application]: applicationConf(fragments),
		[paths.localExample]: localConfExample(fragments),
		".env.example": envExample(settings),
		"AGENTS.md": agentsIndex(packages.cards(names), packages.release()) + beside.index,
		Dockerfile: dockerfile(http, beside.image),
		".dockerignore": lines(dockerIgnored),
		".gitignore": lines(gitIgnored),
		"README.md":
			(await filled(readme.template, {
				...paths,
				...guideLists(settings, writtenOf(fragments)),
				cards: cardLines(packages.cards(names)),
				askedOfDeployment: deploymentLines(packages.cards(names)),
				firstLogin: http.serves ? firstLoginLine(packages.release()) : "",
				port: String(httpPort),
				hostEnv: envName("http.host"),
				portEnv: envName("http.port"),
				...httpLines(http),
				...readme.fill,
			})) + beside.guide,
	});
}

/** The install stage's install: with packages outside the release, what it checks against copied, and checked after. */
const installed = (beside: Beside["image"]) =>
	beside === undefined
		? "RUN pnpm install --frozen-lockfile --prod"
		: `# The lockfile is held to what was recorded of the packages outside the release.
${beside.copy.map((file) => `COPY ${file} ./${file}`).join("\n")}
RUN pnpm install --frozen-lockfile --prod && ${beside.after}`;

/** Each composed module's card, where the app installs it. */
const cardLines = (cards: readonly Card[]) =>
	cards.map((c) => `- \`${c.name}\`: \`${c.card}\``).join("\n");

/** The Deployment section of each composed module whose card has one; nothing when none has. */
function deploymentLines(cards: readonly Card[]): string {
	const asking = cards.flatMap((c) =>
		c.deployment ? [`- \`${c.name}\`: \`${c.deployment}\``] : [],
	);
	if (asking.length === 0) return "";
	return [
		"",
		"## What the composed modules ask of the deployment",
		"",
		"Each of these modules talks to a server the deployment provides; the Deployment section of its card says what that server must offer.",
		"",
		...asking,
		"",
	].join("\n");
}

/** The release's walk to a first login, where its repository is stated; nothing otherwise. */
function firstLoginLine(release: Release): string {
	const at = atRelease(release, "docs/recipe-first-login.md");
	return at ? `A first login, step by step: ${at}\n\n` : "";
}

/** Where a document of the release lies, at its version's tag; none without a repository. */
const atRelease = (release: Release, path: string) =>
	release.repository ? `${release.repository}/blob/v${release.version}/${path}` : undefined;

/**
 * The index for an agent working on the app: where each composed module's card and section
 * defaults lie as installed, which are the truth; it states no fact of its own.
 */
function agentsIndex(cards: readonly Card[], release: Release): string {
	const whole = ["docs/configuration.md", "docs/routes.md"].flatMap((path) => {
		const at = atRelease(release, path);
		return at ? [`- \`${path}\` of the release: ${at}`] : [];
	});
	return `${[
		"# Index for agents",
		"",
		"Each composed module's card is the truth about it; this index only points where the cards lie, as installed, and states nothing of its own.",
		"A module's configuration keys, their defaults and descriptions, are in its `reference.conf`; its routes, client metadata sections and what it asks of a deployment are in its card.",
		"",
		"| Module | Card | Section defaults |",
		"|---|---|---|",
		...cards.map(
			(c) => `| \`${c.name}\` | \`${c.card}\` | ${c.references ? `\`${c.references}\`` : ""} |`,
		),
		...(whole.length > 0
			? [
					"",
					`Every module and route of the release (${release.version}), beyond this app:`,
					"",
					...whole,
				]
			: []),
	].join("\n")}\n`;
}

/** The guide's lists: the keys read from env as table rows, and those written in the local layer. */
const guideLists = (settings: readonly Setting[], written: readonly Written[]) => ({
	settings: settings
		.map((s) => {
			// On one line of its table: a placeholder of several lines as JSON writes it.
			const several = s.placeholder.includes("\n");
			const shown = several ? JSON.stringify(s.placeholder) : s.placeholder;
			// Docker reads one line per variable from an env file, so a value of several lines is never in .env.
			const env = several ? `\`${s.env}\` (process environment only, never .env)` : `\`${s.env}\``;
			return `| \`${s.key}\` | ${env} | \`${shown}\` |`;
		})
		.join("\n"),
	written: written
		.map(
			(w) =>
				`- \`${w.key}\`${w.spansSections ? " (spans sections: written by the operator)" : ""}${w.severalLines ? " (several lines: written here or set in the process environment, never in .env)" : ""}`,
		)
		.join("\n"),
});

/** The guide's lines about http, for an app that listens; and the health check's, for one that answers it. */
function httpLines(http: { readonly serves: boolean; readonly live: boolean }) {
	const config = `-e APP_CONFIG=${paths.local},${paths.application} -v "$PWD/${paths.local}:/app/${paths.local}:ro"`;
	const host = envName("http.host");
	const port = envName("http.port");
	return {
		tryHttp: http.serves
			? `To try it on this machine over plain http, set \`http.public-origin\` and \`issuer.url\` to \`http://localhost:${httpPort}\`, \`http.insecure-origin\` to \`true\`, and \`kernel.environment\` to \`development\`: an http public origin boots only with both, and its cookies cannot be made secure. A deployment keeps an https origin, leaves \`http.insecure-origin\` \`false\` and \`kernel.environment\` \`production\`.\n`
			: "",
		dockerRun: http.serves
			? `docker run --env-file .env -e ${host}=0.0.0.0 -e ${port}=${httpPort} ${config} -p ${httpPort}:${httpPort} auth-provider`
			: `docker run --env-file .env ${config} auth-provider`,
		listening: http.serves
			? `An \`-e\` after \`--env-file\` wins over it: the container listens on every interface at ${httpPort}, where \`-p\` reaches it, whatever \`.env\` names for a run on the host.\n\n`
			: "",
		healthCheck: http.live
			? "Its health check asks `/_healthcheck`, which answers while the process runs; `/readyz` answers readiness, for a load balancer.\n"
			: "",
	};
}

function dockerfile(
	http: { readonly serves: boolean; readonly live: boolean },
	beside: Beside["image"],
): string {
	const port = envName("http.port");
	const listening = http.serves
		? `# Listens on every interface inside the container; the port is http's, which the health check follows.
ENV ${envName("http.host")}=0.0.0.0
ENV ${port}=${httpPort}
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
# An init as process 1 passes signals on and reaps what node leaves behind; the corepack and the yarn
# Node's image bundles go, as the app runs neither.
RUN apk add --no-cache tini && npm uninstall --global corepack && rm -rf /opt/yarn-v* /usr/local/bin/yarn /usr/local/bin/yarnpkg
WORKDIR /app
ENV NODE_ENV=production
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY ${paths.application} ./${paths.application}
${listening}USER node
${exposed}${checked}ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "${paths.main}"]
`;
}
