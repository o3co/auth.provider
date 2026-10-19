/** A deployment's project from a list of modules: configuration from their fragments, the image and a guide. */
import {
	applicationConf,
	envExample,
	envName,
	localConfExample,
	type Setting,
	settingsOf,
	type Written,
	writtenOf,
} from "./fragments.ts";
import { packagesFor } from "./packages.ts";
import {
	filled,
	mainSource,
	manifestOf,
	resealSource,
	sealPackage,
	vacant,
	withKernel,
	writeProject,
} from "./project.ts";

/** The files the generated project names in its guide, each written where the guide says. */
const paths = {
	application: "config/application.conf",
	local: "config/local.conf",
	localExample: "config/local.conf.example",
	main: "src/main.ts",
};

/** Node 24 by version and by digest (the multi-platform index); update both together. */
const nodeImage =
	"node:24.21.0-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1";
/** The corepack that gives the image the manifest's pnpm; pinned, so a build never takes the latest. */
const corepack = "0.36.0";
/** http's default port: the image changes only the interface it listens on. */
const httpPort = 8080;

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

/** Writes the project assembling `modules` into an empty target, its guide from `readme`'s template and values. */
export async function writeDeployment(
	plan: { readonly target: string; readonly workspace?: string },
	modules: readonly string[],
	readme: { readonly template: string; readonly fill: Readonly<Record<string, string>> },
): Promise<void> {
	await vacant(plan.target);
	const names = withKernel(modules);
	const packages = packagesFor(plan);
	const fragments = await packages.fragments(names);
	const settings = settingsOf(fragments);
	const seals = names.includes(sealPackage);
	await writeProject(plan.target, {
		"package.json": manifestOf(
			"node --env-file-if-exists=.env src/main.ts",
			packages.dependencies(names),
			seals ? "node --env-file-if-exists=.env src/reseal.ts" : undefined,
		),
		[paths.main]: await mainSource(modules, packages.importOf),
		...(seals ? { "src/reseal.ts": await resealSource(modules, packages.importOf) } : {}),
		[paths.application]: applicationConf(fragments),
		[paths.localExample]: localConfExample(fragments),
		".env.example": envExample(settings),
		Dockerfile: dockerfile(),
		".dockerignore": lines(dockerIgnored),
		".gitignore": lines(gitIgnored),
		"README.md": await filled(readme.template, {
			...paths,
			...guideLists(settings, writtenOf(fragments)),
			port: String(httpPort),
			hostEnv: envName("http.host"),
			portEnv: envName("http.port"),
			...readme.fill,
		}),
	});
}

/** The guide's lists: the keys read from env as table rows, and those written in the local layer. */
const guideLists = (settings: readonly Setting[], written: readonly Written[]) => ({
	settings: settings
		.map((s) => {
			// On one line of its table: a placeholder of several lines as JSON writes it.
			const shown = s.placeholder.includes("\n") ? JSON.stringify(s.placeholder) : s.placeholder;
			return `| \`${s.key}\` | \`${s.env}\` | \`${shown}\` |`;
		})
		.join("\n"),
	written: written
		.map(
			(w) =>
				`- \`${w.key}\`${w.spansSections ? " (spans sections: written by the operator)" : ""}${w.severalLines ? " (several lines: written here or set in the process environment, never in .env)" : ""}`,
		)
		.join("\n"),
});

function dockerfile(): string {
	return `# syntax=docker/dockerfile:1
# Node 24 pinned by version and digest, corepack pinned too; pnpm is the manifest's packageManager.
FROM ${nodeImage} AS base
# An init as process 1 passes signals on and reaps what node leaves behind.
RUN apk add --no-cache tini && npm install --global corepack@${corepack} && corepack enable
WORKDIR /app

FROM base AS deps
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --prod

FROM base AS runtime
ENV NODE_ENV=production
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY ${paths.application} ./${paths.application}
# Listens on every interface inside the container; the port is http's, which the health check follows.
ENV ${envName("http.host")}=0.0.0.0
ENV ${envName("http.port")}=${httpPort}
USER node
EXPOSE \${${envName("http.port")}}
# Liveness, not readiness: the container is restarted only when the process stops answering.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["node", "-e", "fetch('http://127.0.0.1:' + process.env.${envName("http.port")} + '/_healthcheck').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "${paths.main}"]
`;
}
