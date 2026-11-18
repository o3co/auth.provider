/** A deployment's project from a list of modules: configuration from their fragments, the image and a guide. */

import { entriesOf, mainSource } from "@mod/app-entries";
import { askedOf } from "./asked/asked.ts";
import {
	applicationConf,
	envExample,
	envName,
	localConfExample,
	type Setting,
	sampleLines,
	settingsOf,
	type Written,
	writtenOf,
} from "./fragments/contract.ts";
import { dockerfile, dockerIgnored } from "./image/image.ts";
import { besideRelease } from "./outside/contract.ts";
import type { Card, Packages, Release } from "./packages.ts";
import {
	filled,
	manifestOf,
	vacant,
	withKernel,
	workspaceFile,
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
	const declaring = packages.appEntries?.(names) ?? [];
	const entries = await entriesOf(modules, packages.importOf, run, keys, declaring);
	const dependencies = packages.dependencies(names);
	// The one place a caller without packages outside the release is read as having none.
	const release = packages.release();
	const beside = besideRelease(packages.outside?.(names), {
		dependencies,
		version: release.version,
		zod,
		...(release.integrity ? { integrity: release.integrity } : {}),
		...(release.bundles ? { bundles: release.bundles } : {}),
	});
	await writeProject(target, {
		"package.json": manifestOf(
			dependencies,
			beside.scripts ? { start: run(paths.main), ...entries.scripts } : undefined,
		),
		"pnpm-workspace.yaml": workspaceFile(beside.settings),
		...beside.files,
		[paths.main]: await mainSource(modules, packages.importOf, keys),
		...entries.files,
		[paths.application]: applicationConf(fragments),
		[paths.localExample]: localConfExample(fragments, sampleLines(packages.samples?.(names) ?? [])),
		".env.example": envExample(settings),
		"AGENTS.md": agentsIndex(packages.cards(names), packages.release()) + beside.index,
		Dockerfile: dockerfile(http, beside.image, { ...paths, port: httpPort }),
		".dockerignore": lines(dockerIgnored),
		".gitignore": lines(gitIgnored),
		"README.md":
			(await filled(readme.template, {
				...paths,
				...guideLists(settings, writtenOf(fragments)),
				cards: cardLines(packages.cards(names)),
				askedOfDeployment: deploymentLines(packages.cards(names)),
				...guideAsked(askedOf(names, packages.asks?.(names) ?? [])),
				firstLogin: http.serves ? firstLoginLine(packages.release()) : "",
				port: String(httpPort),
				hostEnv: envName("http.host"),
				portEnv: envName("http.port"),
				...httpLines(http),
				comesWith: beside.comesWith,
				install: beside.install,
				start: beside.scripts ? "pnpm start" : run(paths.main),
				...readme.fill,
			})) + beside.guide,
	});
}

/** The guide's marks for what the modules ask: the lines, the lines under their heading, and the values decided. */
const guideAsked = ({ chosen, decides }: { chosen: string[]; decides: string[] }) => ({
	asked: chosen.join("\n"),
	askedSection:
		chosen.length === 0
			? ""
			: ["## Settings the composed modules ask for", "", ...chosen, "", ""].join("\n"),
	decides: decides.join("\n"),
});

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
