/**
 * An app beside a package outside the release, run as its guide says on the pnpm its manifest pins,
 * from a registry of the test's own, with a command named `node` linked at its `node_modules/.bin`.
 */
import { execFile, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	writeFileSync,
} from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { delimiter, isAbsolute, join } from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parse } from "yaml";
import {
	appZod,
	fragmentsOf,
	type OutsideRecord,
	type Packages,
	writeDeployment,
} from "../src/contract.ts";

const root = join(import.meta.dirname, "..", "..", "..", "..");

const releaseVersion = "1.2.3";
const peers = { zod: "^4.6.0" };
const release = "@o3co/auth-provider-oauth";
const shadow = "@x/shadow";
const peered = "@x/peered";

type Manifest = {
	readonly name: string;
	readonly version: string;
	readonly bin?: Readonly<Record<string, string>>;
	readonly peerDependencies?: Readonly<Record<string, string>>;
};
const published: readonly Manifest[] = [
	{ name: release, version: releaseVersion, peerDependencies: peers },
	{
		name: shadow,
		version: "1.0.0",
		bin: { node: "./run.sh", reseal: "./run.sh" },
		peerDependencies: peers,
	},
	{ name: peered, version: "1.0.0", peerDependencies: { ...peers, [shadow]: "^1.0.0" } },
];

interface Served {
	readonly manifest: Manifest;
	readonly tarball: Buffer;
	readonly integrity: string;
}
const pathOf = ({ name, version }: Manifest) =>
	`/${name}/-/${name.slice(name.indexOf("/") + 1)}-${version}.tgz`;

function packed(manifest: Manifest): Served {
	const at = mkdtempSync(join(tmpdir(), "outside-start-package-"));
	mkdirSync(join(at, "package"));
	writeFileSync(join(at, "package", "package.json"), JSON.stringify(manifest));
	if (manifest.bin) {
		const file = join(at, "package", "run.sh");
		// Says so, and leaves a mark where only the test's environment names one.
		writeFileSync(file, '#!/bin/sh\necho SHADOW\n[ -z "$SHADOW_MARK" ] || : > "$SHADOW_MARK"\n');
		chmodSync(file, 0o755);
	}
	execFileSync("tar", ["-czf", "package.tgz", "package"], { cwd: at });
	const tarball = readFileSync(join(at, "package.tgz"));
	return {
		manifest,
		tarball,
		integrity: `sha512-${createHash("sha512").update(tarball).digest("base64")}`,
	};
}

const served = new Map(published.map((manifest) => [manifest.name, packed(manifest)]));
const servedOf = (name: string) => served.get(name) as Served;
let registry: Server;
let origin = "";

const startRegistry = () =>
	new Promise<void>((started) => {
		const tarballs = new Map([...served.values()].map((s) => [pathOf(s.manifest), s]));
		registry = createServer((request, response) => {
			const path = decodeURIComponent(request.url ?? "/");
			const tarball = tarballs.get(path);
			const doc = served.get(path.slice(1));
			if (tarball) {
				response.writeHead(200, { "content-type": "application/octet-stream" });
				response.end(tarball.tarball);
			} else if (doc) {
				const { name, version } = doc.manifest;
				const when = "2026-01-01T00:00:00.000Z";
				response.writeHead(200, { "content-type": "application/json" });
				response.end(
					JSON.stringify({
						name,
						"dist-tags": { latest: version },
						time: { created: when, modified: when, [version]: when },
						versions: {
							[version]: {
								...doc.manifest,
								dist: { tarball: `${origin}${pathOf(doc.manifest)}`, integrity: doc.integrity },
							},
						},
					}),
				);
			} else {
				response.writeHead(404).end("{}");
			}
		});
		registry.listen(0, "127.0.0.1", () => {
			origin = `http://127.0.0.1:${(registry.address() as AddressInfo).port}`;
			started();
		});
	});

const recordOf = (name: string): OutsideRecord => {
	const { manifest, integrity } = servedOf(name);
	return {
		name,
		version: manifest.version,
		integrity,
		dependencies: {},
		optionalDependencies: {},
		peerDependencies: manifest.peerDependencies ?? {},
		peerDependenciesMeta: {},
	};
};

/** zod's integrity, as the release records it: the app installs the real one, as pnpm itself comes, from npm's registry. */
const zodIntegrity = () =>
	(
		parse(readFileSync(join(root, "pnpm-lock.yaml"), "utf8")).packages[`zod@${appZod}`] as {
			resolution: { integrity: string };
		}
	).resolution.integrity;

/** The app as generated beside the packages named, the test's scopes naming its registry; each file it runs says so. */
async function appOf(names: readonly string[]): Promise<string> {
	const target = mkdtempSync(join(tmpdir(), "outside-start-app-"));
	const packages: Packages = {
		fragments: async () => fragmentsOf([]),
		dependencies: () => ({
			[release]: releaseVersion,
			...Object.fromEntries(names.map((name) => [name, "1.0.0"])),
		}),
		importOf: (name) => name,
		cards: () => [],
		release: () => ({
			version: releaseVersion,
			integrity: { [release]: servedOf(release).integrity, zod: zodIntegrity() },
		}),
		...(names.length > 0
			? {
					outside: () => ({
						modules: names.map(recordOf),
						registries: {
							default: "https://registry.npmjs.org",
							scopes: { "@o3co": origin, "@x": origin },
						},
					}),
				}
			: {}),
	};
	const app = join(target, "app");
	await writeDeployment(app, ["@mod/seal", ...names], packages, {
		template: "pattern-readme.md",
		fill: { name: "outside-start", use: "A test.", card: "" },
	});
	for (const entry of ["main", "reseal"]) {
		expect(existsSync(join(app, "src", `${entry}.ts`))).toBe(true);
		writeFileSync(
			join(app, "src", `${entry}.ts`),
			`console.log("REAL NODE ${entry}", process.env.APP_CONFIG);\n`,
		);
	}
	if (names.length === 0) writeFileSync(join(app, ".npmrc"), `@o3co:registry=${origin}/\n`);
	return app;
}

/** The environment of the operator's shell: not this run's, whose PATH may name what a runner put there. */
const operatorEnv = (mark: string) => ({
	...Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^npm_/i.test(name))),
	PATH: (process.env.PATH ?? "")
		.split(delimiter)
		.filter((dir) => isAbsolute(dir) && !dir.includes(join("node_modules", ".bin")))
		.join(delimiter),
	SHADOW_MARK: mark,
});
const markOf = (app: string) => join(app, "..", "shadow-ran");

/** A command in the app, its status and all it said. Not to hold the process: the registry answering it lives here. */
const ran = async (app: string, command: string, args: readonly string[]) => {
	try {
		const { stdout, stderr } = await promisify(execFile)(command, [...args], {
			cwd: app,
			timeout: 120_000,
			env: operatorEnv(markOf(app)),
		});
		return { status: 0, stdout, said: `${stdout}${stderr}` };
	} catch (error) {
		const failed = error as { code?: number; stdout?: string; stderr?: string };
		const stdout = failed.stdout ?? "";
		return { status: failed.code ?? 1, stdout, said: `${stdout}${failed.stderr ?? ""}` };
	}
};
const inShell = (app: string, command: string) => ran(app, "sh", ["-c", command]);
/** With a store and a cache of the test's own. */
const own = (app: string) =>
	`--store-dir=${join(app, "..", "store")} --cache-dir=${join(app, "..", "cache")}`;

/** The guide's commands as the README gives them, each run as it stands. */
async function installedAsTheGuideSays(app: string) {
	const guide = readFileSync(join(app, "README.md"), "utf8");
	const block = guide.slice(guide.indexOf("## Packages outside this release"));
	const commands = (/```sh\n([\s\S]*?)```/.exec(block)?.[1] ?? "").trim().split("\n");
	expect(commands).toHaveLength(3);
	const said: string[] = [];
	for (const command of commands) {
		const run = await inShell(app, command.startsWith("pnpm") ? `${command} ${own(app)}` : command);
		expect(run.status, `${command}: ${run.said}`).toBe(0);
		said.push(run.stdout);
	}
	return said;
}

const stepFour = (app: string) => {
	const step = /^4\. `(.+)`$/m.exec(readFileSync(join(app, "README.md"), "utf8"))?.[1];
	if (step === undefined) throw new Error("the guide gives no step 4");
	return step;
};
const appConfig = "config/local.conf,config/application.conf";

beforeAll(startRegistry);

afterAll(async () => {
	registry.closeAllConnections();
	await new Promise((closed) => registry.close(closed));
});

describe.each([
	{
		order: "installed as the guide says",
		install: (app: string) => installedAsTheGuideSays(app),
	},
	{
		order: "installed plainly",
		install: async (app: string) => {
			const run = await inShell(app, `pnpm install --no-frozen-lockfile ${own(app)}`);
			expect(run.status, run.said).toBe(0);
			return [];
		},
	},
])("an app beside a package outside the release, $order", ({ install }) => {
	let app = "";

	beforeAll(async () => {
		app = await appOf([peered]);
		await install(app);
	}, 180_000);

	it("is on the pinned pnpm, with a command named node linked at its .bin", async () => {
		const pinned = JSON.parse(readFileSync(join(app, "package.json"), "utf8")).packageManager;
		const { stdout } = await ran(app, "pnpm", ["--version"]);
		expect(`pnpm@${stdout.trim()}`).toBe(pinned);
		expect(existsSync(join(app, "node_modules", ".bin", "node"))).toBe(true);
	});

	it("has no scripts, and pnpm start and pnpm run reseal fail on it, running nothing", async () => {
		expect(JSON.parse(readFileSync(join(app, "package.json"), "utf8"))).not.toHaveProperty(
			"scripts",
		);
		expect(existsSync(join(app, "server.js"))).toBe(false);
		for (const args of [["start"], ["run", "reseal"]]) {
			const run = await ran(app, "pnpm", args);
			expect(run.status, run.said).not.toBe(0);
			expect(run.said).toContain("ERR_PNPM_NO_SCRIPT");
			expect(run.said).not.toContain("SHADOW");
		}
	});

	it("starts with real node by the command the README gives, and runs an entry the same way", async () => {
		const start = stepFour(app);
		expect(start).toBe(`APP_CONFIG=${appConfig} node --env-file-if-exists=.env src/main.ts`);
		const main = await inShell(app, start);
		expect(main.said).not.toContain("SHADOW");
		expect(main.status, main.said).toBe(0);
		expect(main.stdout).toContain(`REAL NODE main ${appConfig}`);
		const entry = await inShell(app, start.replace("src/main.ts", "src/reseal.ts"));
		expect(entry.status, entry.said).toBe(0);
		expect(entry.stdout).toContain(`REAL NODE reseal ${appConfig}`);
		expect(existsSync(markOf(app))).toBe(false);
	});
});

describe("the guide's commands, beside a command named node", () => {
	it("check with real node, which answers for the lockfile, and run nothing of the package", async () => {
		const app = await appOf([peered]);
		const said = await installedAsTheGuideSays(app);
		expect(said[1]).toBe("ok\n");
		expect(existsSync(join(app, "node_modules", ".bin", "node"))).toBe(true);
		const again = await ran(app, "node", ["scripts/check-outside.mjs"]);
		expect(again).toMatchObject({ status: 0, stdout: "ok\n" });
		expect(existsSync(markOf(app))).toBe(false);
	}, 180_000);

	it("leave what the guide says runs with .bin's command to it", async () => {
		const app = await appOf([peered]);
		await installedAsTheGuideSays(app);
		for (const args of [["exec", "node", "-e", "1"], ["node", "-e", "1"], ["reseal"]]) {
			const run = await ran(app, "pnpm", args);
			expect(run.stdout, args.join(" ")).toContain("SHADOW");
		}
	}, 180_000);
});

describe("an app beside no package outside the release", () => {
	it("keeps its scripts, its README starts it by them, and they run", async () => {
		const app = await appOf([]);
		const manifest = JSON.parse(readFileSync(join(app, "package.json"), "utf8"));
		expect(Object.keys(manifest.scripts)).toEqual(["start", "reseal"]);
		expect(stepFour(app)).toBe(`APP_CONFIG=${appConfig} pnpm start`);
		const installed = await inShell(app, `pnpm install --no-frozen-lockfile ${own(app)}`);
		expect(installed.status, installed.said).toBe(0);
		const started = await inShell(app, stepFour(app));
		expect(started.status, started.said).toBe(0);
		expect(started.stdout).toContain(`REAL NODE main ${appConfig}`);
		const entry = await ran(app, "pnpm", ["run", "reseal"]);
		expect(entry.status, entry.said).toBe(0);
		expect(entry.stdout).toContain("REAL NODE reseal");
	}, 180_000);
});
