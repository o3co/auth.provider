/**
 * The image of an app beside a package outside the release, built as the operator builds it: on the
 * base image, the corepack and the pnpm its Dockerfile pins, from a registry of the test's own.
 */
import { execFile, execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
	copyFileSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	realpathSync,
	writeFileSync,
} from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { DockerFailed, docker, dockerSync, dockerWithin } from "@mod/docker-client";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parse, parseAllDocuments, stringify } from "yaml";
import {
	appZod,
	fragmentsOf,
	type OutsideRecord,
	type Packages,
	writeDeployment,
} from "../src/contract.ts";

const root = join(import.meta.dirname, "..", "..", "..", "..");

const scoped = "@x/grant";
const version = "1.0.0";
/** What the image's build reaches the host's registry by. */
const hostName = "host.docker.internal";
const canary = `canary-${randomBytes(16).toString("hex")}`;
const tag = `outside-image-test:${randomBytes(4).toString("hex")}`;

/** The registry's package: its tarball, and its integrity as a registry states it. */
interface Served {
	readonly manifest: Record<string, unknown>;
	readonly tarball: Buffer;
	readonly integrity: string;
}
let served: Served;
let registry: Server;
let port = 0;
/** The tarballs the registry was asked for, and whether each asking held the credential. */
let asked: boolean[] = [];

function packed(manifest: Record<string, unknown>, files: Record<string, string>): Served {
	const at = mkdtempSync(join(tmpdir(), "outside-image-package-"));
	mkdirSync(join(at, "package"));
	const whole = { name: scoped, version, ...manifest };
	writeFileSync(join(at, "package", "package.json"), JSON.stringify(whole));
	for (const [file, text] of Object.entries(files)) writeFileSync(join(at, "package", file), text);
	execFileSync("tar", ["-czf", "package.tgz", "package"], { cwd: at });
	const tarball = readFileSync(join(at, "package.tgz"));
	return {
		manifest: whole,
		tarball,
		integrity: `sha512-${createHash("sha512").update(tarball).digest("base64")}`,
	};
}

/** Each registry's answer: `@x/grant` alone, to a request holding the credential. */
const startRegistry = () =>
	new Promise<void>((started) => {
		registry = createServer((request, response) => {
			const holds = request.headers.authorization === `Bearer ${canary}`;
			const path = decodeURIComponent(request.url ?? "/");
			const file = `/${scoped}/-/grant-${version}.tgz`;
			if (path === file) asked.push(holds);
			if (!holds) {
				response.writeHead(401).end("{}");
			} else if (path === file) {
				response.writeHead(200, { "content-type": "application/octet-stream" });
				response.end(served.tarball);
			} else if (path === `/${scoped}`) {
				const published = "2026-01-01T00:00:00.000Z";
				response.writeHead(200, { "content-type": "application/json" });
				response.end(
					JSON.stringify({
						name: scoped,
						"dist-tags": { latest: version },
						time: { created: published, modified: published, [version]: published },
						versions: {
							[version]: {
								...served.manifest,
								dist: {
									tarball: `http://${request.headers.host}${file}`,
									integrity: served.integrity,
								},
							},
						},
					}),
				);
			} else {
				response.writeHead(404).end("{}");
			}
		});
		// Every interface: a build's container reaches the host by its bridge, not its loopback.
		registry.listen(0, "0.0.0.0", () => {
			port = (registry.address() as AddressInfo).port;
			started();
		});
	});

/** zod's integrity, as the release records it: the workspace installs the app's zod. */
const zodIntegrity = () =>
	(
		parse(readFileSync(join(root, "pnpm-lock.yaml"), "utf8")).packages[`zod@${appZod}`] as {
			resolution: { integrity: string };
		}
	).resolution.integrity;

/**
 * The app as generated, recording the package as `recorded`, and its lockfile as the operator's pnpm
 * writes it, in a project of its own, naming the registry by the address the host knows it.
 */
async function appOf(recorded: string, settings: Record<string, unknown> = {}): Promise<string> {
	const target = realpathSync(mkdtempSync(join(tmpdir(), "outside-image-app-")));
	const record: OutsideRecord = {
		name: scoped,
		version,
		integrity: recorded,
		dependencies: {},
		optionalDependencies: {},
		peerDependencies: {},
		peerDependenciesMeta: {},
	};
	const packages: Packages = {
		fragments: async () => fragmentsOf([]),
		dependencies: () => ({ [scoped]: version }),
		importOf: (name) => name,
		cards: () => [],
		release: () => ({ version: "1.2.3", integrity: { zod: zodIntegrity() } }),
		outside: () => ({
			modules: [record],
			registries: {
				default: "https://registry.npmjs.org",
				scopes: { "@x": `http://${hostName}:${port}` },
			},
		}),
	};
	const app = join(target, "app");
	await writeDeployment(app, [scoped], packages, {
		template: "pattern-readme.md",
		fill: { name: "outside-image", use: "A test.", card: "" },
	});
	const workspace = join(app, "pnpm-workspace.yaml");
	writeFileSync(workspace, stringify({ ...parse(readFileSync(workspace, "utf8")), ...settings }));
	const project = join(target, "project");
	mkdirSync(project);
	for (const file of ["package.json", "pnpm-workspace.yaml"]) {
		copyFileSync(join(app, file), join(project, file));
	}
	writeFileSync(
		join(project, ".npmrc"),
		`@x:registry=http://127.0.0.1:${port}/\n//127.0.0.1:${port}/:_authToken=${canary}\n`,
	);
	// Not to hold the process: the registry answering it lives here. A cache of its own, as the same
	// name at the same address serves another tarball for each case.
	const cache = join(target, "cache");
	await promisify(execFile)("pnpm", ["install", "--lockfile-only", "--cache-dir", cache], {
		cwd: project,
		timeout: dockerWithin.run,
	});
	copyFileSync(join(project, "pnpm-lock.yaml"), join(app, "pnpm-lock.yaml"));
	asked = [];
	return app;
}

/** Builds the app as the guide says, its credential a build secret: what the build wrote. */
function built(app: string) {
	const secret = join(mkdtempSync(join(tmpdir(), "outside-image-secret-")), "npmrc");
	writeFileSync(secret, `//${hostName}:${port}/:_authToken=${canary}\n`);
	return docker(
		[
			"build",
			"--progress=plain",
			"--add-host",
			`${hostName}:host-gateway`,
			"--secret",
			`id=npmrc,src=${secret}`,
			"-t",
			tag,
			app,
		],
		dockerWithin.build,
		{ merged: true },
	);
}

beforeAll(startRegistry);

afterAll(async () => {
	registry.closeAllConnections();
	await new Promise((closed) => registry.close(closed));
	try {
		dockerSync(["image", "rm", "-f", tag], dockerWithin.control);
	} catch (error) {
		if (!(error instanceof DockerFailed) || error.kind !== "absent") throw error;
	}
});

describe("the image's build", () => {
	it(
		"stops at the check, before the install, for a package with a command and a wrong record",
		async () => {
			served = packed({ bin: { node: "./run.js" } }, { "run.js": "process.exit(0);\n" });
			const wrong = `sha512-${"A".repeat(86)}==`;
			const app = await appOf(wrong);
			const failed = await built(app).then(
				(wrote) => new Error(`the build passed:\n${wrote}`),
				(error: unknown) => error,
			);
			expect(failed).toBeInstanceOf(DockerFailed);
			const said = (failed as DockerFailed).wrote;
			expect(said).toContain(`${scoped}: integrity ${served.integrity}, not ${wrong} as recorded`);
			expect(said).toMatch(/\[deps \d+\/\d+\] RUN node scripts\/check-outside\.mjs/);
			// A step started is told by its header; the Dockerfile's excerpt beside the failure is no step.
			expect(said).not.toMatch(/\[deps \d+\/\d+\] RUN .*pnpm install/);
			expect(asked).toEqual([]);
		},
		dockerWithin.build + 60_000,
	);

	it(
		"installs with the credential, and leaves it out of the image the app runs in, though the package asks to read it",
		async () => {
			const reads = 'require("node:fs").copyFileSync("/root/.npmrc", "read");\n';
			served = packed({ scripts: { postinstall: "node read.cjs" } }, { "read.cjs": reads });
			const app = await appOf(served.integrity, { allowBuilds: { [scoped]: true } });
			// The pinned pnpm writes it one document, as the app's workspace asks: the check reads no other.
			const lock = readFileSync(join(app, "pnpm-lock.yaml"), "utf8");
			expect(parseAllDocuments(lock)).toHaveLength(1);
			const wrote = await built(app);
			// The registry refuses a request without it: the install read the secret.
			expect(asked, wrote).toEqual([true]);
			// As root: what a secret's file leaves behind only root may read.
			const run = (script: string) =>
				docker(
					["run", "--rm", "--user", "root", "--entrypoint", "sh", tag, "-c", script],
					dockerWithin.run,
				);
			expect(await run(`test -f /app/node_modules/${scoped}/package.json && echo installed`)).toBe(
				"installed",
			);
			expect(await run(`find / -xdev -type f -exec grep -l '${canary}' {} + || true`)).toBe("");
			expect(await docker(["history", "--no-trunc", tag], dockerWithin.control)).not.toContain(
				canary,
			);
		},
		dockerWithin.build + 2 * dockerWithin.run,
	);
});
