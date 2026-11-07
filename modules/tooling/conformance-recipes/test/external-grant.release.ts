import { execFileSync } from "node:child_process";
import { randomBytes, scryptSync } from "node:crypto";
import {
	cpSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	renameSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { baseEnv, freePort, launch } from "@mod/conformance";
import { packedRegistry } from "@mod/distribution";
import { trialLayer } from "@mod/trial";
import { afterAll, describe, expect, it } from "vitest";
import { commands, shownCommand, transcript, withBlocks } from "../src/main.ts";

const workspace = join(import.meta.dirname, "..", "..", "..", "..");
const recipe = join(workspace, "docs", "recipe-external-grant.md");
const fixture = join(import.meta.dirname, "..", "fixtures", "external-grant");
const grantType = "urn:example:params:oauth:grant-type:example";
const secret = "example-client-secret-0123456789abcdef";
const shownOrigin = "http://127.0.0.1:8080";
const grantName = "@example/example-grant";
/** The project the reader installs the grant into, as the recipe's command names it. */
const project = "outside";
const projectManifest = '{ "private": true }';
/** The app's checked install, in the order the guide to packages outside the release gives. */
const installSteps = [
	["pnpm", "install", "--lockfile-only"],
	["node", "scripts/check-outside.mjs"],
	["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"],
] as const;

/** A bcrypt or scrypt hash, as the provider keeps a client's secret: scrypt here. */
const hashOf = (plain: string) => {
	const salt = randomBytes(16);
	const key = scryptSync(plain, salt, 32, { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
	const b64 = (b: Buffer) => b.toString("base64").replace(/=+$/, "");
	return `$scrypt$ln=15,r=8,p=1$${b64(salt)}$${b64(key)}`;
};

describe("the recipe for a grant of your own, outside the repository", () => {
	const root = mkdtempSync(join(tmpdir(), "recipe-grant-"));
	let stop: (() => Promise<void>) | undefined;
	let stopRegistry: (() => Promise<void>) | undefined;
	/** The composed app started with `tokens.access-token-lifetime` as given; set by the first scene. */
	let startAt: ((lifetime: string) => ReturnType<typeof launch>) | undefined;
	/** The grant composed into an app generated with these arguments too, started as above; set by the first scene. */
	let composedWith:
		| ((
				name: string,
				args: readonly string[],
		  ) => Promise<(extra: string) => ReturnType<typeof launch>>)
		| undefined;
	afterAll(async () => {
		await stop?.();
		await stopRegistry?.();
		rmSync(root, { recursive: true, force: true });
	});

	it("builds the grant against the published packages, composes it into a generated app, and issues a token with it", async () => {
		const tarballs = process.env.RECIPES_TARBALLS ?? "";
		if (!tarballs) {
			throw new Error(
				"RECIPES_TARBALLS names the packed tarballs: run `pnpm bundles`, then `.github/scripts/pack-published.sh <dir>`",
			);
		}
		// Each published name, at the one version of the release, from its tarball alone.
		const packed = new Map(
			readdirSync(tarballs)
				.filter((file) => file.endsWith(".tgz"))
				.map((file) => {
					const path = join(tarballs, file);
					const manifest = JSON.parse(
						execFileSync("tar", ["-xzOf", path, "package/package.json"], { encoding: "utf8" }),
					) as { name: string; version: string };
					return [manifest.name, { path, version: manifest.version }] as const;
				}),
		);
		const entrance = packed.get("@o3co/create-auth-provider");
		if (!entrance) throw new Error(`no @o3co/create-auth-provider among ${tarballs}`);
		const version = entrance.version;
		const manifestText = readFileSync(join(fixture, "package.json"), "utf8");
		const moduleText = readFileSync(join(fixture, "src", "module.mts"), "utf8");
		const grantManifest = JSON.parse(manifestText) as { name: string; version: string };
		expect(grantManifest.name).toBe(grantName);
		const upstream = execFileSync("pnpm", ["config", "get", "registry"], {
			cwd: root,
			encoding: "utf8",
		}).trim();
		const run = (command: string, args: readonly string[], cwd: string) => {
			try {
				execFileSync(command, args, { cwd, stdio: "pipe", encoding: "utf8" });
			} catch (error) {
				const told = error as { stdout?: string; stderr?: string };
				throw new Error(`${command} ${args.join(" ")}:\n${told.stdout ?? ""}${told.stderr ?? ""}`);
			}
		};
		/** Routes the release's scope and the grant's, in `dir`, to the registry at `origin`. */
		const routed = (dir: string, origin: string) =>
			writeFileSync(
				join(dir, ".npmrc"),
				`@o3co:registry=${origin}/\n${grantName.split("/")[0]}:registry=${origin}/\n`,
			);

		// The generator, and the published packages the grant builds against, from the release alone.
		const building = await packedRegistry({ release: tarballs, outside: [], upstream });
		const tool = join(root, "tool");
		const grant = join(root, "example-grant");
		try {
			mkdirSync(tool);
			routed(tool, building.origin);
			writeFileSync(join(tool, "package.json"), JSON.stringify({ name: "tool", private: true }));
			run("pnpm", ["add", `@o3co/create-auth-provider@${version}`], tool);
			cpSync(fixture, grant, { recursive: true });
			renameSync(join(grant, "src", "module.mts"), join(grant, "src", "module.ts"));
			routed(grant, building.origin);
			writeFileSync(join(grant, "package.json"), manifestText.replaceAll("<version>", version));
			run("pnpm", ["install"], grant);
		} finally {
			await building.stop();
		}
		// The grant's package, as its author keeps it, built against the published packages' declarations.
		try {
			execFileSync(join(workspace, "node_modules", ".bin", "tsc"), ["-p", "tsconfig.json"], {
				cwd: grant,
				stdio: "pipe",
				encoding: "utf8",
			});
		} catch (error) {
			const told = error as { stdout?: string; stderr?: string };
			throw new Error(
				`the grant's package does not build:\n${told.stdout ?? ""}${told.stderr ?? ""}`,
			);
		}
		// Published by its author: here, packed and served beside the release.
		const outside = join(root, "outside-tarballs");
		mkdirSync(outside);
		run("pnpm", ["pack", "--pack-destination", outside], grant);
		const registry = await packedRegistry({ release: tarballs, outside: [outside], upstream });
		stopRegistry = registry.stop;

		// The reader's project, the grant installed into it from the registry.
		const staged = `${grantName}@${grantManifest.version}`;
		const staging = join(root, project);
		mkdirSync(staging);
		routed(staging, registry.origin);
		writeFileSync(join(staging, "package.json"), projectManifest);
		run("pnpm", ["add", staged], staging);

		// Generated by the published entrance from outside the project, then installed as the guide says.
		const generatedWith = (name: string, args: readonly string[]) => {
			const at = join(root, name);
			run(
				join(tool, "node_modules", ".bin", "create-auth-provider"),
				[name, ...commands["external-grant"], ...args],
				root,
			);
			for (const [command, ...rest] of installSteps) run(command, rest, at);
			return at;
		};
		const app = generatedWith("my-provider", []);
		expect(readFileSync(join(app, "src", "main.ts"), "utf8")).toContain(`${grantName}/module`);

		// Booted with the trial's settings, and a client allowed the grant.
		const client = {
			id: "example-client",
			kind: "confidential",
			method: "client_secret_basic",
			sections: {
				"client-secret": { hash: hashOf(secret) },
				"client-allowance": { grants: [grantType], scopes: ["example"] },
			},
		};
		const startIn = async (at: string, extra = "") => {
			const port = await freePort();
			const local = await trialLayer(at, {
				redisUrl: "redis://unused.invalid",
				leave: ["redis"],
				layer: `http.port = ${port}\nclients.registered += ${JSON.stringify(client)}${extra}`,
			});
			writeFileSync(join(at, "config", "local.conf"), local);
			return launch({
				command: process.execPath,
				args: ["src/main.ts"],
				cwd: at,
				port,
				env: {
					...baseEnv(),
					APP_CONFIG: "config/local.conf,config/application.conf",
				},
			});
		};
		startAt = (lifetime) => startIn(app, `\ntokens.access-token-lifetime = "${lifetime}"`);
		composedWith = async (name, args) => {
			const at = generatedWith(name, args);
			return (extra) => startIn(at, extra);
		};
		const started = await startIn(app);
		if (started.kind !== "running") throw new Error(`refused:\n${started.output}`);
		stop = started.stop;

		const t = transcript(started.baseUrl, shownOrigin);
		t.block("request");
		const basic = Buffer.from(`${client.id}:${secret}`).toString("base64");
		t.name(basic, "<base64 of example-client:its-secret>");
		const body = new URLSearchParams({ grant_type: grantType, scope: "example" }).toString();
		const answer = await t.send("POST", "/oauth/token", {
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				authorization: `Basic ${basic}`,
			},
			body,
		});
		expect(answer.status, answer.text).toBe(200);
		const issued = JSON.parse(answer.text) as { access_token?: string; scope?: string };
		expect(issued.scope).toBe("example");
		t.name(issued.access_token ?? "", "<access_token>");
		t.mask("expires_in", "<seconds>");

		const shownClient = {
			...client,
			sections: {
				...client.sections,
				"client-secret": { hash: "<a bcrypt or scrypt hash of its secret>" },
			},
		};
		const blocks = {
			"package-json": ["```json", manifestText.trimEnd(), "```"].join("\n"),
			module: ["```ts", moduleText.trimEnd(), "```"].join("\n"),
			command: [
				"```sh",
				`mkdir ${project} && cd ${project}`,
				`echo '${projectManifest}' > package.json`,
				`pnpm add ${staged}`,
				"cd ..",
				shownCommand(commands["external-grant"]),
				"cd my-provider",
				...installSteps.map((step) => step.join(" ")),
				"```",
			].join("\n"),
			client: [
				"```hocon",
				`clients.registered = [${JSON.stringify(shownClient, null, 2)}]`,
				"```",
			].join("\n"),
			request: t.text("request"),
		};
		const committed = readFileSync(recipe, "utf8");
		const rewritten = withBlocks(committed, blocks);
		if (process.env.RECIPES_WRITE) writeFileSync(recipe, rewritten);
		else {
			expect(
				committed,
				"the recipe's blocks are generated: run `pnpm --filter @mod/conformance-recipes run external` with RECIPES_WRITE=1",
			).toBe(rewritten);
		}
	});

	/** Refused above the ceiling, by the settings' keys and no value; running at and below it. */
	const heldToCeiling = async (startedAt: (lifetime: string) => ReturnType<typeof launch>) => {
		const above = await startedAt("3601s");
		expect(above.kind).toBe("refused");
		const told = above.kind === "refused" ? above.output : "";
		const refusal = told.split("\n").find((line) => line.includes("access-token-ceiling")) ?? "";
		expect(refusal).toContain(
			"example-grant.access-token-ceiling: tokens.access-token-lifetime is over it",
		);
		expect(refusal).not.toMatch(/\d/);
		for (const lifetime of ["3600s", "15m"]) {
			const within = await startedAt(lifetime);
			if (within.kind !== "running") throw new Error(`refused at ${lifetime}:\n${within.output}`);
			await within.stop();
		}
	};

	it("refuses boot above the grant's lifetime ceiling, naming both settings and no value, and boots at or below it", async () => {
		if (!startAt) throw new Error("the scene before it composes the app");
		await heldToCeiling(startAt);
	});

	it("makes no cycle of a grant reading `tokens` at build time, beside client ID metadata documents and token exchange", async () => {
		if (!composedWith) throw new Error("the scene before it composes the app");
		const started = await composedWith("beside-exchange", [
			"--add",
			"@mod/clients-cimd",
			"--add",
			"@mod/token-exchange",
		]);
		const main = readFileSync(join(root, "beside-exchange", "src", "main.ts"), "utf8");
		expect(main).toContain("clients-cimd/module");
		expect(main).toContain("token-exchange/module");
		await heldToCeiling((lifetime) => started(`\ntokens.access-token-lifetime = "${lifetime}"`));
	});
});
