import { spawn, spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composed, full } from "@mod/combinations";
import { describe, expect, it, vi } from "vitest";
import { generate, patterns } from "../src/contract.ts";
import { generatePattern } from "../src/pattern.ts";
import { auditReceiversOf, chosenLines } from "../src/patterns/chosen.ts";
import { type Choice, selectionOf } from "../src/patterns/pattern.ts";
import { patternNamed } from "../src/patterns/patterns.ts";
import {
	boot,
	kernel,
	readsScalarsFromEnv,
	refusesEmptyOnlyForSections,
	refusesGeneratedOnlyForNamedKeys,
	writesListsLocally,
} from "./checks.ts";
import {
	configured,
	generatedPattern,
	importedModules as imports,
	linked,
	read,
	root,
} from "./full-app.ts";

// These tests read the whole workspace and boot the app, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 120_000 });

const named = patterns()
	.map((p) => p.name)
	.filter((name) => name !== "full");
const modulesOf = (name: string, choice?: Choice) =>
	composed(selectionOf(patternNamed(name), choice));
const cardFile = (name: string) => join(import.meta.dirname, "..", "src", "patterns", `${name}.md`);

it("names in audit.receivers each composed adapter's receiver, and audit's own log only when none is", () => {
	const of = (modules: readonly string[]) => auditReceiversOf((m) => modules.includes(m));
	expect(of(["@mod/audit-stdout"])).toEqual(["stdout"]);
	expect(of(["@mod/audit-http", "@mod/audit-stdout"])).toEqual(["http", "stdout"]);
	expect(of([])).toEqual(["log"]);
	expect(chosenLines(["@mod/audit", "@mod/audit-stdout"])).toContain(
		"- Audit events named in `audit.receivers = [stdout]`.",
	);
	expect(chosenLines(["@mod/audit"])).toContain(
		"- Audit events named in `audit.receivers = [log]`.",
	);
});

it("tells a federation app taking users from a ledger to give it the lookup by subject", () => {
	const ledger =
		"- A federation login finds its user through the ledger's lookup by subject (`users-http.subject-url`), or by upstream identity (`users-http.upstream-url`).";
	expect(chosenLines(["@mod/federation", "@mod/users-http"])).toContain(ledger);
	expect(chosenLines(["@mod/users-http"])).not.toContain(ledger);
});

async function freePort(): Promise<number> {
	return new Promise((resolve) => {
		const server = createServer().listen(0, "127.0.0.1", () => {
			const address = server.address();
			server.close(() => resolve(typeof address === "object" && address ? address.port : 0));
		});
	});
}

/** Runs the app until it says it listens, then stops it by SIGTERM: its exit code and output. */
async function startsAndStops(target: string) {
	const child = spawn(process.execPath, ["src/main.ts"], {
		cwd: target,
		env: { APP_CONFIG: "config/local.conf,config/application.conf" },
	});
	let output = "";
	const exited = new Promise<number | null>((resolve) => child.once("exit", resolve));
	const listening = new Promise<void>((resolve) => {
		const seen = (chunk: Buffer) => {
			output += chunk;
			if (output.includes('"event":"http.listening"')) resolve();
		};
		child.stdout.on("data", seen);
		child.stderr.on("data", seen);
	});
	await Promise.race([listening, exited]);
	child.kill("SIGTERM");
	return { code: await exited, output };
}

// http-ops comes only through its bridge to http: a manifest gone wrong would drop liveness,
// readiness and the two instruments without a word.
it("composes http-ops in the full template and in every pattern", () => {
	expect(full()).toContain("@mod/http-ops");
	for (const name of named) expect(modulesOf(name), name).toContain("@mod/http-ops");
});

describe.each(named)("the pattern %s", (name) => {
	it("assembles what combinations composes from its selection, and holds its card", async () => {
		const target = await generatedPattern(name);
		const modules = modulesOf(name);
		expect(await imports(target)).toEqual(modules);
		const pkg = JSON.parse(await read(target, "package.json"));
		expect(Object.keys(pkg.dependencies)).toEqual([kernel, ...modules]);
		const card = readFileSync(cardFile(name), "utf8");
		expect(card.startsWith(`# ${name}\n`)).toBe(true);
		expect(card.trimEnd().split("\n").length).toBeLessThanOrEqual(10);
		// The guide opens with the use, and carries the card's lines.
		const readme = await read(target, "README.md");
		expect(readme).toContain(patternNamed(name).use);
		for (const line of card.split("\n").slice(1)) expect(readme).toContain(line);
		expect(readme).toContain("`docker run --env-file .env -e HTTP_HOST=0.0.0.0 -e HTTP_PORT=8080 ");
	});

	it("reads its fragments' scalars from env and writes their lists locally, holding no value", async () => {
		const target = await generatedPattern(name);
		await readsScalarsFromEnv(target, modulesOf(name));
		await writesListsLocally(target, modulesOf(name));
	});

	const modules = modulesOf(name);
	const relayed = modules.includes("@mod/mail-smtp");
	const onRedis = modules.includes("@mod/redis");

	it("refuses an empty configuration only for its sections and the kernel's", async () => {
		await refusesEmptyOnlyForSections(await linked(await generatedPattern(name)), modules);
	});

	it("refuses the generated configuration alone only for keys the guide names", async () => {
		await refusesGeneratedOnlyForNamedKeys(await linked(await generatedPattern(name)));
	});

	it.runIf(relayed)(
		"names the relay's keys when they are unset, the configuration empty or generated",
		async () => {
			const target = await linked(await generatedPattern(name));
			const relay = expect.arrayContaining([expect.stringMatching(/^mail-smtp\./)]);
			expect(await refusesEmptyOnlyForSections(target, modules)).toEqual(relay);
			expect(await refusesGeneratedOnlyForNamedKeys(target)).toEqual(relay);
		},
	);

	it.runIf(onRedis)(
		"boots on the generated configuration filled, refused only for an unreachable Redis",
		async () => {
			const target = await linked(await generatedPattern(name));
			// Nothing listens on port 1.
			await configured(target, { deployment: "multi", redisUrl: "redis://127.0.0.1:1" });
			const run = boot(target, "config/local.conf,config/application.conf");
			expect(run.refused, run.stderr).toEqual(["redis.url"]);
		},
	);

	it.skipIf(onRedis)(
		"boots on the generated configuration filled, and stops on SIGTERM",
		async () => {
			const target = await linked(await generatedPattern(name));
			const port = await freePort();
			await configured(target, { deployment: "single", redisUrl: "", port });
			const run = await startsAndStops(target);
			expect(run.output).toContain('"event":"http.listening"');
			expect(run.code, run.output).toBe(0);
		},
	);
});

it("tells, as the repository's guide does, that a value of several lines goes in the local layer, not in .env", async () => {
	const target = await generatedPattern("simple-web");
	const note = "a value of several lines, such as a PEM key, goes in the local layer instead";
	expect(await read(target, "README.md")).toContain(note);
	expect(await read(target, ".env.example")).toMatch(new RegExp(`^## .*${note}`));
});

it("lists each pattern with its use and areas, full among them", () => {
	const listed = patterns();
	expect(listed.map((p) => p.name)).toEqual([...named, "full"]);
	for (const p of listed) {
		expect(p.use.length, p.name).toBeGreaterThan(0);
		expect(Array.isArray(p.areas), p.name).toBe(true);
	}
	expect(named).toContain("simple-web");
});

/** The module whose scenes each conformance area holds, for the areas a pattern may lack the module of. */
const areaModules: Readonly<Record<string, string>> = {
	federation: "@mod/federation",
	"second-factor": "@mod/mfa",
	device: "@mod/device-grant",
	mtls: "@mod/mtls",
	passkey: "@mod/webauthn",
	exchange: "@mod/token-exchange",
};

it("runs every area whose module a pattern composes against it, the full template too", () => {
	const missing = patterns().flatMap(({ name, areas }) => {
		const modules = name === "full" ? full() : modulesOf(name);
		return Object.entries(areaModules)
			.filter(([area, module]) => modules.includes(module) && !areas.includes(area))
			.map(([area]) => `${name} composes ${areaModules[area]} but runs no ${area} area`);
	});
	expect(missing).toEqual([]);
});

it("lists what conformance adds to a pattern for its run, each composing with the pattern", () => {
	const adds = Object.fromEntries(patterns().map((p) => [p.name, p.conformanceAdd]));
	expect(adds).toMatchObject({
		"sso-federated": ["@mod/login-password"],
		a2a: ["@mod/token-exchange"],
		full: [],
	});
	for (const name of named) {
		const add = adds[name] ?? [];
		expect(modulesOf(name, { add }), name).toEqual(expect.arrayContaining([...add]));
	}
});

it("takes the operator's axes over the pattern's, a group in place of the pattern's, and features added", async () => {
	const choice = {
		axes: { "@mod/store": "@mod/redis" },
		features: { binding: ["@mod/dpop"] },
		add: ["@mod/device-grant"],
	};
	const target = await generatedPattern("simple-web", choice);
	const modules = await imports(target);
	expect(modules).toEqual(modulesOf("simple-web", choice));
	expect(modules).toEqual(expect.arrayContaining(["@mod/redis", "@mod/dpop", "@mod/device-grant"]));
	expect(modules).not.toContain("@mod/store");
	// The guide tells what was chosen, not what the pattern chooses by default.
	const readme = await read(target, "README.md");
	expect(readme).not.toContain("so the deployment runs as one instance");
	expect(readme).toContain("Store in Redis");
	expect(readme).not.toContain("Store in memory");
	expect(await read(await generatedPattern("simple-web"), "README.md")).toContain(
		"Store in memory",
	);
});

it("refuses a pattern, group or name it does not know, and axes for full, before writing anything", async () => {
	const parent = await mkdtemp(join(tmpdir(), "create-app-"));
	const target = join(parent, "app");
	const fixture = { ...patternNamed("simple-web"), features: { login: ["@mod/nowhere"] } };
	await expect(generatePattern({ target, template: "fixture" }, fixture)).rejects.toThrow(
		"@mod/nowhere: not in the workspace",
	);
	for (const [plan, reason] of [
		[{ template: "nowhere" }, "nowhere: no such pattern"],
		[{ template: "simple-web", features: { pages: [] } }, "pages: not a group"],
		[{ template: "simple-web", axes: { "@mod/store": "../up" } }, "not a package name"],
		[{ template: "full", axes: { "@mod/store": "@mod/store" } }, "full takes no axes"],
	] as const) {
		await expect(generate({ target, workspace: root, ...plan }), reason).rejects.toThrow(reason);
	}
	expect(existsSync(target)).toBe(false);
});

it("makes a pattern from the command, with axes, groups and features added", async () => {
	const cli = (...args: string[]) =>
		spawnSync(process.execPath, [join(import.meta.dirname, "..", "src", "main.ts"), ...args], {
			encoding: "utf8",
		});
	const parent = await mkdtemp(join(tmpdir(), "create-app-cli-"));
	const made = cli(
		join(parent, "web"),
		"--workspace",
		root,
		"--pattern",
		"simple-web",
		"--axis",
		"@mod/store=@mod/redis",
		"--binding",
		"@mod/dpop,@mod/mtls",
		"--add",
		"@mod/device-grant",
	);
	expect(made.status, made.stderr).toBe(0);
	expect(await imports(join(parent, "web"))).toEqual(
		modulesOf("simple-web", {
			axes: { "@mod/store": "@mod/redis" },
			features: { binding: ["@mod/dpop", "@mod/mtls"] },
			add: ["@mod/device-grant"],
		}),
	);
	for (const args of [
		[join(parent, "a"), "--pattern", "simple-web", "--axis", "@mod/store"],
		[join(parent, "b"), "--axis", "@mod/store=@mod/redis"],
		[join(parent, "c"), "--pattern", "full", "--login", "@mod/login-password"],
		[join(parent, "d"), "--pattern", "simple-web", "@mod/http"],
	]) {
		expect(cli(...args).status, args.join(" ")).toBe(64);
	}
});
