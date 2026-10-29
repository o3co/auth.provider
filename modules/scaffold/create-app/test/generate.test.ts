import { spawn, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readdir, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mainSource } from "@mod/app-output";
import { addable, needed } from "@mod/combinations";
import { trialLayer } from "@mod/trial";
import { expect, it, vi } from "vitest";
import { generate, run } from "../src/contract.ts";
import {
	freePort,
	readsScalarsFromEnv,
	refusesGeneratedOnlyForNamedKeys,
	startsAndStops,
	writesListsLocally,
} from "./checks.ts";
import { configured, importedModules, linked, root } from "./full-app.ts";

// These tests read the whole workspace, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

it("assembles the modules asked for, with what they need to run and the wirings and bridges they come with", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-"));
	const asked = ["@mod/session", "@mod/tokens", "@mod/code-grant"];
	await generate({ target, modules: asked });
	const imported = await importedModules(target);
	// What combinations reaches from them, session as the default that replaces it, whatever that is.
	const neededList = needed(asked);
	expect(neededList).toEqual(
		expect.arrayContaining([
			"@mod/session-lifecycle",
			"@mod/tokens",
			"@mod/code-grant",
			"@mod/http",
		]),
	);
	expect(neededList).not.toContain("@mod/session");
	// Then the log sink, the default one when the plan names none.
	const expected = [...neededList, "@mod/log-stdout"];
	expect(imported).toEqual(expected);
	const manifest = JSON.parse(await readFile(join(target, "package.json"), "utf8"));
	expect(Object.keys(manifest.dependencies)).toEqual([
		"@mod/kernel",
		"@mod/config-files",
		...expected,
		"zod",
	]);
});

it("assembles the sink the plan names instead, and lists a sink asked for only once", async () => {
	const imports = async (plan: { modules: string[]; sink?: string }) => {
		const target = await mkdtemp(join(tmpdir(), "create-app-"));
		await generate({ target, ...plan });
		return importedModules(target);
	};
	const named = await imports({ modules: ["@mod/http"], sink: "@mod/other-sink" });
	expect(named).toContain("@mod/other-sink");
	expect(named).not.toContain("@mod/log-stdout");
	const listed = await imports({ modules: ["@mod/log-stdout", "@mod/http"] });
	expect(listed.filter((name) => name === "@mod/log-stdout")).toHaveLength(1);
});

it("refuses a target that holds anything, leaving it as it was", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-"));
	await writeFile(join(target, "package.json"), "mine\n");
	await expect(generate({ target, modules: ["@mod/http"] })).rejects.toThrow("not empty");
	expect(await readdir(target)).toEqual(["package.json"]);
	expect(await readFile(join(target, "package.json"), "utf8")).toBe("mine\n");
	// Judged where it would be written: through a directory that does not exist, it is the same one.
	const around = `${target}/missing/..`;
	await expect(generate({ target: around, modules: ["@mod/http"] })).rejects.toThrow("not empty");
	await expect(generate({ target: around, template: "full" })).rejects.toThrow("not empty");
	expect(await readdir(target)).toEqual(["package.json"]);
	// An empty directory, or none, is taken.
	for (const taken of [
		await mkdtemp(join(tmpdir(), "create-app-")),
		join(target, "..", `${target.split("/").at(-1)}-new`),
	]) {
		await generate({ target: taken, modules: ["@mod/http"] });
		expect((await readdir(taken)).sort(), taken).toEqual([
			".dockerignore",
			".env.example",
			".gitignore",
			"AGENTS.md",
			"Dockerfile",
			"README.md",
			"config",
			"package.json",
			"src",
		]);
	}
});

it("refuses a module or sink that is not named as a package, before writing anything", async () => {
	const parent = await mkdtemp(join(tmpdir(), "create-app-"));
	const target = join(parent, "app");
	for (const name of [
		'@mod/a"b',
		"@mod/Upper",
		"../up",
		"@mod/",
		"/x",
		".hidden",
		"a b",
		"a".repeat(215),
	]) {
		await expect(generate({ target, modules: [name] }), name).rejects.toThrow("not a package name");
		await expect(generate({ target, modules: ["@mod/http"], sink: name }), name).rejects.toThrow(
			"not a package name",
		);
	}
	expect(await readdir(parent)).toEqual([]);
});

it("reads its fragments' scalars from env and writes their lists locally, with a start script and what git leaves out", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-"));
	await generate({ target, modules: ["@mod/tokens"] });
	const modules = (await importedModules(target)).flatMap((name) => (name ? [name] : []));
	await readsScalarsFromEnv(target, modules);
	await writesListsLocally(target, modules);
	const manifest = JSON.parse(await readFile(join(target, "package.json"), "utf8"));
	expect([manifest.private, manifest.type, manifest.scripts]).toEqual([
		true,
		"module",
		{ start: "node --env-file-if-exists=.env src/main.ts" },
	]);
	const ignored = (await readFile(join(target, ".gitignore"), "utf8")).split("\n");
	expect(ignored).toContain(".env");
	expect(ignored).toContain("!.env.example");
	await expect(readFile(join(target, "src", "reseal.ts"), "utf8")).rejects.toThrow();
	await expect(readFile(join(target, "src", "witness-backfill.ts"), "utf8")).rejects.toThrow();
	const guide = await readFile(join(target, "README.md"), "utf8");
	expect(guide).toContain("from the modules listed: `@mod/tokens`.");
	expect(guide).toContain(
		"- `tokens.revocation`: `denylist`, or `unsupported` to answer revocation as unsupported. With `unsupported`, a composed module that needs access tokens revocable refuses boot and says why.",
	);
	// Its store is kept in memory: accepted, one instance, and Redis named for more.
	expect(guide).toContain("the memory store accepted (`store.accept-volatile = true`)");
	expect(guide).toContain(
		"- `kernel.deployment`: `single`: the store is kept in this process, so the deployment runs as one instance; list `@mod/redis` to keep it in Redis and run several.",
	);
});

it("promises no http, port or health check to a listed app that composes no http", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-"));
	await generate({ target, modules: ["@mod/redis"] });
	expect(await importedModules(target)).not.toContain("@mod/http");
	const docker = await readFile(join(target, "Dockerfile"), "utf8");
	expect(docker).not.toContain("HEALTHCHECK");
	expect(docker).not.toContain("EXPOSE");
	const guide = await readFile(join(target, "README.md"), "utf8");
	expect(guide).not.toContain("_healthcheck");
	expect(guide).not.toContain("plain http");
});

it("boots a listed app on its generated configuration filled, holding what its modules need, and stops on SIGTERM", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-"));
	await generate({ target, modules: ["@mod/code-grant"], workspace: root });
	await linked(target);
	// The generated file alone is refused only for keys the guide names.
	await refusesGeneratedOnlyForNamedKeys(target);
	const port = await freePort();
	await configured(target, { deployment: "single", redisUrl: "", port });
	const run = await startsAndStops(target);
	expect(run.output).toContain('"event":"http.listening"');
	expect(run.code, run.output).toBe(0);
});

it("writes a witness-backfill script for an app that keeps the enrollment witness, settling each subject it reads", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-"));
	await generate({ target, modules: ["@mod/mfa-witnessing", "@mod/log-stdout"], workspace: root });
	const manifest = JSON.parse(await readFile(join(target, "package.json"), "utf8"));
	expect(manifest.scripts["witness-backfill"]).toBe(
		"node --env-file-if-exists=.env src/witness-backfill.ts",
	);
	const source = await readFile(join(target, "src", "witness-backfill.ts"), "utf8");
	// The app built and never started, a subject a line from standard input, and only counts told.
	for (const part of [/witnessBackfill/, /\.settle\(/, /process\.stdin/, /await app\.stop\(\)/]) {
		expect(source).toMatch(part);
	}
	expect(source).not.toMatch(/app\.start\(/);
	await linked(target);
	const run = spawnSync(process.execPath, ["src/witness-backfill.ts"], {
		cwd: target,
		env: { ...process.env, APP_CONFIG: "config/application.conf" },
		input: "alice\n",
		encoding: "utf8",
	});
	// Its sections unset, boot is refused as the app's is, telling no subject.
	expect([run.status, run.stdout]).toEqual([78, ""]);
});

it("writes a reseal script for an app that seals, which seals again through each holder and tells the counts", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-"));
	await generate({ target, modules: ["@mod/seal", "@mod/log-stdout"], workspace: root });
	const manifest = JSON.parse(await readFile(join(target, "package.json"), "utf8"));
	expect(manifest.scripts).toEqual({
		start: "node --env-file-if-exists=.env src/main.ts",
		reseal: "node --env-file-if-exists=.env src/reseal.ts",
	});
	// Stopped before it exits, so the stop hooks run (connections closed, buffered log lines out).
	expect(await readFile(join(target, "src", "reseal.ts"), "utf8")).toMatch(/await app\.stop\(\)/);
	await linked(target);
	const key = Buffer.from(Array.from({ length: 32 }, (_, i) => i * 7 + 1)).toString("base64");
	await writeFile(
		join(target, "config", "seal.conf"),
		JSON.stringify({ seal: { current: { id: "now", key } } }),
	);
	// What seal needs to run (its keys, http) is set by trial's layer; the seal key is this test's.
	await writeFile(
		join(target, "config", "local.conf"),
		await trialLayer(target, { redisUrl: "redis://127.0.0.1:1", leave: ["seal"] }),
	);
	const reseal = (files: string) =>
		spawnSync(process.execPath, ["src/reseal.ts"], {
			cwd: target,
			env: { ...process.env, KERNEL_DEPLOYMENT: "single", APP_CONFIG: files },
			encoding: "utf8",
		});
	const done = reseal("config/seal.conf,config/local.conf,config/application.conf");
	expect([done.status, done.stdout]).toEqual([0, "previous keys may be retired\n"]);
	expect(reseal("config/application.conf").status).toBe(78);
});

it("warns once as it boots of the 0.17 variables set and never read, by name and count, never by value", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-"));
	await generate({ target, modules: ["@mod/seal", "@mod/log-stdout"], workspace: root });
	await linked(target);
	const key = Buffer.from(Array.from({ length: 32 }, (_, i) => i * 7 + 1)).toString("base64");
	await writeFile(
		join(target, "config", "seal.conf"),
		JSON.stringify({ seal: { current: { id: "now", key } } }),
	);
	await writeFile(
		join(target, "config", "local.conf"),
		await trialLayer(target, { redisUrl: "redis://127.0.0.1:1", leave: ["seal"] }),
	);
	const run = (legacy: Record<string, string>) =>
		spawnSync(process.execPath, ["src/reseal.ts"], {
			cwd: target,
			env: {
				...process.env,
				KERNEL_DEPLOYMENT: "single",
				APP_CONFIG: "config/seal.conf,config/local.conf,config/application.conf",
				...legacy,
			},
			encoding: "utf8",
		});
	const left = run({ OAUTH_ACCESS_TOKEN_EXPIRES_IN: "61937", CORE_DEPLOYMENT_MODE: "multi-q7" });
	expect(left.status).toBe(0);
	const warned = left.stderr.split("\n").filter((line) => line.startsWith("warn "));
	expect(warned).toEqual([
		"warn config-files: 2 variables named in 0.17 are set and never read: CORE_DEPLOYMENT_MODE, OAUTH_ACCESS_TOKEN_EXPIRES_IN; see docs/migration.md",
	]);
	expect(`${left.stdout}${left.stderr}`).not.toMatch(/61937|multi-q7/);
	expect(run({}).stderr).not.toMatch(/^warn /m);
});

it("links each dependency to the workspace when given one, and refuses a module it does not hold", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-"));
	await generate({ target, modules: ["@mod/log-stdout"], workspace: root });
	const manifest = JSON.parse(await readFile(join(target, "package.json"), "utf8"));
	expect(manifest.dependencies).toEqual({
		"@mod/kernel": `link:${join(root, "modules", "foundation", "kernel")}`,
		"@mod/config-files": `link:${join(root, "modules", "foundation", "config-files")}`,
		"@mod/log-stdout": `link:${join(root, "modules", "log-sinks", "log-stdout")}`,
		zod: "4.6.7",
	});
	const elsewhere = await mkdtemp(join(tmpdir(), "create-app-"));
	await expect(
		generate({ target: elsewhere, modules: ["@mod/nowhere"], workspace: root }),
	).rejects.toThrow("@mod/nowhere: not in the workspace");
});

it("starts on the configuration files APP_CONFIG lists, and exits 78 telling each refusal", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-"));
	await generate({ target, modules: ["@mod/log-stdout"], workspace: root });
	await linked(target);
	const run = (env: Record<string, string>) =>
		spawnSync(process.execPath, ["src/main.ts"], {
			cwd: target,
			env: { ...process.env, ...env },
			encoding: "utf8",
		});
	// The generated file holds no value: the kernel's deployment is read from the environment.
	expect(run({}).status).toBe(78);
	expect(run({ KERNEL_DEPLOYMENT: "single" }).status).toBe(0);
	const refused = run({
		KERNEL_DEPLOYMENT: "single",
		APP_CONFIG: "config/application.conf,missing.conf",
	});
	expect(refused.status).toBe(78);
	expect(refused.stderr).toMatch(/^refused missing\.conf: /m);
});

/** A module whose start takes a second, saying when it begins, ends and stops. */
const slowModule = `import { contract, defineModule } from "@mod/kernel";
const slow = contract("test.slow");
export default defineModule({ name: "slow", takes: [] }, (m) => [
	m.provide(slow).by((c) => {
		c.onStart(async () => {
			process.stdout.write("starting\\n");
			await new Promise((r) => setTimeout(r, 1000));
			process.stdout.write("started\\n");
		});
		c.onStop(() => {
			process.stdout.write("stopped\\n");
		});
		return {};
	}),
]);
`;

it("stops once started on a SIGTERM that comes while it starts, instead of being killed by it", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-"));
	await generate({ target, modules: ["@mod/log-stdout"], workspace: root });
	await mkdir(join(target, "node_modules", "@mod"), { recursive: true });
	await mkdir(join(target, "node_modules", "@test"), { recursive: true });
	for (const [name, dir] of [
		["kernel", "foundation/kernel"],
		["config-files", "foundation/config-files"],
		["log-stdout", "log-sinks/log-stdout"],
	]) {
		await symlink(
			join(root, "modules", dir as string),
			join(target, "node_modules", "@mod", name as string),
		);
	}
	// Beside the app, not under node_modules, as a workspace link would be.
	await mkdir(join(target, "slow"));
	await writeFile(join(target, "slow", "module.js"), slowModule);
	await writeFile(
		join(target, "slow", "package.json"),
		JSON.stringify({ name: "@test/slow", type: "module", exports: { "./module": "./module.js" } }),
	);
	await symlink(join(target, "slow"), join(target, "node_modules", "@test", "slow"));
	await writeFile(
		join(target, "src", "main.ts"),
		await mainSource(["@mod/log-stdout", "@test/slow"]),
	);
	const child = spawn(process.execPath, ["src/main.ts"], {
		cwd: target,
		env: { ...process.env, KERNEL_DEPLOYMENT: "single" },
	});
	let output = "";
	const exited = new Promise<[number | null, string | null]>((resolve) =>
		child.once("exit", (code, signal) => resolve([code, signal])),
	);
	child.stdout.on("data", (chunk) => {
		output += chunk;
		if (output === "starting\n") child.kill("SIGTERM");
	});
	child.stderr.on("data", (chunk) => {
		output += chunk;
	});
	expect(await exited, output).toEqual([0, null]);
	expect(output.split("\n").filter((line) => !line.startsWith("{"))).toEqual([
		"starting",
		"started",
		"stopped",
		"",
	]);
});

it("makes an app from the command naming session by its default, with session's bridges", async () => {
	const target = join(await mkdtemp(join(tmpdir(), "create-app-")), "app");
	const out: string[] = [];
	const io = { out: (text: string) => out.push(text), err: () => {} };
	expect(await run([target, "@mod/session-lifecycle", "@mod/tokens", "@mod/code-grant"], io)).toBe(
		0,
	);
	// A listed app holds what its modules need, and its guide tells the settings.
	expect(out.join("")).toBe(`created ${target}\nnext: cd ${target} and follow its README.md\n`);
	const imported = await importedModules(target);
	expect(imported).toContain("@mod/session-tokens");
	expect(imported).not.toContain("@mod/session");
});

it("runs the command on given arguments, answering a usage error as 64 and writing nothing", async () => {
	const said: string[] = [];
	const io = { out: (text: string) => said.push(text), err: (text: string) => said.push(text) };
	expect(await run([], io)).toBe(64);
	expect(said.join("")).toContain("usage: create-auth-provider <target>");
});

it("refuses an empty name in a group's list as a usage error, and answers a plan it cannot make as 1 with its reason", async () => {
	const err: string[] = [];
	const io = { out: () => {}, err: (text: string) => err.push(text) };
	const target = join(await mkdtemp(join(tmpdir(), "create-app-")), "app");
	for (const args of [
		[target, "--pattern", "a2a", "--binding", ""],
		[target, "--pattern", "a2a", "--login", "@mod/login-password,"],
	]) {
		err.length = 0;
		expect(await run(args, io), args.join(" ")).toBe(64);
		expect(err.join(""), args.join(" ")).toContain("usage: create-auth-provider <target>");
	}
	err.length = 0;
	expect(await run([target, "--pattern", "no-such-pattern"], io)).toBe(1);
	expect(err.join("")).toMatch(/no-such-pattern/);
	expect(err.join("")).not.toMatch(/\n\s+at /);
});

it("answers --help with the usage on standard output, and an option it does not know as a usage error", async () => {
	const [out, err]: [string[], string[]] = [[], []];
	const io = { out: (text: string) => out.push(text), err: (text: string) => err.push(text) };
	expect(await run(["--help"], io)).toBe(0);
	expect(out.join("")).toContain("usage: create-auth-provider <target>");
	for (const args of [
		["app", "--nope"],
		["app", "--pattern"],
	]) {
		err.length = 0;
		expect(await run(args, io), args.join(" ")).toBe(64);
		expect(err.join(""), args.join(" ")).toMatch(
			/^.*'--(nope|pattern).*\nusage: create-auth-provider <target>/s,
		);
	}
});

it("answers --list with what --add takes, one name a line, writing nothing", async () => {
	const [out, err]: [string[], string[]] = [[], []];
	const io = { out: (text: string) => out.push(text), err: (text: string) => err.push(text) };
	expect(await run(["--list"], io)).toBe(0);
	expect(out.join("")).toBe(`${addable().join("\n")}\n`);
	expect(addable()).toContain("@mod/dpop");
	expect(err).toEqual([]);
	expect(await run(["--list", "app"], io)).toBe(64);
	expect(out.join("")).not.toContain("created");
	const [help] = [[] as string[]];
	await run(["--help"], { out: (text) => help.push(text), err: () => {} });
	expect(help.join("")).toContain("create-auth-provider --list");
});
