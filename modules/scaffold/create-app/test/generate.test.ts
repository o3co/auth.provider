import { spawn, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readdir, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { completed } from "@mod/combinations";
import { kernelConfig } from "@mod/kernel";
import { expect, it, vi } from "vitest";
import { generate, run } from "../src/contract.ts";
import { mainSource } from "../src/project.ts";
import { importedModules, linked, root } from "./full-app.ts";

// These tests read the whole workspace, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

it("assembles the modules asked for, with the wirings and bridges they come with by default", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-"));
	await generate({ target, modules: ["@mod/session", "@mod/tokens", "@mod/code-grant"] });
	const imported = await importedModules(target);
	// The modules asked for first, session as the default that replaces it, then what combinations
	// completes them with, whatever that is.
	const completedList = completed(["@mod/session", "@mod/tokens", "@mod/code-grant"]);
	expect(completedList.slice(0, 3)).toEqual([
		"@mod/session-lifecycle",
		"@mod/tokens",
		"@mod/code-grant",
	]);
	expect(completedList.length).toBeGreaterThan(3);
	// Then the log sink, the default one when the plan names none.
	const expected = [...completedList, "@mod/log-stdout"];
	expect(imported).toEqual(expected);
	const manifest = JSON.parse(await readFile(join(target, "package.json"), "utf8"));
	expect(Object.keys(manifest.dependencies)).toEqual(["@mod/kernel", ...expected]);
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
			".gitignore",
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

it("writes the kernel's configuration, a start script and what git leaves out", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-"));
	await generate({ target, modules: ["@mod/http"] });
	const config = JSON.parse(await readFile(join(target, "config", "application.conf"), "utf8"));
	expect(config).toEqual(kernelConfig());
	const manifest = JSON.parse(await readFile(join(target, "package.json"), "utf8"));
	expect([manifest.private, manifest.type, manifest.scripts]).toEqual([
		true,
		"module",
		{ start: "node src/main.ts" },
	]);
	const ignored = (await readFile(join(target, ".gitignore"), "utf8")).split("\n");
	expect(ignored).toEqual(["node_modules/", "config/local*.conf", ""]);
	await expect(readFile(join(target, "src", "reseal.ts"), "utf8")).rejects.toThrow();
});

it("writes a reseal script for an app that seals, which seals again through each holder and tells the counts", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-"));
	await generate({ target, modules: ["@mod/seal", "@mod/log-stdout"], workspace: root });
	const manifest = JSON.parse(await readFile(join(target, "package.json"), "utf8"));
	expect(manifest.scripts).toEqual({ start: "node src/main.ts", reseal: "node src/reseal.ts" });
	// Stopped before it exits, so the stop hooks run (connections closed, buffered log lines out).
	expect(await readFile(join(target, "src", "reseal.ts"), "utf8")).toMatch(/await app\.stop\(\)/);
	await linked(target);
	const key = Buffer.from(Array.from({ length: 32 }, (_, i) => i * 7 + 1)).toString("base64");
	await writeFile(
		join(target, "config", "seal.conf"),
		JSON.stringify({ seal: { current: { id: "now", key } } }),
	);
	const reseal = (files: string) =>
		spawnSync(process.execPath, ["src/reseal.ts"], {
			cwd: target,
			env: { ...process.env, APP_CONFIG: files },
			encoding: "utf8",
		});
	const done = reseal("config/application.conf,config/seal.conf");
	expect([done.status, done.stdout]).toEqual([0, ""]);
	expect(reseal("config/application.conf").status).toBe(78);
});

it("links each dependency to the workspace when given one, and refuses a module it does not hold", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-"));
	await generate({ target, modules: ["@mod/log-stdout"], workspace: root });
	const manifest = JSON.parse(await readFile(join(target, "package.json"), "utf8"));
	expect(manifest.dependencies).toEqual({
		"@mod/kernel": `link:${join(root, "modules", "foundation", "kernel")}`,
		"@mod/log-stdout": `link:${join(root, "modules", "log-sinks", "log-stdout")}`,
	});
	const elsewhere = await mkdtemp(join(tmpdir(), "create-app-"));
	await expect(
		generate({ target: elsewhere, modules: ["@mod/nowhere"], workspace: root }),
	).rejects.toThrow("@mod/nowhere is not in the workspace");
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
	expect(run({}).status).toBe(0);
	const refused = run({ APP_CONFIG: "config/application.conf,missing.conf" });
	expect(refused.status).toBe(78);
	expect(refused.stderr).toMatch(/^refused missing\.conf: /m);
});

/** A module whose start takes a second, saying when it begins, ends and stops. */
const slowModule = `import { contract, defineModule } from "@mod/kernel";
const slow = contract("test.slow");
export default defineModule({ name: "slow" }, (m) => [
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
	const child = spawn(process.execPath, ["src/main.ts"], { cwd: target });
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
	const io = { out: () => {}, err: () => {} };
	expect(await run([target, "@mod/session-lifecycle", "@mod/tokens", "@mod/code-grant"], io)).toBe(
		0,
	);
	const imported = await importedModules(target);
	expect(imported).toContain("@mod/session-tokens");
	expect(imported).not.toContain("@mod/session");
});

it("runs the command on given arguments, answering a usage error as 64 and writing nothing", async () => {
	const said: string[] = [];
	const io = { out: (text: string) => said.push(text), err: (text: string) => said.push(text) };
	expect(await run([], io)).toBe(64);
	expect(said.join("")).toContain("usage: create-app <target>");
});

it("answers --help with the usage on standard output, and an option it does not know as a usage error", async () => {
	const [out, err]: [string[], string[]] = [[], []];
	const io = { out: (text: string) => out.push(text), err: (text: string) => err.push(text) };
	expect(await run(["--help"], io)).toBe(0);
	expect(out.join("")).toContain("usage: create-app <target>");
	for (const args of [
		["app", "--nope"],
		["app", "--pattern"],
	]) {
		err.length = 0;
		expect(await run(args, io), args.join(" ")).toBe(64);
		expect(err.join(""), args.join(" ")).toMatch(
			/^.*'--(nope|pattern).*\nusage: create-app <target>/s,
		);
	}
});
