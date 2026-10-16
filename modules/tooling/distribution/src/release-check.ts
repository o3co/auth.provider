import { execFileSync, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { patterns, trialSettings } from "@mod/create-app";
import { buildBundles } from "./build.ts";
import { readBundles } from "./contract.ts";
import { refusalsIn } from "./refused.ts";
import { releaseOf } from "./workspace.ts";

/**
 * Checks the release as an operator meets it: every bundle packed, an app of each pattern made by
 * the packed create-auth-provider, installed from the tarballs alone, its entry type-checked, and
 * booted on trial settings to readiness, or to its refusals where it needs a Redis it cannot reach.
 */
const root = process.env.INIT_CWD ?? process.cwd();
const workspace = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const out = join(root, "dist", "bundles");
const say = (text: string) => process.stdout.write(`${text}\n`);
const problems: string[] = [];

const { problems: unbuilt } = buildBundles({
	bundles: readBundles(root),
	release: releaseOf(root) ?? { version: workspace.version },
	out,
	licenseFile: join(root, "LICENSE"),
});
if (unbuilt.length > 0) {
	for (const problem of unbuilt) console.error(problem);
	process.exit(1);
}

const scratch = mkdtempSync(join(tmpdir(), "release-check-"));
const tarballs = join(scratch, "tarballs");
mkdirSync(tarballs);
const overrides: Record<string, string> = {};
for (const dir of readdirSync(out)) {
	const { name } = JSON.parse(readFileSync(join(out, dir, "package.json"), "utf8"));
	const packed = execFileSync("pnpm", ["pack", "--pack-destination", tarballs], {
		cwd: join(out, dir),
		encoding: "utf8",
	})
		.trim()
		.split("\n")
		.findLast((line) => line.endsWith(".tgz"));
	if (!packed) throw new Error(`${name}: pnpm pack named no tarball`);
	const tarball = packed.startsWith("/") ? packed : join(tarballs, packed);
	// npm and pnpm alike ship what the tarball holds: the license must be in it.
	const held = execFileSync("tar", ["-tzf", tarball], { encoding: "utf8" }).split("\n");
	if (!held.includes("package/LICENSE")) problems.push(`${name}: its tarball holds no LICENSE`);
	overrides[name] = `file:${tarball}`;
}
say(`packed ${Object.keys(overrides).length}`);

/** A project installing from the tarballs alone; any outside package comes from the store first. */
const install = (dir: string) => {
	writeFileSync(
		join(dir, "pnpm-workspace.yaml"),
		`overrides:\n${Object.entries(overrides)
			.map(([name, spec]) => `  "${name}": "${spec}"`)
			.join("\n")}\n`,
	);
	execFileSync("pnpm", ["install", "--prefer-offline", "--no-frozen-lockfile"], {
		cwd: dir,
		stdio: "pipe",
	});
};

const tool = join(scratch, "tool");
mkdirSync(tool);
const entrance = "@o3co/create-auth-provider";
writeFileSync(
	join(tool, "package.json"),
	JSON.stringify({
		name: "release-check-tool",
		private: true,
		dependencies: { [entrance]: overrides[entrance] },
	}),
);
install(tool);

const freePort = () =>
	new Promise<number>((resolve) => {
		const server = createServer();
		server.listen(0, "127.0.0.1", () => {
			const { port } = server.address() as { port: number };
			server.close(() => resolve(port));
		});
	});

/** Boots the app: ready at /readyz, or refused (exit 78) with every refusal it wrote; anything else fails. */
async function booted(app: string): Promise<string> {
	const port = await freePort();
	const { env, local } = await trialSettings(app, { redisUrl: "redis://127.0.0.1:1", port });
	writeFileSync(join(app, "config", "local.conf"), local);
	const child = spawn(process.execPath, ["src/main.ts"], {
		cwd: app,
		env: {
			...env,
			PATH: process.env.PATH ?? "",
			APP_CONFIG: "config/local.conf,config/application.conf",
		},
	});
	let output = "";
	child.stdout.on("data", (chunk) => {
		output += chunk;
	});
	child.stderr.on("data", (chunk) => {
		output += chunk;
	});
	const exited = new Promise<number | null>((resolve) =>
		child.once("exit", (code) => resolve(code)),
	);
	for (let waited = 0; waited < 60_000; waited += 250) {
		if (child.exitCode !== null) break;
		const ready = await fetch(`http://127.0.0.1:${port}/readyz`).then(
			(answer) => answer.status === 200,
			() => false,
		);
		if (ready) {
			child.kill("SIGTERM");
			await exited;
			return "ready";
		}
		await new Promise((resolve) => setTimeout(resolve, 250));
	}
	child.kill("SIGKILL");
	const code = await exited;
	const refusals = refusalsIn(output);
	if (code === 78 && refusals.length > 0) return `refused: ${refusals.join("; ")}`;
	throw new Error(`exited ${code}:\n${output}`);
}

const tsc = join(root, "node_modules", ".bin", "tsc");
for (const name of patterns().map((pattern) => pattern.name)) {
	const app = join(scratch, `app-${name}`);
	try {
		execFileSync(
			join(tool, "node_modules", ".bin", "create-auth-provider"),
			[app, "--pattern", name],
			{
				stdio: "pipe",
			},
		);
		install(app);
		execFileSync(
			tsc,
			[
				"--noEmit",
				"--strict",
				"--target",
				"es2024",
				"--module",
				"nodenext",
				"--moduleResolution",
				"nodenext",
				"--allowImportingTsExtensions",
				"--skipLibCheck",
				"--types",
				"node",
				"--typeRoots",
				join(root, "node_modules", "@types"),
				"src/main.ts",
			],
			{ cwd: app, stdio: "pipe" },
		);
		say(`${name}: ${await booted(app)}`);
	} catch (error) {
		const told = error as { stdout?: Buffer; stderr?: Buffer; message: string };
		problems.push(`${name}: ${told.stdout ?? ""}${told.stderr ?? ""}${told.message}`);
		say(`${name}: failed`);
	}
}

for (const problem of problems) console.error(problem);
say(problems.length === 0 ? `release: ok (${scratch})` : `release: ${problems.length}`);
process.exit(problems.length === 0 ? 0 : 1);
