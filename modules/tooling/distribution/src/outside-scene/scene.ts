/** A package outside the release composed as an operator does, from a registry, held to what the release sealed. */
import { execFileSync, spawn } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { swappedZod } from "./swap.ts";

const grant = "@x/release-check-grant";

/** Runs a command in `cwd`, answering its exit status, its standard output, and all it said. */
const ran = (command: string, args: readonly string[], cwd: string) => {
	try {
		const stdout = execFileSync(command, args, { cwd, encoding: "utf8", stdio: "pipe" });
		return { status: 0, stdout, said: stdout };
	} catch (error) {
		const told = error as { status?: number; stdout?: string; stderr?: string; message: string };
		const stdout = told.stdout ?? "";
		return {
			status: told.status ?? 1,
			stdout,
			said: `${stdout}${told.stderr ?? ""}${told.message}`,
		};
	}
};
const must = (command: string, args: readonly string[], cwd: string) => {
	const { status, said } = ran(command, args, cwd);
	if (status !== 0) throw new Error(`${command} ${args.join(" ")}: ${said}`);
};

/** A package outside the release, needing a module of the release and taking its bundle and zod as peers. */
function packOutside(dir: string, into: string, version: string, zod: string) {
	mkdirSync(dir, { recursive: true });
	writeFileSync(
		join(dir, "package.json"),
		JSON.stringify({
			name: grant,
			version: "1.0.0",
			type: "module",
			exports: { "./module": "./module.js" },
			peerDependencies: { "@o3co/auth-provider-oauth": `^${version}`, zod: `^${zod}` },
			authProvider: { format: 1, kind: "feature", needs: ["@mod/tokens"] },
		}),
	);
	writeFileSync(join(dir, "module.js"), "export default {};\n");
	writeFileSync(join(dir, "config.example"), 'grant {\n\tissuer = "REPLACE-ISSUER"\n}\n');
	writeFileSync(
		join(dir, "README.md"),
		"# release-check-grant\n\nA package of the release check.\n",
	);
	must("pnpm", ["pack", "--pack-destination", into], dir);
}

/** Starts the registry over the directories, before the upstream's, answering its origin and how to stop it. */
function served(upstream: string, dirs: readonly string[]) {
	const child = spawn("node", [join(import.meta.dirname, "registry.ts"), upstream, ...dirs], {
		stdio: ["ignore", "pipe", "inherit"],
	});
	const origin = new Promise<string>((resolve, reject) => {
		let said = "";
		child.stdout.on("data", (chunk: Buffer) => {
			said += chunk.toString();
			if (said.includes("\n")) resolve(said.trim());
		});
		child.on("exit", (code) => reject(new Error(`the registry exited ${code}`)));
	});
	return { origin, stop: () => child.kill() };
}

/**
 * Serves the release's tarballs and a package outside it from a registry of its own; installs
 * `create-auth-provider` and, into a project of its own, the package from it; generates an app of
 * the pattern adding it; installs the app as published, by version; and runs its `check:outside`,
 * which must pass. Then points the lockfile's zod at another package's tarball on zod's registry,
 * and the check must refuse it for the integrity the release recorded, and for that alone.
 */
export async function outsideScene(options: {
	readonly tarballs: string;
	readonly scratch: string;
	readonly version: string;
	readonly zod: string;
	readonly pattern: string;
}): Promise<string> {
	const at = (dir: string) => {
		const path = join(options.scratch, dir);
		mkdirSync(path, { recursive: true });
		return path;
	};
	const outside = at("outside-tarballs");
	packOutside(at("outside-package"), outside, options.version, options.zod);
	const upstream = execFileSync("pnpm", ["config", "get", "registry"], {
		cwd: options.scratch,
		encoding: "utf8",
	}).trim();
	const registry = served(upstream.endsWith("/") ? upstream : `${upstream}/`, [
		options.tarballs,
		outside,
	]);
	try {
		const origin = await registry.origin;
		const npmrc = `@o3co:registry=${origin}/\n@x:registry=${origin}/\n`;
		const project = (dir: string) => {
			const path = at(dir);
			writeFileSync(join(path, ".npmrc"), npmrc);
			writeFileSync(join(path, "package.json"), JSON.stringify({ name: dir, private: true }));
			return path;
		};
		const tool = project("outside-tool");
		must("pnpm", ["add", `@o3co/create-auth-provider@${options.version}`], tool);
		const staging = project("outside-staging");
		must("pnpm", ["add", `${grant}@1.0.0`], staging);
		const app = join(options.scratch, "outside-app");
		must(
			join(tool, "node_modules", ".bin", "create-auth-provider"),
			[app, "--pattern", options.pattern, "--add", `npm:${grant}`, "--outside-from", staging],
			options.scratch,
		);
		writeFileSync(join(app, ".npmrc"), npmrc);
		must("pnpm", ["install"], app);
		must("pnpm", ["check:outside"], app);

		const record = JSON.parse(readFileSync(join(app, "outside-modules.json"), "utf8")) as {
			registries: { default: string };
			held: Record<string, string>;
		};
		const lockfile = join(app, "pnpm-lock.yaml");
		const swapped = swappedZod(readFileSync(lockfile, "utf8"), record.registries.default);
		if ("problem" in swapped) throw new Error(swapped.problem);
		writeFileSync(lockfile, swapped.text);
		const refused = ran("pnpm", ["--silent", "check:outside"], app);
		const expected = `zod: integrity ${swapped.integrity}, not ${record.held.zod} as the release recorded\ncheck:outside: 1 refusal(s)\n`;
		if (refused.status !== 1 || refused.stdout !== expected) {
			throw new Error(
				`a zod pointed at another tarball was not refused for its integrity alone: ${refused.said}`,
			);
		}
		return "generated from a registry, installed by version and checked; zod pointed elsewhere refused";
	} finally {
		registry.stop();
	}
}
