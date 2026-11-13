/**
 * The app of the release with the most packages: its packed entrance installed from the tarballs
 * alone, and the full template with every feature that release opts in made by it. Of what is
 * installed, no install script runs; the entrance and its `combinations` do.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { overridesFile } from "../release-check/image.ts";

export const entrance = "@o3co/create-auth-provider";

/** Installs the project in `dir` from the tarballs alone (`byName`), no script run. */
export function installFromTarballs(dir: string, byName: Readonly<Record<string, string>>) {
	writeFileSync(join(dir, "pnpm-workspace.yaml"), overridesFile(byName));
	execFileSync(
		"pnpm",
		["install", "--prefer-offline", "--no-frozen-lockfile", "--ignore-scripts"],
		{ cwd: dir, stdio: ["ignore", "ignore", "inherit"] },
	);
}

/**
 * The features that opt in, as the release installed in `project` tells them: the `combinations`
 * of the bundle its entrance depends on, so the tarballs, not this workspace, choose them.
 */
export function releaseOptIns(project: string): string[] {
	const installed = realpathSync(join(project, "node_modules", entrance));
	const manifest = JSON.parse(readFileSync(join(installed, "package.json"), "utf8")) as {
		readonly dependencies?: Readonly<Record<string, string>>;
	};
	const bundles = Object.keys(manifest.dependencies ?? {});
	if (bundles.length !== 1)
		throw new Error(`${entrance} depends on ${bundles.length} packages, not its bundle alone`);
	const told = execFileSync(
		process.execPath,
		[
			"--input-type=module",
			"--eval",
			`const { optIns } = await import(${JSON.stringify(`${bundles[0]}/combinations`)});
process.stdout.write(JSON.stringify(optIns()));`,
		],
		{ cwd: installed, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] },
	);
	const names: unknown = JSON.parse(told);
	if (!Array.isArray(names) || !names.every((name) => typeof name === "string"))
		throw new Error("the release's opt-ins are not a list of names");
	return names;
}

/**
 * Makes into `scratch` the entrance's project (`entrance`) and the app (`app`); refused where the
 * tarballs hold no entrance.
 */
export function fullApp(
	byName: Readonly<Record<string, string>>,
	scratch: string,
): { readonly entrance: string; readonly app: string } {
	const tarball = byName[entrance];
	if (!tarball) throw new Error(`no ${entrance} tarball among the tarballs`);
	const tool = join(scratch, "entrance");
	mkdirSync(tool);
	writeFileSync(
		join(tool, "package.json"),
		JSON.stringify({
			name: "entrance",
			private: true,
			dependencies: { [entrance]: `file:${tarball}` },
		}),
	);
	installFromTarballs(tool, byName);
	const app = join(scratch, "app");
	execFileSync(
		join(tool, "node_modules", ".bin", "create-auth-provider"),
		[app, "--pattern", "full", ...releaseOptIns(tool).flatMap((name) => ["--add", name])],
		{ stdio: "pipe" },
	);
	return { entrance: tool, app };
}
