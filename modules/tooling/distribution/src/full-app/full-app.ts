/**
 * The app of the release with the most packages: its packed entrance installed from the tarballs
 * alone, and the full template with every feature that opts in made by it. Nothing installed runs.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { optIns } from "@mod/combinations";
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
		[app, "--pattern", "full", ...optIns().flatMap((name) => ["--add", name])],
		{ stdio: "pipe" },
	);
	return { entrance: tool, app };
}
