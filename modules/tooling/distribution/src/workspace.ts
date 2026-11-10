import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { Release } from "./publish.ts";

/** The repository URL the workspace's package.json states, as a string or as `{ url }`. */
export function repositoryOf(workspace: { readonly repository?: unknown }): string | undefined {
	const stated = workspace.repository;
	if (typeof stated === "string") return stated;
	const url = (stated as { url?: unknown } | undefined)?.url;
	return typeof url === "string" ? url : undefined;
}

/** The root README's copyright and license line, closing each package's README; none without one. */
export function noticeIn(root: string): string | undefined {
	const readme = join(root, "README.md");
	if (!existsSync(readme)) return undefined;
	return readFileSync(readme, "utf8")
		.split("\n")
		.find((line) => line.startsWith("Copyright ") && line.includes("Apache License"));
}

/** What every package of the release carries, as the workspace at `root` states it; none without a version. */
export function releaseOf(root: string): Release | undefined {
	const workspace = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
	if (typeof workspace.version !== "string") return undefined;
	const repository = repositoryOf(workspace);
	const notice = noticeIn(root);
	return {
		version: workspace.version,
		...(workspace.engines ? { engines: workspace.engines } : {}),
		...(typeof workspace.license === "string" ? { license: workspace.license } : {}),
		...(repository ? { repository } : {}),
		...(notice ? { notice } : {}),
		...(Array.isArray(workspace.keywords) ? { keywords: workspace.keywords } : {}),
	};
}

export interface Member {
	readonly name: string;
	readonly dir: string;
	readonly dependencies: readonly string[];
}

export interface Bundle {
	readonly dir: string;
	readonly shipped: boolean | undefined;
	readonly members: readonly Member[];
}

/** Whether the bundle manifest in `dir` ships the bundle; undefined when it is missing or unreadable. */
function shippedOf(dir: string): boolean | undefined {
	try {
		return JSON.parse(readFileSync(join(dir, "package.json"), "utf8")).private === false;
	} catch {
		return undefined;
	}
}

/** Bundles are the parent directories of the packages the workspace definition places. */
export function readBundles(root: string): Bundle[] {
	const listed = JSON.parse(
		execFileSync("pnpm", ["ls", "-r", "--json", "--depth", "-1"], { cwd: root, encoding: "utf8" }),
	) as { name: string; path: string }[];
	const groups = Map.groupBy(
		listed.filter((entry) => entry.path !== root),
		(entry) => dirname(entry.path),
	);
	return [...groups].map(([dir, entries]) => {
		return {
			dir,
			shipped: shippedOf(dir),
			members: entries.map((entry) => ({
				name: entry.name,
				dir: entry.path,
				dependencies: Object.keys(
					JSON.parse(readFileSync(join(entry.path, "package.json"), "utf8")).dependencies ?? {},
				),
			})),
		};
	});
}
