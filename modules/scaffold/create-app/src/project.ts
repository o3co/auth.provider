/** The workspace's packages, and the app's dependencies on them. */
import { execFileSync } from "node:child_process";

/** Package directories by name, as the workspace definition places them. */
export function workspacePackages(root: string): Map<string, string> {
	const listed = JSON.parse(
		execFileSync("pnpm", ["ls", "-r", "--json", "--depth", "-1"], { cwd: root, encoding: "utf8" }),
	) as { name: string; path: string }[];
	return new Map(listed.map((entry) => [entry.name, entry.path]));
}

/** Each name's dependency: a link to its workspace directory when given a workspace, else any version. */
export function dependenciesOf(
	names: readonly string[],
	known: ReadonlyMap<string, string> | undefined,
): Record<string, string> {
	const dependencies: Record<string, string> = {};
	for (const name of names) {
		const dir = known?.get(name);
		if (known && !dir) throw new Error(`${name} is not in the workspace`);
		dependencies[name] = dir ? `link:${dir}` : "*";
	}
	return dependencies;
}
