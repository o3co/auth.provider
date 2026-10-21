/** The workspace's packages, as the workspace definition places them. */
import { execFileSync } from "node:child_process";

/** Package directories by name. */
export function workspacePackages(root: string): Map<string, string> {
	const listed = JSON.parse(
		execFileSync("pnpm", ["ls", "-r", "--json", "--depth", "-1"], { cwd: root, encoding: "utf8" }),
	) as { name: string; path: string }[];
	return new Map(listed.map((entry) => [entry.name, entry.path]));
}
