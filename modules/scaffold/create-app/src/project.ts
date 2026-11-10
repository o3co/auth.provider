/** The workspace's packages, and the app's dependencies on them. */
import { workspacePackages } from "@mod/workspace-packages";

/** Package directories by name, as the workspace definition places them. */
export function packageDirsIn(root: string): Map<string, string> {
	return new Map(workspacePackages(root).map((p) => [p.name, p.dir]));
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
