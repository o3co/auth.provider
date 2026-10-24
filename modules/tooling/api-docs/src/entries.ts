import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** The scope the shipped bundles are published under. */
export const scope = "@o3co";

/** The manifests of the scope's packages a project holds, each with its dir. */
export function bundlesIn(project: string) {
	const at = join(project, "node_modules", scope);
	if (!existsSync(at)) return [];
	return readdirSync(at)
		.map((dir) => join(at, dir))
		.filter((dir) => existsSync(join(dir, "package.json")))
		.map((dir) => ({
			dir,
			manifest: JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as {
				readonly name: string;
				readonly private?: boolean;
				readonly exports?: Record<string, unknown>;
				readonly dependencies?: Record<string, string>;
				readonly peerDependencies?: Record<string, string>;
			},
		}));
}

/**
 * The public names of each member's contract the shipped bundles offer: `<bundle>/<member>`, the
 * member's `.`. Its `testing`, `module` and `audit-events` are not the contract, and an unshipped
 * bundle is read by nobody.
 */
export function entriesOf(project: string): string[] {
	return bundlesIn(project)
		.filter(({ manifest }) => manifest.private !== true)
		.flatMap(({ manifest }) =>
			Object.keys(manifest.exports ?? {})
				.filter((key) => /^\.\/[^/]+$/.test(key))
				.map((key) => `${manifest.name}/${key.slice(2)}`),
		)
		.sort();
}
