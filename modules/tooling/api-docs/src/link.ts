import { existsSync, mkdirSync, readdirSync, readFileSync, symlinkSync } from "node:fs";
import { dirname, join } from "node:path";
import { scope } from "./entries.ts";

/** The first workspace member, in path order, that holds an outside package installed. */
function heldBy(repo: string, name: string): string | undefined {
	const modules = join(repo, "modules");
	for (const concern of readdirSync(modules, { withFileTypes: true }).filter((e) =>
		e.isDirectory(),
	)) {
		const members = readdirSync(join(modules, concern.name), { withFileTypes: true })
			.filter((e) => e.isDirectory())
			.map((e) => e.name)
			.sort();
		for (const member of members) {
			const held = join(modules, concern.name, member, "node_modules", name);
			if (existsSync(join(held, "package.json"))) return held;
		}
	}
	return undefined;
}

const link = (target: string, at: string) => {
	if (existsSync(at)) return;
	mkdirSync(dirname(at), { recursive: true });
	symlinkSync(target, at, "dir");
};

/**
 * Makes a project of the bundles built here (`pnpm bundles`) as a release installs them: each
 * bundle at its public name, and each outside package its manifest names from a workspace member
 * that holds it. For a check before a release; a release's site reads what npm installs.
 */
export function linkBuilt(options: {
	readonly bundles: string;
	readonly repo: string;
	readonly project: string;
}): void {
	const { bundles, repo, project } = options;
	const outside = new Set<string>();
	for (const dir of readdirSync(bundles).sort()) {
		const path = join(bundles, dir, "package.json");
		if (!existsSync(path)) continue;
		const manifest = JSON.parse(readFileSync(path, "utf8")) as {
			readonly name: string;
			readonly dependencies?: Record<string, string>;
			readonly peerDependencies?: Record<string, string>;
		};
		link(join(bundles, dir), join(project, "node_modules", manifest.name));
		for (const name of Object.keys({ ...manifest.dependencies, ...manifest.peerDependencies })) {
			if (!name.startsWith(`${scope}/`)) outside.add(name);
		}
	}
	for (const name of [...outside].sort()) {
		const held = heldBy(repo, name);
		if (held !== undefined) link(held, join(project, "node_modules", name));
	}
}
