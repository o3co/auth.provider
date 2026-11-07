import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";

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

export function check(bundles: readonly Bundle[]): string[] {
	const problems: string[] = [];
	const bundleOf = new Map(bundles.flatMap((b) => b.members.map((m) => [m.name, b] as const)));
	const edges = new Map(
		bundles.map((b) => [
			b,
			new Set(
				b.members
					.flatMap((m) => m.dependencies.map((d) => bundleOf.get(d)))
					.filter((d): d is Bundle => d !== undefined && d !== b),
			),
		]),
	);
	for (const bundle of bundles) {
		if (bundle.shipped === undefined) problems.push(`${bundle.dir}: bundle manifest is missing`);
		for (const dep of edges.get(bundle) ?? []) {
			if (bundle.shipped && dep.shipped === false) {
				problems.push(`${bundle.dir}: depends on unshipped bundle ${dep.dir}`);
			}
		}
	}
	const state = new Map<Bundle, "open" | "done">();
	const visit = (bundle: Bundle, path: readonly Bundle[]): void => {
		if (state.get(bundle) === "open") {
			problems.push(`bundle cycle: ${[...path, bundle].map((b) => b.dir).join(" → ")}`);
			return;
		}
		if (state.get(bundle) === "done") return;
		state.set(bundle, "open");
		for (const dep of edges.get(bundle) ?? []) visit(dep, [...path, bundle]);
		state.set(bundle, "done");
	};
	for (const bundle of bundles) visit(bundle, []);
	return problems;
}
