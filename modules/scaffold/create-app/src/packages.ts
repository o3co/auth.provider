import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
	type Ask,
	type Asked,
	type Card,
	fragmentsIn,
	fragmentsOf,
	type Packages,
} from "@mod/app-output";
import type { Outside, Read } from "./outside/contract.ts";
import { dependenciesOf, workspacePackages } from "./project.ts";

/** Where an entry's files lie in the app: under `node_modules`, the entry's own path. */
const installed = (
	entry: string,
	ships: { readonly references: boolean; readonly deployment: boolean },
): Omit<Card, "name"> => ({
	card: `node_modules/${entry}/README.md`,
	...(ships.references ? { references: `node_modules/${entry}/reference.conf` } : {}),
	...(ships.deployment ? { deployment: `node_modules/${entry}/README.md#deployment` } : {}),
});

/** Whether a card has a section of what its module asks of the deployment. */
const asksOfDeployment = (card: string) =>
	existsSync(card) && /^## Deployment$/m.test(readFileSync(card, "utf8"));

/** What a manifest declares for the guide: its lines, the owner it adapts, and the name it registers under it. */
const askedIn = (name: string, manifest: Readonly<Record<string, unknown>> | undefined): Asked => ({
	name,
	...(Array.isArray(manifest?.asks) ? { asks: manifest.asks as Ask[] } : {}),
	...(typeof manifest?.adapts === "string" ? { adapts: manifest.adapts } : {}),
	...(typeof manifest?.registersAs === "string" ? { registersAs: manifest.registersAs } : {}),
});

/** A repository URL as a manifest states it, a string or `{ url }`, plain https and no `.git`. */
const repositoryOf = (stated: unknown): string | undefined => {
	const url = typeof stated === "string" ? stated : (stated as { url?: unknown } | undefined)?.url;
	return typeof url === "string" ? url.replace(/^git\+/, "").replace(/\.git$/, "") : undefined;
};

export interface Indexed {
	readonly version: string;
	readonly repository?: string;
	readonly packages: readonly {
		readonly name: string;
		readonly package: string;
		readonly entry: string;
		readonly fragment?: string;
		readonly references?: boolean;
		readonly deployment?: boolean;
		/** The member's manifest, as the release wrote it. */
		readonly manifest?: Readonly<Record<string, unknown>>;
	}[];
	/** Sealed by the release: each bundle's integrity, by its public name, and zod's. */
	readonly integrity?: Readonly<Record<string, string>>;
	readonly zod?: { readonly version: string; readonly integrity: string };
}

/** The index distribution writes at the root of the bundle create-app is built into. */
export const bundleIndex = join(import.meta.dirname, "..", "..", "index.json");

/** The packages outside the release read for a plan, and the names let through though fresh. */
export interface Beside {
	readonly read: Read;
	readonly fresh?: readonly string[];
}
/** The workspace this package lies in, where `combinations` reads the modules it composes. */
const ownWorkspace = join(import.meta.dirname, "..", "..", "..", "..");

/**
 * The packages as published, from the index, where create-app is built into a bundle and no
 * workspace is given; else the workspace's, linked when one is given.
 */
export function packagesFor(plan: { readonly workspace?: string }, index = bundleIndex): Packages {
	if (plan.workspace === undefined && existsSync(index)) {
		return publishedIn(JSON.parse(readFileSync(index, "utf8")) as Indexed);
	}
	const root = resolve(plan.workspace ?? ownWorkspace);
	let listed: Map<string, string> | undefined;
	// Listed on first use: a target refused as it is written reads no workspace.
	const dirs = () => {
		listed ??= workspacePackages(root);
		return listed;
	};
	return {
		fragments: (names) => fragmentsIn(names.flatMap((name) => dirs().get(name) ?? [])),
		dependencies: (names) => dependenciesOf(names, plan.workspace ? dirs() : undefined),
		importOf: (name) => name,
		cards: (names) =>
			names.map((name) => {
				const dir = dirs().get(name);
				return {
					name,
					...installed(name, {
						references: dir !== undefined && existsSync(join(dir, "reference.conf")),
						deployment: dir !== undefined && asksOfDeployment(join(dir, "README.md")),
					}),
				};
			}),
		asks: (names) =>
			names.flatMap((name) => {
				const dir = dirs().get(name);
				return dir === undefined
					? []
					: [askedIn(name, JSON.parse(readFileSync(join(dir, "package.json"), "utf8")))];
			}),
		release: () => {
			const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
			const repository = repositoryOf(manifest.repository);
			return { version: String(manifest.version), ...(repository ? { repository } : {}) };
		},
	};
}

/**
 * The packages as published, from the index, and beside them the packages outside the release read
 * for the plan: each of those depended on at its recorded version, imported by its own name.
 */
export function publishedIn(index: Indexed, beside?: Beside): Packages {
	const byName = new Map(index.packages.map((entry) => [entry.name, entry]));
	const outside = new Map<string, Outside>(
		(beside?.read.outside ?? []).map((o) => [o.declaration.name, o]),
	);
	const found = (name: string) => {
		const entry = byName.get(name);
		if (!entry) throw new Error(`${name} is no published package`);
		return entry;
	};
	return {
		// The release's and those outside it in one reading, so no section is read twice.
		fragments: async (names) =>
			fragmentsOf(
				names.flatMap((name) => {
					const fragment = outside.has(name) ? outside.get(name)?.fragment : found(name).fragment;
					return fragment === undefined ? [] : [{ from: name, text: fragment }];
				}),
			),
		dependencies: (names) =>
			Object.fromEntries(
				names.map((name) => {
					const beside = outside.get(name);
					return beside ? [name, beside.record.version] : [found(name).package, index.version];
				}),
			),
		importOf: (name) => (outside.has(name) ? name : found(name).entry),
		cards: (names) =>
			names.map((name) => {
				const read = outside.get(name);
				if (read) {
					return {
						name,
						...installed(name, {
							references: read.references !== undefined,
							deployment: /^## Deployment$/m.test(read.card ?? ""),
						}),
					};
				}
				const { entry, references, deployment } = found(name);
				return {
					name,
					...installed(entry, { references: references === true, deployment: deployment === true }),
				};
			}),
		// A package outside the release declares nothing for the guide.
		asks: (names) =>
			names.flatMap((name) =>
				outside.has(name) || !byName.has(name) ? [] : [askedIn(name, byName.get(name)?.manifest)],
			),
		release: () => ({
			version: index.version,
			...(index.repository ? { repository: index.repository } : {}),
			...(index.integrity && index.zod
				? { integrity: { ...index.integrity, zod: index.zod.integrity } }
				: {}),
		}),
		outside: (names) => {
			const modules = names.flatMap((name) => outside.get(name)?.record ?? []);
			if (modules.length === 0 || beside === undefined) return undefined;
			const fresh = (beside.fresh ?? []).filter((name) => names.includes(name));
			return {
				modules,
				registries: beside.read.registries,
				...(fresh.length > 0 ? { fresh } : {}),
			};
		},
	};
}
