import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { type Card, fragmentsIn, fragmentsOf, type Packages } from "@mod/app-output";
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

/** A repository URL as a manifest states it, a string or `{ url }`, plain https and no `.git`. */
const repositoryOf = (stated: unknown): string | undefined => {
	const url = typeof stated === "string" ? stated : (stated as { url?: unknown } | undefined)?.url;
	return typeof url === "string" ? url.replace(/^git\+/, "").replace(/\.git$/, "") : undefined;
};

interface Indexed {
	readonly version: string;
	readonly repository?: string;
	readonly packages: readonly {
		readonly name: string;
		readonly package: string;
		readonly entry: string;
		readonly fragment?: string;
		readonly references?: boolean;
		readonly deployment?: boolean;
	}[];
}

/** The index distribution writes at the root of the bundle create-app is built into. */
const bundleIndex = join(import.meta.dirname, "..", "..", "index.json");
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
		release: () => {
			const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
			const repository = repositoryOf(manifest.repository);
			return { version: String(manifest.version), ...(repository ? { repository } : {}) };
		},
	};
}

function publishedIn(index: Indexed): Packages {
	const byName = new Map(index.packages.map((entry) => [entry.name, entry]));
	const found = (name: string) => {
		const entry = byName.get(name);
		if (!entry) throw new Error(`${name} is no published package`);
		return entry;
	};
	return {
		fragments: async (names) =>
			fragmentsOf(
				names.flatMap((name) => {
					const { fragment } = found(name);
					return fragment === undefined ? [] : [{ from: name, text: fragment }];
				}),
			),
		dependencies: (names) =>
			Object.fromEntries(names.map((name) => [found(name).package, index.version])),
		importOf: (name) => found(name).entry,
		cards: (names) =>
			names.map((name) => {
				const { entry, references, deployment } = found(name);
				return {
					name,
					...installed(entry, { references: references === true, deployment: deployment === true }),
				};
			}),
		release: () => ({
			version: index.version,
			...(index.repository ? { repository: index.repository } : {}),
		}),
	};
}
