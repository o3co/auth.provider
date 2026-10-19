/** What the full template with every opt-in contributes, assembled in memory on the trial's settings and never started. */
import { readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { full, optIns } from "@mod/combinations";
import { assemble, contract, defineModule, type ExtensionPoint, loadConfig } from "@mod/kernel";
import { generate } from "../generate.ts";
import { workspacePackages } from "../project.ts";
import { trialSettings } from "../trial.ts";

/** A section's schema, as a module gives it: a Standard Schema that can describe itself. */
export interface Schema {
	readonly "~standard": { readonly jsonSchema?: { input(o: object): unknown } };
}

/** One contribution with a name and a schema, and the package whose module contributed it. */
export interface Contributed {
	readonly owner: string;
	readonly name: string;
	readonly schema: Schema;
}

/** A module as its definition holds it: its name, and the points it contributes to. */
interface Definition {
	readonly name: string;
	readonly contributes: readonly { readonly point: unknown }[];
}

/** The Redis store the full template composes, in place of which the memory store is composed: Redis is asked at assembly. */
const redis = "@mod/redis";
const memory = "@mod/store";

let assembled: Promise<readonly Contributed[]> | undefined;

/** The client metadata sections composed in full with every opt-in, in module order, by contributor. */
export function clientSectionsIn(root: string): Promise<readonly Contributed[]> {
	assembled ??= contributedIn(root);
	return assembled;
}

async function contributedIn(root: string): Promise<readonly Contributed[]> {
	const packages = workspacePackages(root);
	const entryOf = async (name: string, entry: string) => {
		const dir = packages.get(name);
		if (!dir) throw new Error(`${name}: not in the workspace`);
		const manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
		return import(join(dir, manifest.exports[entry]));
	};
	const names = full(optIns()).map((name) => (name === redis ? memory : name));
	const modules = await Promise.all(
		names.map(async (name) => ({ owner: name, module: (await entryOf(name, "./module")).default })),
	);
	const point: ExtensionPoint<Contributed> = (await entryOf("@mod/clients", ".")).metadataSections;
	const probed = contract<readonly Contributed[]>("references.client-sections");
	const probe = defineModule({ name: "references-probe" }, (m) => [
		m.provide(probed).by((c) => c.collect(point)),
	]);
	const config = await trialConfig(root);
	const app = await assemble({ modules: [...modules.map((m) => m.module), probe], config });
	const sections = app.get(probed);
	const owners = modules.flatMap(({ owner, module }) =>
		(module as Definition).contributes.filter((c) => c.point === point).map(() => owner),
	);
	if (owners.length !== sections.length) {
		throw new Error(
			`${sections.length} client sections collected from ${owners.length} contributions`,
		);
	}
	return sections.map((s, i) => ({ owner: owners[i] as string, name: s.name, schema: s.schema }));
}

/** The full template's configuration with every opt-in, on the trial's settings, its store kept in memory. */
async function trialConfig(root: string) {
	const target = await mkdtemp(join(tmpdir(), "create-app-references-"));
	try {
		await generate({ target, template: "full", workspace: root, add: optIns() });
		const { env, local } = await trialSettings(target, { redisUrl: "redis://127.0.0.1:1" });
		await writeFile(join(target, "local.conf"), local);
		await writeFile(join(target, "memory.conf"), "store { accept-volatile = true }\n");
		const files = ["memory.conf", "local.conf", join("config", "application.conf")];
		const config = (await loadConfig({
			files: files.map((file) => join(target, file)),
			env,
		})) as Record<string, unknown>;
		const { redis: _redis, ...kept } = config;
		return kept;
	} finally {
		await rm(target, { recursive: true, force: true });
	}
}
