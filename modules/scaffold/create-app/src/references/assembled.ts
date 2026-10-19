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

/** A route as `http` holds it, as far as the reference reads it. */
interface Route {
	readonly method: string;
	readonly path: string;
	readonly takes?: readonly string[];
	readonly uses?: readonly { readonly policy: { readonly label: string } }[];
	readonly cors?: object;
}

/** A module as its definition holds it: its name, and the points it contributes to. */
interface Definition {
	readonly name: string;
	readonly contributes: readonly { readonly point: unknown }[];
}

/** The Redis store the full template composes, in place of which the memory store is composed: Redis is asked at assembly. */
const redis = "@mod/redis";
const memory = "@mod/store";

/** A route as the reference reads it: the package whose module contributed it, and what it takes and passes through. */
export interface RouteSeen {
	readonly owner: string;
	readonly method: string;
	readonly path: string;
	readonly takes?: readonly string[];
	readonly policies: readonly string[];
	readonly cors: boolean;
}

/** What the assembly collected: the client metadata sections, the IdP types' settings, and the routes. */
export interface Assembled {
	readonly clientSections: readonly Contributed[];
	readonly idpTypes: readonly Contributed[];
	readonly routes: readonly RouteSeen[];
}

let assembled: Promise<Assembled> | undefined;

/** What full with every opt-in composes at three points, each in module order, by contributor; assembled once. */
export function assembledIn(root: string): Promise<Assembled> {
	assembled ??= collectedIn(root);
	return assembled;
}

/** A point's contributions, and how the reference reads each. */
interface Point<T, R> {
	readonly point: ExtensionPoint<T>;
	readonly read: (contribution: T) => R;
}

async function collectedIn(root: string): Promise<Assembled> {
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
	const clients: Point<{ name: string; schema: Schema }, Omit<Contributed, "owner">> = {
		point: (await entryOf("@mod/clients", ".")).metadataSections,
		read: ({ name, schema }) => ({ name, schema }),
	};
	const types: Point<{ type: string; settings: Schema }, Omit<Contributed, "owner">> = {
		point: (await entryOf("@mod/upstreams", ".")).idpTypes,
		read: ({ type, settings }) => ({ name: type, schema: settings }),
	};
	const routes: Point<Route, Omit<RouteSeen, "owner">> = {
		point: (await entryOf("@mod/http", ".")).routes,
		read: ({ method, path, takes, uses, cors }) => ({
			method,
			path,
			...(takes ? { takes } : {}),
			policies: (uses ?? []).map((u) => u.policy.label),
			cors: cors !== undefined,
		}),
	};
	const probed = contract<readonly (readonly unknown[])[]>("references.collected");
	const probe = defineModule({ name: "references-probe" }, (m) => [
		m
			.provide(probed)
			.by(async (c) =>
				Promise.all([c.collect(clients.point), c.collect(types.point), c.collect(routes.point)]),
			),
	]);
	const config = await trialConfig(root);
	const app = await assemble({ modules: [...modules.map((m) => m.module), probe], config });
	const [sections = [], idps = [], served = []] = app.get(probed);
	/** Each contribution read, by the package whose module contributed it, in module order. */
	const byOwner = <T, R>({ point, read }: Point<T, R>, collected: readonly unknown[]) => {
		const owners = modules.flatMap(({ owner, module }) =>
			(module as Definition).contributes.filter((c) => c.point === point).map(() => owner),
		);
		if (owners.length !== collected.length) {
			throw new Error(`${collected.length} collected from ${owners.length} contributions`);
		}
		return collected.map((c, i) => ({ owner: owners[i] as string, ...read(c as T) }));
	};
	return {
		clientSections: byOwner(clients, sections),
		idpTypes: byOwner(types, idps),
		routes: byOwner(routes, served),
	};
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
