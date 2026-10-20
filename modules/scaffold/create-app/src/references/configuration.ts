/** The configuration reference: every module's section, from its schema and its fragment, as one document. */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { type Fragment, fragmentsIn, kernel, settingsOf } from "@mod/app-output";
import { workspacePackages } from "../project.ts";
import { assembledIn, type Contributed, type Schema } from "./assembled.ts";

/** The part of a JSON Schema the reference reads. */
export interface JsonSchema {
	readonly type?: string | readonly string[];
	readonly properties?: Readonly<Record<string, JsonSchema>>;
	readonly required?: readonly string[];
	readonly items?: JsonSchema;
	readonly enum?: readonly unknown[];
	readonly anyOf?: readonly JsonSchema[];
	readonly oneOf?: readonly JsonSchema[];
	readonly const?: unknown;
	readonly default?: unknown;
	readonly description?: string;
	readonly minimum?: number;
	readonly maximum?: number;
}

/** One key of a section, as the reference shows it. */
export interface Row {
	readonly key: string;
	readonly type: string;
	readonly default?: unknown;
	readonly required: boolean;
	readonly env?: string;
	readonly example?: unknown;
	readonly description?: string;
}

const typeOf = (s: JsonSchema): string => {
	if (s.const !== undefined) return String(s.const);
	if (s.enum) return s.enum.map((v) => String(v)).join(" | ");
	const either = s.anyOf ?? s.oneOf;
	if (either) return [...new Set(either.map(typeOf))].join(" | ");
	if (s.type === "array") return `list of ${s.items ? typeOf(s.items) : "any"}`;
	if (s.type === "object") return "map";
	const name = Array.isArray(s.type) ? s.type.join(" | ") : (s.type ?? "any");
	const range =
		s.minimum !== undefined || s.maximum !== undefined
			? ` (${s.minimum ?? ""}–${s.maximum ?? ""})`
			: "";
	return `${name}${range}`;
};

/** An object's keys, or a union of objects' keys merged: required only where every variant requires it. */
function objectOf(s: JsonSchema): JsonSchema | undefined {
	if (s.properties) return s;
	const variants = (s.oneOf ?? s.anyOf ?? []).map(objectOf);
	if (variants.length === 0 || variants.some((v) => v === undefined)) return undefined;
	const properties: Record<string, JsonSchema> = {};
	for (const v of variants as JsonSchema[]) {
		for (const [name, p] of Object.entries(v.properties ?? {})) {
			const held = properties[name];
			const either = held ? [...(held.anyOf ?? [held]), p] : undefined;
			properties[name] = either
				? {
						anyOf: either,
						...(held?.default !== undefined ? { default: held.default } : {}),
						...(held?.description ? { description: held.description } : {}),
					}
				: p;
		}
	}
	const required = Object.keys(properties).filter((name) =>
		(variants as JsonSchema[]).every((v) => (v.required ?? []).includes(name)),
	);
	return { type: "object", properties, required };
}

/**
 * Each key of a schema, objects with properties walked into; `at` reads the fragment's value and
 * env. A key is required only where every object holding it is required too.
 */
export function rowsOf(
	schema: JsonSchema,
	path: readonly string[],
	at: (key: string) => { readonly env?: string; readonly example?: unknown },
	held = true,
): Row[] {
	const object = objectOf(schema);
	return Object.entries(object?.properties ?? {}).flatMap(([name, s]) => {
		const keyPath = [...path, name];
		const required = held && (object?.required ?? []).includes(name) && s.default === undefined;
		const inner = objectOf(s);
		if (inner) return rowsOf(inner, keyPath, at, required);
		const key = keyPath.join(".");
		return [
			{
				key,
				type: typeOf(s),
				...(s.default === undefined ? {} : { default: s.default }),
				required,
				...at(key),
				...(s.description ? { description: s.description } : {}),
			},
		];
	});
}

/** A fragment's own leaves, typed by their sample, for a section read without a schema. */
function fragmentRows(fragment: Fragment, at: (key: string) => { env?: string }): Row[] {
	const walk = (tree: Record<string, unknown>, path: string[]): Row[] =>
		Object.entries(tree).flatMap(([name, value]) => {
			const keyPath = [...path, name];
			if (typeof value === "object" && value !== null && !Array.isArray(value)) {
				return walk(value as Record<string, unknown>, keyPath);
			}
			const key = keyPath.join(".");
			const type = Array.isArray(value) ? "list" : typeof value;
			return [{ key, type, required: false, ...at(key), example: value }];
		});
	return walk(fragment.tree as Record<string, unknown>, [fragment.section]);
}

/** A section of the workspace: its owner, the owner's directory, its schema and its rows. */
export interface Section {
	readonly section: string;
	readonly owner: string;
	readonly dir: string;
	readonly schema: Schema;
	readonly rows: Row[];
	/** The fragment's keys read from env that no row holds: under a map whose names are the operator's. */
	readonly unfixed: readonly string[];
}

/** The keys read from env that no row holds, as one under a map (a record whose names the operator picks). */
export const unfixedKeys = (rows: readonly Row[], read: readonly string[]): string[] =>
	read.filter((key) => !rows.some((row) => row.key === key));

/** Every section of the workspace. */
export async function sectionsIn(root: string): Promise<Section[]> {
	const found = [];
	for (const [name, dir] of workspacePackages(root)) {
		if (dir === root) continue;
		const manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
		const entry: string | undefined = manifest.exports?.["./module"];
		const module = entry
			? ((await import(join(dir, entry))).default as { name: string; section?: Schema })
			: undefined;
		const [fragment] = await fragmentsIn([dir]);
		const env = new Map(fragment ? settingsOf([fragment]).map((s) => [s.key, s.env]) : []);
		const example = new Map(
			fragment ? fragmentRows(fragment, () => ({})).map((r) => [r.key, r.example]) : [],
		);
		const at = (key: string) => {
			const variable = env.get(key);
			return {
				...(variable === undefined ? {} : { env: variable }),
				...(example.has(key) ? { example: example.get(key) } : {}),
			};
		};
		const schema = module?.section?.["~standard"].jsonSchema?.input({ target: "draft-2020-12" });
		if (module?.section && schema) {
			const rows = rowsOf(schema as JsonSchema, [module.name], at);
			found.push({
				section: module.name,
				owner: name,
				dir,
				schema: module.section,
				rows,
				unfixed: unfixedKeys(rows, [...env.keys()]),
			});
		} else if (fragment && name === kernel) {
			// The kernel reads its own section, by the schema its contract exports.
			const own = (await import(join(dir, manifest.exports["."]))).kernelSection as Schema;
			const read = own["~standard"].jsonSchema?.input({ target: "draft-2020-12" });
			const rows = read
				? rowsOf(read as JsonSchema, [fragment.section], at)
				: fragmentRows(fragment, at);
			const unfixed = unfixedKeys(rows, [...env.keys()]);
			found.push({ section: fragment.section, owner: name, dir, schema: own, rows, unfixed });
		}
	}
	return found.sort((a, b) => (a.section < b.section ? -1 : 1));
}

/** A section modules add to client records: its name, its contributor, its schema and its rows under `sections`. */
export type ClientSection = Omit<Section, "dir" | "unfixed">;

/** Contributions as sections, by name: their keys under `path`. */
const asSections = (found: readonly Contributed[], path: (name: string) => string[]) =>
	found
		.map(({ owner, name, schema }) => {
			const read = schema["~standard"].jsonSchema?.input({ target: "draft-2020-12" });
			const rows = read ? rowsOf(read as JsonSchema, path(name), () => ({})) : [];
			return { section: name, owner, schema, rows };
		})
		.sort((a, b) => (a.section < b.section ? -1 : 1));

/** Every client metadata section the full template with every opt-in composes, by name. */
export async function clientSectionsOf(root: string): Promise<ClientSection[]> {
	return asSections((await assembledIn(root)).clientSections, (name) => ["sections", name]);
}

/** Every IdP type's settings the full template with every opt-in composes, by type, under one IdP of `federation`. */
export async function idpTypesOf(root: string): Promise<ClientSection[]> {
	return asSections((await assembledIn(root)).idpTypes, () => ["federation", "idps", "<name>"]);
}

/** A value in a table cell, on one line: a string of several lines as JSON writes it, `\n` and all. */
const cell = (value: unknown) =>
	value === undefined
		? ""
		: `\`${(typeof value === "string" && !value.includes("\n") ? value : JSON.stringify(value)).replaceAll("|", "\\|")}\``;
const text = (value: string | undefined) =>
	(value ?? "").replaceAll("|", "\\|").replaceAll("\n", " ");

/** The reference, generated: one table per section, then one per client metadata section and per IdP type. */
export function referenceOf(
	sections: readonly Omit<Section, "dir" | "schema" | "unfixed">[],
	clients: readonly Omit<ClientSection, "schema">[] = [],
	types: readonly Omit<ClientSection, "schema">[] = [],
): string {
	const blocks = sections.map(({ section, owner, rows }) => {
		const lines = rows.map(
			(r) =>
				`| \`${r.key}\` | ${text(r.type)} | ${cell(r.default)} | ${r.required ? "yes" : ""} | ${r.env ? `\`${r.env}\`` : ""} | ${cell(r.example)} | ${text(r.description)} |`,
		);
		return [
			`## ${section}`,
			"",
			`From \`${owner}\`.`,
			"",
			"| Key | Type | Default | Required | Variable | Example | Description |",
			"|---|---|---|---|---|---|---|",
			...lines,
		].join("\n");
	});
	return `${[
		"# Configuration",
		"",
		"Generated by `create-app` from each module's section schema and its `config.example`: do not edit; run `pnpm --filter @mod/create-app run configuration`.",
		"A variable is read by the configuration `create-app` generates, for a key the module's example holds; any other key is written in the local layer.",
		"",
		...blocks.flatMap((b) => [b, ""]),
		...(clients.length > 0 ? [clientPartOf(clients), ""] : []),
		...(types.length > 0 ? [typePartOf(types), ""] : []),
	]
		.join("\n")
		.trimEnd()}\n`;
}

/** One table per contribution, under its heading, by the module that adds it. */
const contributedBlocks = (
	found: readonly Omit<ClientSection, "schema">[],
	heading: (name: string) => string,
) =>
	found.map(({ section, owner, rows }) =>
		[
			`### ${heading(section)}`,
			"",
			`From \`${owner}\`.`,
			"",
			"| Key | Type | Default | Required | Description |",
			"|---|---|---|---|---|",
			...rows.map(
				(r) =>
					`| \`${r.key}\` | ${text(r.type)} | ${cell(r.default)} | ${r.required ? "yes" : ""} | ${text(r.description)} |`,
			),
		].join("\n"),
	);

/** The client metadata sections: what a client record holds under `sections`, by the module that adds each. */
function clientPartOf(clients: readonly Omit<ClientSection, "schema">[]): string {
	const blocks = contributedBlocks(clients, (name) => `sections.${name}`);
	return [
		"## Client metadata sections",
		"",
		"What a client record holds under `sections`, each added by the module named, which reads it.",
		"Shown as the full template with every opt-in composes them on the trial's settings: a section whose shape follows the composition (`client-assertion` by the outbound policy, `sender-binding` by the bindings composed) can differ in another app.",
		"",
		...blocks.flatMap((b) => [b, ""]),
	]
		.join("\n")
		.trimEnd();
}

/** The IdP types' settings: what one IdP under `federation`'s `idps` holds, by the module that adds its type. */
function typePartOf(types: readonly Omit<ClientSection, "schema">[]): string {
	const blocks = contributedBlocks(types, (name) => `federation.idps.<name> (type = ${name})`);
	return [
		"## IdP type settings",
		"",
		"What one IdP under `federation`'s `idps.<name>` holds beside its `type`, by the module that adds the type, which reads them.",
		"Shown as the full template with every opt-in composes them on the trial's settings: the URLs each type takes follow the outbound policy, which can differ in another app.",
		"",
		...blocks.flatMap((b) => [b, ""]),
	]
		.join("\n")
		.trimEnd();
}

/** Where the reference lies in the workspace. */
export const referenceFile = (root: string) => join(root, "docs", "configuration.md");

/** A key as HOCON writes it: quoted when it holds more than letters, digits, `-` and `_`. */
const hoconKey = (key: string) => (/^[A-Za-z0-9_-]+$/.test(key) ? key : JSON.stringify(key));

/** A value as HOCON writes it: a number with its unit bare (`5m`, `64KiB`), anything else as JSON. */
const hoconValue = (value: unknown) =>
	typeof value === "string" && /^\d+(\.\d+)?\s?[A-Za-z]+$/.test(value)
		? value
		: JSON.stringify(value);

/** A section's defaults as HOCON, for an operator to read: each key, described, with its default or what it needs. */
export function referenceConfOf({
	section,
	owner,
	rows,
}: Omit<Section, "dir" | "schema" | "unfixed">): string {
	const keys = rows.flatMap((r) => {
		const key = r.key.split(".").slice(1).map(hoconKey).join(".");
		const about = (r.description ?? "")
			.split("\n")
			.filter(Boolean)
			.map((line) => `\t# ${line}`);
		const value =
			r.default !== undefined
				? `\t${key} = ${hoconValue(r.default)}`
				: `\t# ${key}: ${r.required ? "required" : "optional"}`;
		return [...about, value];
	});
	return [
		`# The defaults of \`${owner}\`'s section, generated by \`create-app\` from its schema: do not edit; run \`pnpm --filter @mod/create-app run configuration\`.`,
		"# For reading only: the module applies these itself, and the app does not load this file.",
		`${hoconKey(section)} {`,
		...keys,
		"}",
		"",
	].join("\n");
}

/** Where a section's defaults lie: beside its package's manifest. */
export const referenceConfFile = (dir: string) => join(dir, "reference.conf");
