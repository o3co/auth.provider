/** The configuration reference: every module's section, from its schema and its fragment, as one document. */
import { join } from "node:path";
import { kernel } from "@mod/app-entries";
import { type Fragment, fragmentsIn, settingsOf } from "@mod/app-output";
import type { Pkg } from "@mod/guard-imports";
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
	/** With `within`, required once that object is set. */
	readonly required: boolean;
	/** The optional object the key lies in, nearest first: its default and requiredness hold only once that is set. */
	readonly within?: string;
	/** The variants the row holds in, outermost first: a key's own facts that differ by variant are one row each. */
	readonly when?: readonly Clause[];
	readonly env?: string;
	readonly example?: unknown;
	readonly description?: string;
}

/** One variant clause: the key that tells a union's variants apart, and the values it takes in them. */
export interface Clause {
	readonly key: string;
	readonly values: readonly string[];
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

/** A union's object variants, nested unions flattened; none where one of them is not an object. */
function variantsOf(s: JsonSchema): JsonSchema[] | undefined {
	if (s.properties) return [s];
	const either = s.oneOf ?? s.anyOf;
	if (!either) return undefined;
	const all = either.map(variantsOf);
	return all.some((v) => v === undefined) ? undefined : (all as JsonSchema[][]).flat();
}

/** The values a variant names for `name`, as a constant or a list of them. */
function valuesAt(v: JsonSchema, name: string): string[] | undefined {
	const p = v.properties?.[name];
	if (p?.const !== undefined) return [String(p.const)];
	return p?.enum?.map((value) => String(value));
}

/** The key that tells a union's variants apart: each names its own values of it, none another's. */
function discriminatorOf(variants: readonly JsonSchema[]): string | undefined {
	if (variants.length < 2) return undefined;
	return Object.keys(variants[0]?.properties ?? {}).find((name) => {
		const values = variants.map((v) => valuesAt(v, name));
		if (values.some((v) => v === undefined)) return false;
		const all = (values as string[][]).flat();
		return new Set(all).size === all.length;
	});
}

type At = (key: string) => { readonly env?: string; readonly example?: unknown };

/**
 * Each key of a schema, objects with properties walked into; `at` reads the fragment's value and
 * env. A key inside an object neither required nor defaulted lies `within` it: its default and
 * requiredness hold once that object is set. Inside a defaulted object no key is required. In a
 * union told apart by one key, a key holds `when` that key takes the values of the variants it is
 * alike in; where all of them are alike, it holds in each.
 */
export function rowsOf(
	schema: JsonSchema,
	path: readonly string[],
	at: At,
	held = true,
	within?: string,
	when: readonly Clause[] = [],
): Row[] {
	const variants = variantsOf(schema);
	const on = variants === undefined ? undefined : discriminatorOf(variants);
	if (variants === undefined || on === undefined) {
		const object = objectOf(schema);
		return Object.entries(object?.properties ?? {}).flatMap(([name, s]) =>
			keyRows(name, s, (object?.required ?? []).includes(name), path, at, held, within, when),
		);
	}
	const by = [...path, on].join(".");
	const names = [...new Set(variants.flatMap((v) => Object.keys(v.properties ?? {})))];
	return names.flatMap((name) => {
		const holding = variants.filter((v) => v.properties?.[name] !== undefined);
		if (name === on) {
			const each = holding.map((v) => v.properties?.[name] as JsonSchema);
			const described = each.find((p) => p.description)?.description;
			const either = { anyOf: each, ...(described ? { description: described } : {}) };
			return keyRows(name, either, true, path, at, held, within, when);
		}
		// The variants alike in this key, its schema the same and required in each or in none.
		const alike = Map.groupBy(holding, (v) =>
			JSON.stringify([v.properties?.[name], (v.required ?? []).includes(name)]),
		);
		const everywhere = alike.size === 1 && holding.length === variants.length;
		return [...alike.values()].flatMap((group) => {
			const [v] = group as [JsonSchema];
			const clause = { key: by, values: group.flatMap((g) => valuesAt(g, on) ?? []) };
			return keyRows(
				name,
				v.properties?.[name] as JsonSchema,
				(v.required ?? []).includes(name),
				path,
				at,
				held,
				within,
				everywhere ? when : [...when, clause],
			);
		});
	});
}

/** One key's rows: an object's walked into, a leaf's its own. */
function keyRows(
	name: string,
	s: JsonSchema,
	listed: boolean,
	path: readonly string[],
	at: At,
	held: boolean,
	within: string | undefined,
	when: readonly Clause[],
): Row[] {
	const keyPath = [...path, name];
	const own = listed && s.default === undefined;
	if (variantsOf(s)) {
		if (own || s.default !== undefined) return rowsOf(s, keyPath, at, held && own, within, when);
		return rowsOf(s, keyPath, at, true, keyPath.join("."), when);
	}
	const key = keyPath.join(".");
	return [
		{
			key,
			type: typeOf(s),
			...(s.default === undefined ? {} : { default: s.default }),
			required: held && own,
			...(within === undefined ? {} : { within }),
			...(when.length === 0 ? {} : { when }),
			...at(key),
			...(s.description ? { description: s.description } : {}),
		},
	];
}

/** The keys inside lists of objects, under `<list>.<i>`, which the rows keep as one list row each. */
export function itemRowsOf(schema: JsonSchema, path: readonly string[]): Row[] {
	const object = objectOf(schema);
	return Object.entries(object?.properties ?? {}).flatMap(([name, s]) => {
		const keyPath = [...path, name];
		const items = s.type === "array" && s.items ? objectOf(s.items) : undefined;
		if (items) {
			const item = [...keyPath, "<i>"];
			return [...rowsOf(items, item, () => ({}), false), ...itemRowsOf(items, item)];
		}
		const inner = objectOf(s);
		return inner ? itemRowsOf(inner, keyPath) : [];
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
	/** The keys inside its lists of objects, which `rows` keeps as one list row each. */
	readonly items?: Row[];
	/** The fragment's keys read from env that no row holds: under a map whose names are the operator's. */
	readonly unfixed: readonly string[];
}

/** The keys read from env that no row holds, as one under a map (a record whose names the operator picks). */
export const unfixedKeys = (rows: readonly Row[], read: readonly string[]): string[] =>
	read.filter((key) => !rows.some((row) => row.key === key));

/** Every section of the workspace. */
export async function sectionsIn(packages: readonly Pkg[]): Promise<Section[]> {
	const found = [];
	for (const { name, dir, manifest } of packages) {
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
				items: itemRowsOf(schema as JsonSchema, [module.name]),
				unfixed: unfixedKeys(rows, [...env.keys()]),
			});
		} else if (fragment && name === kernel) {
			// The kernel reads its own section, by the schema its contract exports.
			const own = (await import(join(dir, manifest.exports?.["."] as string)))
				.kernelSection as Schema;
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
			const items = read ? itemRowsOf(read as JsonSchema, path(name)) : [];
			return { section: name, owner, schema, rows, items };
		})
		.sort((a, b) => (a.section < b.section ? -1 : 1));

/** Every client metadata section the full template with every opt-in composes, by name. */
export async function clientSectionsOf(
	root: string,
	packages: readonly Pkg[],
): Promise<ClientSection[]> {
	return asSections((await assembledIn(root, packages)).clientSections, (name) => [
		"sections",
		name,
	]);
}

/** Every IdP type's settings the full template with every opt-in composes, by type, under one IdP of `federation`. */
export async function idpTypesOf(root: string, packages: readonly Pkg[]): Promise<ClientSection[]> {
	return asSections((await assembledIn(root, packages)).idpTypes, () => [
		"federation",
		"idps",
		"<name>",
	]);
}

/** A value in a table cell, on one line: a string of several lines as JSON writes it, `\n` and all. */
const cell = (value: unknown) =>
	value === undefined
		? ""
		: `\`${(typeof value === "string" && !value.includes("\n") ? value : JSON.stringify(value)).replaceAll("|", "\\|")}\``;
const text = (value: string | undefined) =>
	(value ?? "").replaceAll("|", "\\|").replaceAll("\n", " ");
/** A row's default and requiredness cells, each holding only once the object it lies within is set. */
/** Values in prose: `a`, `a or b`, `a, b or c`. */
const either = (values: readonly string[]) =>
	values.length < 2 ? (values[0] ?? "") : `${values.slice(0, -1).join(", ")} or ${values.at(-1)}`;

/** What a row holds under, outermost first: the optional object it lies within set, each variant it holds in. */
const conditionsOf = (r: Row, write: (text: string, kind: "key" | "value") => string) => {
	const set = r.within === undefined ? [] : [{ key: r.within, values: undefined }];
	// By the object each is of, the variant of an object before an optional object in it.
	const level = (c: { key: string; values: unknown }) =>
		2 * c.key.split(".").length + (c.values === undefined ? 1 : 0);
	const all = [...set, ...(r.when ?? [])].sort((a, b) => level(a) - level(b));
	const said = all.map(({ key, values }) =>
		values === undefined
			? `${write(key, "key")} is set`
			: `${write(key, "key")} is ${either(values.map((v) => write(v, "value")))}`,
	);
	return said.length === 0 ? "" : `when ${said.join(" and ")}`;
};

/** A row's default and requiredness cells, each holding only under the row's conditions. */
const held = (r: Row) => {
	const when = conditionsOf(r, (text) => `\`${text}\``);
	const once = when === "" ? "" : ` ${when}`;
	const fallback = r.default === undefined ? "" : `${cell(r.default)}${once}`;
	return { fallback, required: r.required ? when || "yes" : "" };
};

/** The reference, generated: one table per section, then one per client metadata section and per IdP type. */
export function referenceOf(
	sections: readonly Omit<Section, "dir" | "schema" | "unfixed">[],
	clients: readonly Omit<ClientSection, "schema">[] = [],
	types: readonly Omit<ClientSection, "schema">[] = [],
): string {
	const blocks = sections.map(({ section, owner, rows }) => {
		const lines = rows.map((r) => {
			const { fallback, required } = held(r);
			return `| \`${r.key}\` | ${text(r.type)} | ${fallback} | ${required} | ${r.env ? `\`${r.env}\`` : ""} | ${cell(r.example)} | ${text(r.description)} |`;
		});
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
		"Generated by `references` from each module's section schema and its `config.example`: do not edit; run `pnpm --filter @mod/references run configuration`.",
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
			...rows.map((r) => {
				const { fallback, required } = held(r);
				return `| \`${r.key}\` | ${text(r.type)} | ${fallback} | ${required} | ${text(r.description)} |`;
			}),
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

/**
 * A section's defaults as HOCON, for an operator to read: each key, described, with its default or
 * what it needs; a key within an optional object or held in some variants only as a comment, saying when it holds.
 */
export function referenceConfOf({
	section,
	owner,
	rows,
}: Omit<Section, "dir" | "schema" | "unfixed">): string {
	const keys = rows.flatMap((r) => {
		const inSection = (path: string) => path.split(".").slice(1).map(hoconKey).join(".");
		const key = inSection(r.key);
		const about = (r.description ?? "")
			.split("\n")
			.filter(Boolean)
			.map((line) => `\t# ${line}`);
		const needs = r.required ? "required" : "optional";
		const once = conditionsOf(r, (text, kind) => (kind === "key" ? inSection(text) : text));
		if (once !== "") {
			const value =
				r.default !== undefined
					? `\t# ${key} = ${hoconValue(r.default)} (${once})`
					: `\t# ${key}: ${needs} ${once}`;
			return [...about, value];
		}
		const value =
			r.default !== undefined ? `\t${key} = ${hoconValue(r.default)}` : `\t# ${key}: ${needs}`;
		return [...about, value];
	});
	return [
		`# The defaults of \`${owner}\`'s section, generated by \`references\` from its schema: do not edit; run \`pnpm --filter @mod/references run configuration\`.`,
		"# For reading only: the module applies these itself, and the app does not load this file.",
		`${hoconKey(section)} {`,
		...keys,
		"}",
		"",
	].join("\n");
}

/** Where a section's defaults lie: beside its package's manifest. */
export const referenceConfFile = (dir: string) => join(dir, "reference.conf");
