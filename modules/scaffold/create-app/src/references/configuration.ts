/** The configuration reference: every module's section, from its schema and its fragment, as one document. */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { type Fragment, fragmentsIn, settingsOf } from "../fragments.ts";
import { kernel, workspacePackages } from "../project.ts";

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

/** Each key of a schema, objects with properties walked into; `at` reads the fragment's value and env. */
export function rowsOf(
	schema: JsonSchema,
	path: readonly string[],
	at: (key: string) => { readonly env?: string; readonly example?: unknown },
): Row[] {
	const object = objectOf(schema);
	return Object.entries(object?.properties ?? {}).flatMap(([name, s]) => {
		const keyPath = [...path, name];
		const inner = objectOf(s);
		if (inner) return rowsOf(inner, keyPath, at);
		const key = keyPath.join(".");
		return [
			{
				key,
				type: typeOf(s),
				...(s.default === undefined ? {} : { default: s.default }),
				required: (object?.required ?? []).includes(name) && s.default === undefined,
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

/** A section's schema, as its module exports it: a Standard Schema that can describe itself. */
interface Schema {
	readonly "~standard": { readonly jsonSchema?: { input(o: object): unknown } };
}

/** A section of the workspace: its owner, the owner's directory, its schema and its rows. */
export interface Section {
	readonly section: string;
	readonly owner: string;
	readonly dir: string;
	readonly schema: Schema;
	readonly rows: Row[];
}

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
			found.push({
				section: module.name,
				owner: name,
				dir,
				schema: module.section,
				rows: rowsOf(schema as JsonSchema, [module.name], at),
			});
		} else if (fragment && name === kernel) {
			// The kernel reads its own section, by the schema its contract exports.
			const own = (await import(join(dir, manifest.exports["."]))).kernelSection as Schema;
			const read = own["~standard"].jsonSchema?.input({ target: "draft-2020-12" });
			const rows = read
				? rowsOf(read as JsonSchema, [fragment.section], at)
				: fragmentRows(fragment, at);
			found.push({ section: fragment.section, owner: name, dir, schema: own, rows });
		}
	}
	return found.sort((a, b) => (a.section < b.section ? -1 : 1));
}

const cell = (value: unknown) =>
	value === undefined
		? ""
		: `\`${(typeof value === "string" ? value : JSON.stringify(value)).replaceAll("|", "\\|")}\``;
const text = (value: string | undefined) =>
	(value ?? "").replaceAll("|", "\\|").replaceAll("\n", " ");

/** The reference, generated: one table per section. */
export function referenceOf(sections: readonly Omit<Section, "dir" | "schema">[]): string {
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
	]
		.join("\n")
		.trimEnd()}\n`;
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
export function referenceConfOf({ section, owner, rows }: Omit<Section, "dir" | "schema">): string {
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
