/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Where a configuration path lands in a Zod schema: the schema that
 * parses the value at a dot path, found by walking the schema's objects and
 * the wrappers a configuration schema puts around them. Three readers use
 * it: the transitional reader's picked schema (`pickConfigSchema`, what a
 * composition root reads before it knows its modules), the guard that every
 * leaf an environment variable sets reads the string it arrives as, and the
 * check that a section refuses an unknown key at every object level it
 * declares (`schemaObjectLevels`).
 */

import { z } from "zod";

/** The definition every Zod v4 schema carries, as far as this file reads it. */
interface Def {
	readonly type: string;
	readonly innerType?: z.ZodType;
	readonly in?: z.ZodType;
	readonly out?: z.ZodType;
	readonly shape?: Readonly<Record<string, z.ZodType>>;
	readonly valueType?: z.ZodType;
	readonly options?: readonly z.ZodType[];
	readonly left?: z.ZodType;
	readonly right?: z.ZodType;
	readonly getter?: () => z.ZodType;
	readonly coerce?: boolean;
	readonly element?: z.ZodType;
	readonly values?: readonly unknown[];
}

const defOf = (schema: z.ZodType): Def => (schema as unknown as { _zod: { def: Def } })._zod.def;

/** A literal's values: every `z.literal` carries at least one. */
const literalValues = (def: Def): readonly unknown[] => def.values as readonly unknown[];

/** The wrappers that parse a value as their inner schema does, less or more permissively. */
const WRAPPERS = new Set([
	"optional",
	"nullable",
	"default",
	"prefault",
	"readonly",
	"catch",
	"nonoptional",
]);

/**
 * The schemas `schema` may parse a value with, once its wrappers are seen
 * through: a wrapper's inner schema, a pipe's end that holds the shape (the
 * target of a `z.preprocess`, the source of a `.transform`), each member of a
 * union, both sides of an intersection, a lazy schema's result.
 */
function bodiesOf(schema: z.ZodType, onTransform?: () => void): z.ZodType[] {
	const def = defOf(schema);
	const inner = (next: z.ZodType) => bodiesOf(next, onTransform);
	if (WRAPPERS.has(def.type) && def.innerType) return inner(def.innerType);
	if (def.type === "pipe" && def.in && def.out) {
		if (defOf(def.out).type !== "transform") return inner(def.out);
		onTransform?.();
		return inner(def.in);
	}
	if (def.type === "union" && def.options) return def.options.flatMap(inner);
	if (def.type === "intersection" && def.left && def.right) {
		return [...inner(def.left), ...inner(def.right)];
	}
	if (def.type === "lazy" && def.getter) {
		// The schema's own cached result, so a schema that reaches itself is the same object again.
		const cached = (schema as unknown as { _zod: { innerType?: z.ZodType } })._zod.innerType;
		return inner(cached ?? def.getter());
	}
	return [schema];
}

/**
 * Every schema that parses the value at `path` inside `schema` — more than
 * one where a union or an intersection offers several — or none when the
 * path leaves what `schema` declares: a key no object on the way declares, a
 * list, a scalar. A record's value schema answers any key. The schemas are
 * the ones declared at the path, wrappers included.
 */
export function schemasAtPath(schema: z.ZodType, path: readonly string[]): z.ZodType[] {
	if (path.length === 0) return [schema];
	const [key, ...rest] = path as [string, ...string[]];
	return bodiesOf(schema).flatMap((body) => {
		const def = defOf(body);
		if (def.type === "object" && def.shape && Object.hasOwn(def.shape, key)) {
			return schemasAtPath(def.shape[key] as z.ZodType, rest);
		}
		if (def.type === "record" && def.valueType) return schemasAtPath(def.valueType, rest);
		return [];
	});
}

/** The schemas `environmentCoercer` names: core's own readers of an environment string. */
const ENVIRONMENT_COERCERS = new WeakSet<object>();

/**
 * Names `schema` as one of core's environment coercers (`coerceBooleanFromEnv`,
 * each `durationFromEnv`), whose preprocess reads the string a `${?VAR}`
 * carries into the type its schema takes, so `readsEnvironmentString` trusts
 * it. Tagged rather than probed: a probe ("false", "1") would run the
 * schema's own bounds and refinements, and report a leaf that refuses `"1"`
 * as too small as one that cannot read a string. Any other preprocess is
 * judged by the schema it hands on. Answers `schema`.
 * @internal
 */
export function environmentCoercer<T extends z.ZodType>(schema: T): T {
	ENVIRONMENT_COERCERS.add(schema);
	return schema;
}

/**
 * Whether `schema` reads the string an environment variable arrives as, seen
 * through its wrappers, a lazy schema and both sides of an intersection:
 * `true` for a string, an enum, a template literal, a literal with a string
 * value, any, unknown, every `z.coerce.*` scalar, and the containers a leaf
 * sits in; `false` for every other type (a plain boolean, number, bigint or
 * date, null, NaN, a symbol, a custom schema, a type it does not know), and
 * for a union only when no member reads a string. A `z.preprocess` counts
 * only on evidence: one of core's environment coercers (`environmentCoercer`)
 * reads it, and any other is judged by the schema it hands on, since its
 * function may do nothing with the string (`z.preprocess((v) => v,
 * z.boolean())` refuses `"false"`).
 */
export function readsEnvironmentString(schema: z.ZodType): boolean {
	if (ENVIRONMENT_COERCERS.has(schema)) return true;
	const def = defOf(schema);
	if (WRAPPERS.has(def.type) && def.innerType) return readsEnvironmentString(def.innerType);
	if (def.type === "pipe" && def.in && def.out) {
		// A preprocess (its input a function) by what it hands on; a
		// `.transform` (its output a function) by the schema that reads first.
		return readsEnvironmentString(defOf(def.in).type === "transform" ? def.out : def.in);
	}
	if (def.type === "union" && def.options) return def.options.some(readsEnvironmentString);
	if (def.type === "intersection" && def.left && def.right) {
		return readsEnvironmentString(def.left) && readsEnvironmentString(def.right);
	}
	if (def.type === "lazy" && def.getter) return readsEnvironmentString(def.getter());
	// No string equals `true` or `1`: a literal reads the string only if one
	// of its values is a string.
	if (def.type === "literal") return literalValues(def).some((value) => typeof value === "string");
	// A scalar `z.coerce.*` converts the string: a number, a boolean, a
	// bigint, a date (and a string).
	if (COERCIBLE.has(def.type)) return def.coerce === true;
	return READS_A_STRING.has(def.type);
}

/** The scalar types whose `z.coerce.*` form reads a string, and whose plain form does not. */
const COERCIBLE: ReadonlySet<string> = new Set(["number", "boolean", "bigint", "date"]);

/**
 * The types that take the string itself — a string, an enum, a template
 * literal, any and unknown — and the containers a leaf sits in (an object, a
 * record, a list), which `unreadableLeaves` walks into rather than reads.
 * Every other type — null, undefined, void, never, NaN, a symbol, a map, a
 * set, a tuple, a custom schema, a file, a promise, a function, a type Zod
 * adds later — does not read one: an unknown type is reported, not trusted.
 */
const READS_A_STRING: ReadonlySet<string> = new Set([
	"string",
	"enum",
	"template_literal",
	"any",
	"unknown",
	"object",
	"record",
	"array",
]);

/**
 * The kinds of value `schema` produces — `"boolean"`, `"number"`,
 * `"string"`, `"object"`… — seen through its wrappers and a preprocess, or
 * `undefined` when it cannot be told without running it (a `.transform`, a
 * custom schema): each member of a union adds its own.
 */
export function outputKinds(schema: z.ZodType): ReadonlySet<string> | undefined {
	const def = defOf(schema);
	if (WRAPPERS.has(def.type) && def.innerType) return outputKinds(def.innerType);
	if (def.type === "pipe" && def.out) {
		return defOf(def.out).type === "transform" ? undefined : outputKinds(def.out);
	}
	if (def.type === "union" && def.options) {
		const kinds = new Set<string>();
		for (const option of def.options) {
			const found = outputKinds(option);
			if (found === undefined) return undefined;
			for (const kind of found) kinds.add(kind);
		}
		return kinds;
	}
	if (def.type === "literal") return new Set(literalValues(def).map((value) => typeof value));
	if (def.type === "enum") return new Set(["string"]);
	if (["transform", "custom", "any", "unknown", "lazy"].includes(def.type)) return undefined;
	return new Set([def.type]);
}

/**
 * Every leaf `schema` declares that does not read the string an environment
 * variable arrives as (`readsEnvironmentString`), with its dot path under
 * `prefix`: through objects, a record's values (`*`) and a list's elements
 * (`[]`) — any of them a `${?VAR}` in an operator's own file can set, whether
 * or not a shipped file does. Sorted by path, each path once.
 */
export function unreadableLeaves(
	schema: z.ZodType,
	prefix = "",
): { readonly path: string; readonly leaf: z.ZodType }[] {
	const found = new Map<string, z.ZodType>();
	const walk = (node: z.ZodType, path: string) => {
		if (!readsEnvironmentString(node)) {
			if (!found.has(path)) found.set(path, node);
			return;
		}
		for (const body of bodiesOf(node)) {
			const def = defOf(body);
			const at = (key: string) => (path === "" ? key : `${path}.${key}`);
			if (def.type === "object" && def.shape) {
				for (const [key, child] of Object.entries(def.shape)) walk(child, at(key));
			} else if (def.type === "record" && def.valueType) {
				walk(def.valueType, at("*"));
			} else if (def.type === "array" && def.element) {
				walk(def.element, at("[]"));
			}
		}
	};
	walk(schema, prefix);
	// Each path is a key of `found` once, so no two compare equal.
	return [...found].sort(([a], [b]) => (a < b ? -1 : 1)).map(([path, leaf]) => ({ path, leaf }));
}

/** An object or a record a schema declares, at its path (`*`: any record key or list index). */
export interface SchemaObjectLevel {
	readonly path: readonly string[];
	readonly kind: "object" | "record";
	/** The object or record schema itself, its wrappers seen through. */
	readonly schema: z.ZodType;
}

/**
 * Every object and record `schema` declares, at its path: through objects, a
 * record's values and a list's elements, each form of a union and both sides
 * of an intersection listed at the same path. A lazy schema is followed until
 * it reaches a schema already on the way, which is listed there and not
 * entered again. In walk order, parents first.
 */
export function schemaObjectLevels(schema: z.ZodType): SchemaObjectLevel[] {
	const levels: SchemaObjectLevel[] = [];
	const walk = (node: z.ZodType, path: readonly string[], ancestors: ReadonlySet<z.ZodType>) => {
		for (const body of bodiesOf(node)) {
			// A schema met again on its own way down is listed once more, not entered.
			const again = ancestors.has(body);
			const within = new Set(ancestors).add(body);
			const def = defOf(body);
			if (def.type === "object" && def.shape) {
				levels.push({ path, kind: "object", schema: body });
				if (again) continue;
				for (const [key, child] of Object.entries(def.shape)) walk(child, [...path, key], within);
			} else if (def.type === "record" && def.valueType) {
				levels.push({ path, kind: "record", schema: body });
				if (again) continue;
				walk(def.valueType, [...path, "*"], within);
			} else if (def.type === "array" && def.element && !again) {
				walk(def.element, [...path, "*"], within);
			}
		}
	};
	walk(schema, [], new Set());
	return levels;
}

/** The paths of `unreadableLeaves`. */
export function unreadableLeafPaths(schema: z.ZodType, prefix = ""): string[] {
	return unreadableLeaves(schema, prefix).map(({ path }) => path);
}

/** A node of the tree `pickConfigSchema` builds: a picked leaf, or keys under it. */
type PickNode = { readonly leaf: z.ZodType } | { readonly children: Map<string, PickNode> };

/**
 * The one schema declared at `segments` inside `schema`, for a picked read — a
 * `RangeError` naming the path when there is none, or several, or when the
 * path runs beneath a value the schema transforms as a whole (a `.transform`):
 * a key read there would be what was written, not what the transform makes
 * of it, so the refusal names the shorter path to read instead. A
 * `z.preprocess` is read through.
 */
function pickedAt(schema: z.ZodType, segments: readonly string[]): z.ZodType {
	const path = segments.join(".");
	let candidates: z.ZodType[] = [schema];
	for (const [index, key] of segments.entries()) {
		const next: z.ZodType[] = [];
		for (const candidate of candidates) {
			let transformed = false;
			const bodies = bodiesOf(candidate, () => {
				transformed = true;
			});
			if (transformed) {
				const shorter = segments.slice(0, index).join(".");
				throw new RangeError(
					`cannot read "${path}": the configuration schema transforms "${shorter}" as a whole — read "${shorter}"`,
				);
			}
			for (const body of bodies) {
				const def = defOf(body);
				if (def.type === "object" && def.shape && Object.hasOwn(def.shape, key)) {
					next.push(def.shape[key] as z.ZodType);
				} else if (def.type === "record" && def.valueType) {
					next.push(def.valueType);
				}
			}
		}
		candidates = next;
	}
	if (candidates.length !== 1) {
		throw new RangeError(
			candidates.length === 0
				? `cannot read "${path}": the configuration schema declares no such key`
				: `cannot read "${path}": the configuration schema declares ${candidates.length} schemas there — read a shorter path`,
		);
	}
	return candidates[0] as z.ZodType;
}

/**
 * The default `schema` declares for an absent value, seen through the
 * wrappers around it (`.default()`, or `.prefault()`), or none.
 */
function declaredDefault(schema: z.ZodType): { readonly value: unknown } | undefined {
	const def = defOf(schema) as Def & { readonly defaultValue?: unknown };
	if (def.type === "default" || def.type === "prefault") return { value: def.defaultValue };
	if (WRAPPERS.has(def.type) && def.innerType) return declaredDefault(def.innerType);
	return undefined;
}

/**
 * The schema of `paths` alone inside `schema` (transitional), what a
 * composition root parses before it knows its modules: each path's own
 * schema as `schema` declares it there (wrappers, coercions, checks and
 * transforms included), under objects that hold only the picked keys. An
 * ancestor of a picked path is optional unless `schema` declares a default
 * for it; then an absent ancestor reads as that default. A path under another
 * picked path is covered by it.
 *
 * A path `schema` does not declare as one schema (a key no object on the way
 * declares, one a union offers several schemas for, or one beneath a value
 * the schema transforms whole) is a `RangeError` naming it and, for a
 * transform, the shorter path to read.
 */
export function pickConfigSchema(schema: z.ZodType, paths: readonly string[]): z.ZodObject {
	const root: Map<string, PickNode> = new Map();
	const sorted = [...new Set(paths)].sort((a, b) => a.split(".").length - b.split(".").length);
	for (const path of sorted) {
		const segments = path.split(".");
		if (segments.some((key) => key.length === 0)) {
			throw new RangeError(`cannot read "${path}": not a dot-separated path of non-empty keys`);
		}
		const leaf = pickedAt(schema, segments);
		let children = root;
		for (const [index, key] of segments.entries()) {
			const node = children.get(key);
			// Shorter paths come first: one already picked covers this one.
			if (node !== undefined && "leaf" in node) break;
			if (index === segments.length - 1) {
				children.set(key, { leaf });
				break;
			}
			const next = node ?? { children: new Map<string, PickNode>() };
			if (node === undefined) children.set(key, next);
			children = next.children;
		}
	}
	const build = (
		children: Map<string, PickNode>,
		prefix: readonly string[],
	): Record<string, z.ZodType> =>
		Object.fromEntries(
			[...children].map(([key, node]) => {
				if ("leaf" in node) return [key, node.leaf];
				const path = [...prefix, key];
				const picked = z.object(build(node.children, path));
				const declared = declaredDefault(pickedAt(schema, path));
				return [
					key,
					declared === undefined ? picked.optional() : picked.prefault(declared.value as never),
				];
			}),
		);
	return z.object(build(root, []));
}
