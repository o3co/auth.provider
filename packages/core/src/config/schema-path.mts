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
 * Where a configuration path lands in a Zod schema (#728): the schema that
 * parses the value at a dot path, found by walking the schema's objects and
 * the wrappers a configuration schema puts around them. Two readers use it:
 * the transitional reader's picked schema (`pickConfigSchema`, what a
 * composition root reads before it knows its modules) and the guard that
 * every leaf an environment variable sets reads the string it arrives as.
 */

import type { z } from "zod";

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
}

const defOf = (schema: z.ZodType): Def => (schema as unknown as { _zod: { def: Def } })._zod.def;

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
function bodiesOf(schema: z.ZodType): z.ZodType[] {
	const def = defOf(schema);
	if (WRAPPERS.has(def.type) && def.innerType) return bodiesOf(def.innerType);
	if (def.type === "pipe" && def.in && def.out) {
		return defOf(def.out).type === "transform" ? bodiesOf(def.in) : bodiesOf(def.out);
	}
	if (def.type === "union" && def.options) return def.options.flatMap(bodiesOf);
	if (def.type === "intersection" && def.left && def.right) {
		return [...bodiesOf(def.left), ...bodiesOf(def.right)];
	}
	if (def.type === "lazy" && def.getter) return bodiesOf(def.getter());
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

/**
 * Whether `schema` reads the string an environment variable arrives as, for
 * a value it would otherwise refuse as a string: `false` only for a bare
 * `z.boolean()` or a `z.number()` that does not coerce — seen through its
 * wrappers, and for a union only when none of its members reads a string. A
 * `z.preprocess` reads it (its function sees the string first), as does a
 * `z.coerce.number()`, a string, an enum or anything else.
 */
export function readsEnvironmentString(schema: z.ZodType): boolean {
	const def = defOf(schema);
	if (WRAPPERS.has(def.type) && def.innerType) return readsEnvironmentString(def.innerType);
	if (def.type === "pipe" && def.in) {
		return defOf(def.in).type === "transform" || readsEnvironmentString(def.in);
	}
	if (def.type === "union" && def.options) return def.options.some(readsEnvironmentString);
	if (def.type === "boolean") return false;
	if (def.type === "number") return def.coerce === true;
	return true;
}

/**
 * Every leaf `schema` declares that does not read the string an environment
 * variable arrives as (`readsEnvironmentString`), as a dot path under
 * `prefix`: through objects, a record's values (`*`) and a list's elements
 * (`[]`) — any of them a `${?VAR}` in an operator's own file can set, whether
 * or not a shipped file does. Sorted, each once.
 */
export function unreadableLeafPaths(schema: z.ZodType, prefix = ""): string[] {
	const found = new Set<string>();
	const walk = (node: z.ZodType, path: string) => {
		if (!readsEnvironmentString(node)) {
			found.add(path);
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
	return [...found].sort();
}
