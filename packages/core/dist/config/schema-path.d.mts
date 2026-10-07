/**
 * Where a configuration path lands in a Zod schema: the schema that
 * parses the value at a dot path, found by walking the schema's objects and
 * the wrappers a configuration schema puts around them. Two readers use
 * it: the guard that every leaf an environment variable sets reads the
 * string it arrives as, and the check that a section refuses an unknown key
 * at every object level it declares (`schemaObjectLevels`).
 */
import type { z } from "zod";
/**
 * Every schema that parses the value at `path` inside `schema` — more than
 * one where a union or an intersection offers several — or none when the
 * path leaves what `schema` declares: a key no object on the way declares, a
 * list, a scalar. A record's value schema answers any key. The schemas are
 * the ones declared at the path, wrappers included.
 */
export declare function schemasAtPath(schema: z.ZodType, path: readonly string[]): z.ZodType[];
/**
 * Names `schema` as one of core's environment coercers (`coerceBooleanFromEnv`,
 * each `wholeNumberFromEnv`), whose preprocess reads the string a `${?VAR}`
 * carries into the type its schema takes, so `readsEnvironmentString` trusts
 * it. Tagged rather than probed: a probe ("false", "1") would run the
 * schema's own bounds and refinements, and report a leaf that refuses `"1"`
 * as too small as one that cannot read a string. Any other preprocess is
 * judged by the schema it hands on. Answers `schema`.
 * @internal
 */
export declare function environmentCoercer<T extends z.ZodType>(schema: T): T;
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
export declare function readsEnvironmentString(schema: z.ZodType): boolean;
/**
 * The kinds of value `schema` produces — `"boolean"`, `"number"`,
 * `"string"`, `"object"`… — seen through its wrappers and a preprocess, or
 * `undefined` when it cannot be told without running it (a `.transform`, a
 * custom schema): each member of a union adds its own.
 */
export declare function outputKinds(schema: z.ZodType): ReadonlySet<string> | undefined;
/**
 * Every leaf `schema` declares that does not read the string an environment
 * variable arrives as (`readsEnvironmentString`), with its dot path under
 * `prefix`: through objects, a record's values (`*`) and a list's elements
 * (`[]`) — any of them a `${?VAR}` in an operator's own file can set, whether
 * or not a shipped file does. Sorted by path, each path once.
 */
export declare function unreadableLeaves(schema: z.ZodType, prefix?: string): {
    readonly path: string;
    readonly leaf: z.ZodType;
}[];
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
export declare function schemaObjectLevels(schema: z.ZodType): SchemaObjectLevel[];
/** The paths of `unreadableLeaves`. */
export declare function unreadableLeafPaths(schema: z.ZodType, prefix?: string): string[];
//# sourceMappingURL=schema-path.d.mts.map