/**
 * The pieces of boot's one composed parse of the configuration a composition
 * root hands `createApp` (the HOCON it resolved, never parsed first): how a
 * schema's parse is laid over what was written ({@link overlayConfig}), so a
 * key no schema declares is kept, not stripped; how a key is written; how a
 * Zod issue path is named to the operator; and how a refused parse becomes
 * one `RangeError` ({@link parsedOrRefused}).
 */
import type { z } from "zod";
/**
 * An object literal's kind of object: its prototype is `Object.prototype`, or
 * it has none. Configuration is merged, copied and written only through
 * these; anything else — a list, a `URL`, an instance a transform built — is
 * a value, taken whole.
 */
export declare function isPlainConfigObject(value: unknown): value is Record<string, unknown>;
/**
 * `over` (a schema's parse) laid on `under` (what was written), key by key
 * through plain objects (`isPlainConfigObject`):
 *
 * - where both hold a plain object, their keys are merged the same way;
 * - anywhere else the parsed value wins whole (a list, a `URL`, a value whose
 *   type the schema changed);
 * - a key the parse holds as `undefined` is removed: the schema made nothing
 *   of the value written there (an empty environment variable read as unset);
 * - a key the parse does not hold is kept as written, which is how a key no
 *   schema declares survives the parse.
 *
 * An `undefined` `over` answers `under`. Neither input is changed: every
 * object on a merged path is a new one, and a value only one side holds is
 * that side's own.
 */
export declare function overlayConfig(under: unknown, over: unknown): unknown;
/** `target[key] = value`, defined rather than assigned: a key named `__proto__` stays a key. */
export declare function defineConfigKey(target: Record<string, unknown>, key: string, value: unknown): void;
/** A Zod issue path as the operator writes it: its keys joined with dots. */
export declare function operatorPath(path: readonly PropertyKey[]): string;
/**
 * `value` parsed by `schema`, or a `RangeError` naming each issue at its
 * operator path (the whole configuration named as such), with the Zod error
 * as its `cause`. A parse that throws instead of answering — a getter on a
 * hand-built configuration — is a refusal like any other, carrying what it
 * threw as the `cause`, not an error escaping the reader.
 */
export declare function parsedOrRefused<T>(schema: z.ZodType<T>, value: unknown): T;
//# sourceMappingURL=composed.d.mts.map