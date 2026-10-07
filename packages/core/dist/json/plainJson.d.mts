/**
 * The one rule for a value JSON gives back as it is, and the copy taken by
 * it: each field read once, frozen at every depth, so whatever acts on the
 * copy acts on what was checked, and nothing a reader runs (a getter, a
 * Proxy trap) can answer one thing to the check and another to the writer.
 *
 * Taken as it is:
 * - `null`, a boolean, a string, a finite number other than `-0` (JSON writes
 *   it as `0`);
 * - a plain array (prototype `Array.prototype`): its `length` read once, its
 *   own keys exactly its indices — a hole, or a field of its own JSON would
 *   drop, is refused — each index read once; `undefined` in it is refused,
 *   since JSON would write `null`;
 * - a plain object (prototype `Object.prototype` or none, read once): each
 *   own key read once — an own getter runs once — one read as `undefined`
 *   left out as JSON leaves it out, an own `__proto__` kept as the field it is.
 *
 * Every own key of either must be one JSON writes — a string, enumerable — so
 * a symbol's field or a hidden one, a hidden `toJSON` among them, is refused
 * rather than lost. An object two fields share is copied once.
 *
 * Anything else is refused, naming where: a class's instance, an Array
 * subclass, a built-in (a Date, a Map, a RegExp, a boxed number, a Proxy over
 * any of them), a function, a symbol, a bigint, `undefined`, NaN, an
 * infinity, `-0`, a cycle, a read that throws, and nesting past the stack, the
 * copy's or JSON's. So a value is taken whole or not at all, never in part.
 */
/**
 * What {@link copyPlainJson} answers: the frozen copy, or where the value is
 * not one JSON gives back as it is — a path from the value itself, `""` for
 * the value, `.name` for an object's field and `[index]` for a list's entry
 * (`.a[0].b`). The keys are written as they are, not escaped, so a key
 * holding `.` or `[` reads as more than one step; the path is for a reader,
 * never parsed. It is as long as the nesting it names: a value nested
 * thousands deep is refused at a path thousands of steps long.
 */
export type PlainJsonCopy = {
    readonly ok: true;
    readonly copy: unknown;
} | {
    readonly ok: false;
    readonly at: string;
};
/**
 * `value` as its plain JSON copy (see this file's header), or where it is not
 * one. Never throws: whatever a read throws, a Proxy's trap included, is a
 * refusal there, and nothing of the thrown value is run to tell.
 */
export declare function copyPlainJson(value: unknown): PlainJsonCopy;
/**
 * {@link copyPlainJson}, but `-0` read as `0`, as `JSON.stringify` writes it,
 * rather than refused. Internal to core: stage 1 copies a configuration with
 * it, where HOCON resolves `-0` from what an operator wrote and boot always
 * read it as `0`.
 */
export declare function copyPlainJsonNegativeZeroAsZero(value: unknown): PlainJsonCopy;
//# sourceMappingURL=plainJson.d.mts.map