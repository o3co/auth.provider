/**
 * boot/parsed-values.mts: how stage 1 parses a piece of the configuration
 * with a schema a module declared — synchronously, a throw answered as an
 * issue — and the frozen copy of what the schema answered, which every
 * factory reading it receives. Shared by the modules' sections, the
 * `core.federations` entries dispatched to a type and the `config` slot.
 */
import type { z } from "zod";
/**
 * A parsed section as every factory of its module receives it: plain data —
 * arrays, and objects whose prototype is `Object.prototype` or `null` —
 * copied and frozen all the way down, so no factory can change what another
 * reads, and a subtree the schema passed through (`z.unknown()`) is not the
 * `config` slot's own object. Anything else — a `URL`, a `Buffer`, a class
 * instance a transform built — is handed over as the schema made it: freezing
 * a typed array throws, and copying an instance would lose what it is.
 *
 * Stage 1 also makes the whole parsed configuration into the `config` slot
 * with it, so every module that requires `config`, and core, read one frozen
 * copy that no module can change.
 */
export declare function frozenSection(value: unknown, copies?: Map<object, unknown>): unknown;
/**
 * Parse `value` with one schema of stage 1 — core's base or a module's
 * section — synchronously. A schema
 * that throws instead of answering — an async refinement (Zod cannot finish
 * it synchronously), or a transform or a getter that throws — is one more
 * issue at the root of what it parsed, naming `subject`, so it refuses boot
 * the way a refused value does rather than escaping stage 1 as a bare error.
 */
export declare function parseSection(schema: z.ZodType, value: unknown, subject?: string): {
    readonly data: unknown;
} | {
    readonly issues: readonly z.ZodIssue[];
};
//# sourceMappingURL=parsed-values.d.mts.map