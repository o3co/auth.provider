import type { Module } from "../modules/manifest/module-spec.mjs";
/**
 * Every leaf the modules' section schemas declare, each at its module's name,
 * that would refuse an environment variable's string — a bare `z.boolean()`, or a
 * `z.number()` that does not coerce — as `<module>: <path>`, sorted. A record's value is `*`, a list's
 * element `[]`.
 */
export declare function unreadableModuleLeaves(modules: readonly Module[]): string[];
//# sourceMappingURL=environmentLeaves.d.mts.map