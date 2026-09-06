import type { ComponentKey } from "./component-map.mjs";
import type { Module, ModuleSpec } from "./module-spec.mjs";
/**
 * Authoring entry point for v0.5.0 manifests. The `const` generic
 * parameters R and O capture the literal `requires` / `optional` arrays
 * at the call site without the author writing `as const`, so providers
 * and contribution factories receive a precisely-typed deps object.
 *
 * Per A2-α §3.1 (TypeScript 5.0+ `const` modifier on generic parameters).
 *
 * @example
 * ```typescript
 * export const myModule = defineModule({
 *   name: "my-module",
 *   requires: ["config"],         // inferred as readonly ["config"]
 *   provides: {
 *     auditSink: ({ config }) => createAuditSink(config),
 *   },
 * });
 * ```
 */
export declare function defineModule<const R extends ComponentKey = never, const O extends ComponentKey = never>(spec: ModuleSpec<R, O>): Module;
//# sourceMappingURL=define-module.d.mts.map