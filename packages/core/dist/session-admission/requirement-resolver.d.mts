/**
 * The requirement resolver admission accepts: the one the boot planner or
 * `resolverForTests` built here, branded through a module-private `WeakSet`.
 * Anything else — a home-made object, a copy — is a `RangeError`.
 */
import type { AdmissionAction } from "./actions.mjs";
import type { RegisteredRequirement, SessionRequirementResolver } from "./requirement.mjs";
/** What a resolver is built over: the collectors' read side, or a test's lists. */
export interface SessionRequirementSource {
    get(name: string): RegisteredRequirement | undefined;
    entries(): IterableIterator<readonly [string, RegisteredRequirement]>;
    action(name: string): AdmissionAction | undefined;
}
/**
 * Builds the branded resolver over `source` and records it, so `admitSession`
 * knows it. `wrap` is the planner's read gate (closed while the `provides`
 * factories run); it is applied to the object recorded, which is the one a
 * consumer is handed. For the boot planner and `resolverForTests` alone.
 * @internal
 */
export declare function sessionRequirementResolverOver(source: SessionRequirementSource, wrap?: <T extends object>(view: T) => T): SessionRequirementResolver;
/**
 * Refuses a resolver the planner or `resolverForTests` did not build; a
 * home-made object or a copy forges nothing. Consumer factories run it on
 * their `requirements` at construction, with their own name as `factory` and
 * the names of the actions they admit as `admits`, so a missing or forged
 * resolver, or an admitted action no module registers, fails where the
 * composition is assembled rather than on a request. Admission also runs it
 * on every call.
 */
export declare function checkResolver(value: unknown, factory?: string, admits?: readonly string[]): SessionRequirementResolver;
//# sourceMappingURL=requirement-resolver.d.mts.map