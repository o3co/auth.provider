/**
 * The way to author a `federationTypes` declaration: a helper that ties the
 * factories' entry to the schema.
 *
 * Inside `defineModule({ … })` the record fixes the entry at `unknown` (no
 * per-key inference, and a method is bivariant in its entry), so a schema for
 * `{ issuer }` could pair with a factory typed for `{ clientId }` unnoticed.
 * The helper infers `E` from `entrySchema` and checks both factories,
 * properties here, strictly. `Deps` is written, not inferred: a nested call inside an
 * inferring `defineModule` cannot pick up the module's deps.
 */
import type { z } from "zod";
import type { Contributed, FederationInstance, FederationProvider, FederationRedirectPolicyContribution, FederationTypeContribution } from "./contributes-map.mjs";
/**
 * A `federationTypes` declaration as the helper takes it. The factories are
 * function properties, so their pairing with the schema is checked
 * contravariantly.
 */
export interface FederationTypeDeclaration<Deps, E> {
    readonly entrySchema: z.ZodType<E>;
    readonly factory: (deps: Deps, instance: FederationInstance<E>) => Contributed<FederationProvider>;
    readonly redirectPolicy: (deps: Deps, instance: FederationInstance<E>) => Contributed<FederationRedirectPolicyContribution>;
}
/**
 * Author a `federationTypes` declaration whose factories' entry is the entry
 * schema's output:
 *
 * ```typescript
 * contributes: {
 *   federationTypes: {
 *     oidc: defineFederationType<OidcModuleDeps>()({
 *       entrySchema: OidcEntry,
 *       factory: (deps, { name, entry }) => createOidcProvider(name, entry), // entry: z.output<typeof OidcEntry>
 *       redirectPolicy: (deps, { entry }) => createRedirectPolicy(entry),
 *     }),
 *   },
 * }
 * ```
 *
 * Curried so that `Deps` is written and `E` inferred. At run time it answers
 * the declaration it was given.
 */
export declare function defineFederationType<Deps>(): <E>(declaration: FederationTypeDeclaration<Deps, E>) => FederationTypeContribution<Deps, E>;
//# sourceMappingURL=define-federation-type.d.mts.map