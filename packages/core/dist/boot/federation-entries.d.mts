import type { FederationProvider } from "../federations/types.mjs";
import type { DispatchedFederation, NameKeyedCollector, NormalisedModule, RegisteredFederationType } from "./types.mjs";
/** A `federationTypes` declaration's members, as normalisation read them. */
export interface FederationTypeSnapshot {
    readonly entrySchema: unknown;
    readonly factory: unknown;
    readonly redirectPolicy: unknown;
}
/**
 * The registration a `federationTypes` declaration contributes through: its
 * members read once, here, and a factory of the deps stage 4 hands every
 * contribution that answers a `RegisteredFederationType`, each factory bound
 * to those deps and called as the method it was declared as.
 */
export declare function federationTypeRegistration(declaration: object): (deps: Record<string, unknown>) => RegisteredFederationType;
/** What a `federationTypes` entry's registration read its declaration as; `undefined` for anything else. */
export declare function federationTypeSnapshot(registration: unknown): FederationTypeSnapshot | undefined;
/**
 * Every enabled `core.federations` entry is handled by the installed module
 * that registers its `type` under `federationTypes`; nothing else registers
 * a federation, since no module contributes and no host supplies the
 * `federations` or `federationRedirectPolicies` collector
 * (`contribution-kind-guarded`). An enabled entry whose type no module
 * registers is `federation-type-unhandled`, every such entry listed at once
 * with its type, and the types handled. The message names each entry and its
 * type, and quotes nothing else of it. A disabled entry is not read; that
 * every entry names a type is core's schema's.
 * @internal
 */
export declare function checkFederationEntriesHandled(modules: readonly NormalisedModule[], config: unknown): void;
/**
 * Parses each enabled `core.federations` entry whose `type` a module
 * registers, in the configuration's key order: its name held to the
 * federation-name rule, its `callbackURL` a non-empty string, and the rest of
 * it — the keys core owns removed — parsed synchronously by the type's
 * `entrySchema` as stage 1 read it, then copied and frozen. Answers what
 * stage 4 dispatches. Any refusal makes one `config-validation-failed`
 * naming every issue at the path the operator wrote
 * (`core.federations.<name>…`), each refused entry listed with the module
 * whose declaration of its type is in force and its path; a schema that
 * throws, or answers a value that throws as it is copied, is an issue at the
 * entry. Two such entries never share a `callbackURL`: the callback answers
 * only the federation its path names, so only one of the two could complete
 * a login. Each entry after the first that carries one is an issue at its
 * `callbackURL`, naming the first; the values are compared as written, and
 * the message quotes none of them. An entry is flat: a key named after its
 * type is read as one of the type's keys, and the refusal of a missing
 * `callbackURL`, or a type's schema's refusal of that key as unrecognized,
 * says so when that key holds an object. Runs after
 * `checkFederationEntriesHandled`, so every enabled entry's type is
 * registered.
 * @internal
 */
export declare function parseFederationEntries(modules: readonly NormalisedModule[], config: unknown): readonly DispatchedFederation[];
/** What one dispatched entry builds: its provider and its redirect policy, registered as a pair. */
export interface DispatchedPair {
    readonly provider: FederationProvider;
    readonly redirectPolicy: unknown;
}
/**
 * Builds the provider and the redirect policy of one dispatched entry with
 * its type's registered factories, the provider first. Throws — for the
 * caller to report as the contribution's failure — when a factory throws,
 * when the provider is not an object named after its entry
 * (`namedProvider`), or when the policy is not an object. Registers nothing:
 * the caller registers both, or neither.
 * @internal
 */
export declare function buildDispatchedFederation(federation: DispatchedFederation, types: NameKeyedCollector<RegisteredFederationType> | undefined): Promise<DispatchedPair>;
//# sourceMappingURL=federation-entries.d.mts.map