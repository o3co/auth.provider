/**
 * `resolverForTests`: the branded `SessionRequirementResolver` a test builds
 * when it constructs a consumer by hand. It is registered in the same set as
 * the boot planner's, so the brand stops accidents, not a deployment that
 * imports the testing entry on purpose. Each requirement is registered and
 * its reach sealed as boot does, and at most one may declare the
 * second-factor authority; each action is registered as boot registers one,
 * and no remediation may take an action's name. `allowAnyReach` lifts the
 * reach rules (the snapshot stays) for tests of admission's own mechanics
 * that need two reaching requirements; nothing else uses it.
 */
import { type AdmissionActionDeclaration } from "../actions.mjs";
import { type SessionRequirement, type SessionRequirementResolver } from "../requirement.mjs";
/**
 * The resolver a test hands a consumer: `requirements` by their names, in the
 * order given, and `actions` — what a consumer's module registers under
 * `contributes.admissionActions` — by theirs. Two requirements of one name,
 * or two that declare the second-factor authority, are refused before any
 * reach is read, as boot orders them. With `issuer`, each page is held to
 * that origin. Each reach is read once, here, held to boot's rules unless
 * `allowAnyReach`, and the resolver answers that snapshot. The authority's
 * binding to the MFA ports is boot's alone.
 */
export declare function resolverForTests(requirements: readonly SessionRequirement[], options?: {
    readonly issuer?: string;
    readonly allowAnyReach?: boolean;
    readonly actions?: Readonly<Record<string, AdmissionActionDeclaration>>;
}): SessionRequirementResolver;
//# sourceMappingURL=resolver.d.mts.map