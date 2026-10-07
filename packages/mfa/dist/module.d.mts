/**
 * `mfaModule` and `mfaModules`: what a composition installs to turn MFA on
 * (installed is on).
 *
 * Requires core's three MFA ports (the name `mfa` is accepted only from a
 * module bound to them), `userSessionStore`, `sessionRequirementResolver`,
 * `csrfGuard` (every MFA POST runs it), `loginCompletion` (a verified second
 * factor finishes the login through it) and `deploymentMode` (the development
 * sample key is refused under `multi`, so a mode read as absent must not lift
 * that); reads `rateLimiter` — what limits the routes, which pass every
 * request through without one — `auditSink` and `subjectRevocation` (each
 * absence declared; the routes' admission of a signed-in session, and every
 * use of a login's transaction, reads the boundary), `logger`,
 * `mailSender` — where the account-email proof and a factor's codes go — and
 * `userRepository`, for the enrollment witness's write alone
 * (`markMfaEnrolled`). Nothing it keeps forks per replica.
 *
 * Reads its own section, `mfa` — the mode, its settings and the step-up
 * page, `mfa.page.url` — and the deployment mode from the `deploymentMode`
 * slot. The page's old path, `endpoints.mfa.url`, refuses the boot naming
 * the new one, and so does `ENDPOINTS_MFA_URL` set, whether or not
 * `MFA_PAGE_URL` is. `mfa.rateLimit` is removed: setting it refuses the boot.
 *
 * Contributes `sessionRequirements.mfa`. Its factory refuses the boot when
 * `mfa.mode` is `off` or unset, when no `sessionLifecycleStore` is wired beside
 * the user-session store (core's session lifecycle is required where one is
 * wired), when the package's settings are unusable (naming
 * the key), when `mfa.page.url` is unset, or when
 * `mfa.enrollment.requireEmailProof` is `always` and no `mailSender` is wired —
 * nobody could give the proof, so nobody could bind (the MFA ADR's D20). It
 * builds the key ring's sealing once per boot (so
 * `mfa_factor_sealed_with_retired_key` is logged once per key id) and keeps it,
 * with the requirement core issues `mfa.step_up` to and the enrollment
 * witness, for the same boot's routes (`mfaBootState`). It warns once each:
 * when the development sample key is in use; when the user-session store
 * cannot record a step-up (`mfa_step_up_unsupported`), admission's view then
 * saying no second factor can be recorded on any session, so the requirement
 * sends it to log in instead; when `when-mail` meets no
 * `mailSender`, so a first binding asks no proof
 * (`mfa_first_binding_without_email_proof`); and when the directory cannot
 * write the witness (`mfa_enrollment_witness_unwritable`).
 *
 * Claims the `mfa` prefix every `/session/mfa` POST limits under, with no
 * budget of its own: the wired limiter's `limits` and `defaultLimit` decide.
 *
 * Contributes `mfa.manage`, graded `credential_change`, as the admission
 * action its routes admit a signed-in session's enrollment, rename or removal
 * for, and `mfa.view`, graded `use`, for the list of its factors.
 *
 * Provides `mfaSubjectLeases`, authoritative: the subject's lease owner over
 * the MFA transaction store, built by this module from `mfa.storeTimeoutMs`
 * (`factorSet.mts`) — its routes build theirs from the same settings, so every
 * writer holds a lease of the same rules — and the one `mfaResetModule`
 * requires: the operator reset is available only where this module is
 * installed.
 *
 * Contributes the MFA routes (`routes.mts`) at `/session/mfa`, after the
 * session middleware. Their factory runs after every factor has registered,
 * so it checks the installed factors (`checkInstalledFactors`) first, and
 * the resolver holds `mfa.manage` (core's `checkResolver`). Without
 * `subjectRevocation` the subject's own release can lift the hard hold on a
 * rebind but never give the week or the backoff back early: said once at
 * warn (`mfa_lock_release_unavailable`).
 */
import { type Logger, type MfaFactorResolver, type Module, type SessionRequirement } from "@o3co/auth-provider-core";
import { type MfaSettings } from "./config.mjs";
import { type MfaSubjectLeases } from "./factorSet.mjs";
import { type FirstBindingMark } from "./firstBindingMark.mjs";
import { type MfaRequirementMode } from "./requirement.mjs";
import { type MfaSealing } from "./sealing.mjs";
import { type MfaEnrollmentWitness } from "./witness.mjs";
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        /** The subject's lease owner `mfaModule` builds from `mfa.storeTimeoutMs`: what every writer of a subject's factor set holds. */
        readonly mfaSubjectLeases?: MfaSubjectLeases;
    }
}
/** The id of the MFA routes' contribution: what another route orders itself against. */
export declare const MFA_ROUTES_ID = "mfa-routes";
/**
 * The key prefix every `/session/mfa` POST limits under on the wired limiter
 * (`mfa:ip:<ip>`), which the module claims with no budget. No `:`.
 */
export declare const MFA_RATE_LIMIT_PREFIX = "mfa";
/** What a composition root tells the MFA module that its configuration cannot. */
export interface MfaModuleOptions {
    /**
     * The name the deployment selected its configuration by — the standalone
     * passes `CONFIG_ENV || NODE_ENV` — read beside `NODE_ENV` by the
     * development sample key's refusal, which accepts the key only where each
     * name set says development or test, with at least one set.
     */
    readonly environment?: string;
}
/** What one boot of the MFA module built, for the routes of the same boot. */
export interface MfaBootState {
    readonly mode: MfaRequirementMode;
    readonly settings: MfaSettings;
    /** The one sealing of this boot, on the composition's logger. */
    readonly sealing: MfaSealing;
    /** The object the requirement's factory returned: the one core issued `mfa.step_up` to. */
    readonly requirement: SessionRequirement;
    /** The enrollment witness over the composition's directory. */
    readonly witness: MfaEnrollmentWitness;
    /** The one first-binding mark every reader of this boot judges by. */
    readonly firstBindingMark: FirstBindingMark;
    readonly logger: Logger;
}
/**
 * What the MFA module built in the boot whose `mfaFactorResolver` is
 * `factors`. Throws when that boot built none: the requirement's factory
 * runs before any route factory, so a route asking for it is in a boot
 * without the module.
 */
export declare function mfaBootState(factors: MfaFactorResolver): MfaBootState;
/**
 * `mfa.mode = "required"` with no counting factor enabled: the `cause` of the
 * boot's refusal, with its reason.
 */
export declare class MfaNoCountingFactorError extends RangeError {
    readonly reason = "mfa-no-counting-factor";
    /**
     * `enabledKinds`: the enabled factors, none counting, already admitted by core's
     * hint grammar. The module cannot tell which factor modules are installed, so the
     * message names the TOTP key only conditionally.
     */
    constructor(enabledKinds: readonly string[]);
}
/**
 * An enabled factor whose kind core's hint grammar refuses: a first
 * binding's answer lists the kinds (`hints.enrollable`), and core would
 * refuse that answer at every such login. The `cause` of the boot's
 * refusal; `JSON.stringify` quotes the kind, whatever it holds.
 */
export declare class MfaFactorKindUnhintableError extends RangeError {
    readonly reason = "mfa-factor-kind-unhintable";
    constructor(kind: string);
}
/**
 * More enabled counting factors than a hint list carries: a first binding's
 * `hints.enrollable` would list them all, and core would refuse that answer
 * at every such login. The `cause` of the boot's refusal.
 */
export declare class MfaTooManyFactorsError extends RangeError {
    readonly reason = "mfa-too-many-factors";
    constructor(count: number);
}
/**
 * The MFA module (see this file's header): the `mfa` session requirement and
 * the MFA routes' mount. `options.environment` reaches the development
 * sample key's refusal.
 */
export declare function mfaModule(options?: MfaModuleOptions): Module;
/**
 * What a composition lists to install MFA: the TOTP factor's module, the
 * recovery-code factor's, the email factor's (off by default), and the MFA
 * module.
 */
export declare function mfaModules(options?: MfaModuleOptions): readonly Module[];
//# sourceMappingURL=module.d.mts.map