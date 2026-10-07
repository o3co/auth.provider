/**
 * The vocabulary of session admission (ADR 2026-09-28-session-admission):
 * the claim, the request, the `Admission` answer, `SessionRequirement` with
 * its input and verdict, the step-up page, and the establishment half
 * (`PrimaryAuthentication`, the interruption, the `PrimaryContinuation`,
 * the `Establishment` capability). Types and the registration checks only;
 * the decisions are made in `admit.mts` and its stage files. The brands are
 * type-level here and runtime-checked where each is built (`request-check.mts`,
 * `requirement-resolver.mts`, `establishment.mts`, `admit.mts`), so an `as`
 * cast forges the type and nothing else.
 */
import type { AuditSink } from "../audit/types.mjs";
import type { Logger } from "../logging/Logger.mjs";
import type { CodeAuthentication, CodeData } from "../repositories/types.mjs";
import type { RecordedAuthentication } from "../user-sessions/authentication.mjs";
import type { SessionLifecycleStore } from "../user-sessions/lifecycle/types.mjs";
import type { SessionAuthentication, SessionEnrollmentFacts, SubjectRevocation, UserSession, UserSessionClaims, UserSessionStore } from "../user-sessions/types.mjs";
import { type AcrTable } from "./acr.mjs";
import type { AdmissionAction } from "./actions.mjs";
/**
 * The stores admission reads itself, by the name an `unavailable` admission
 * gives each one's outage. Every other `Admission.store` is a requirement's
 * name, so no requirement may register under one of these: a consumer that
 * tells an outage by its store never takes a requirement's for a store's.
 */
export declare const ADMISSION_INFRASTRUCTURE_STORES: readonly ["user_session", "revocation_boundary", "session_lifecycle"];
/** A store admission reads itself, by the name its outage is given. */
export type AdmissionInfrastructureStore = (typeof ADMISSION_INFRASTRUCTURE_STORES)[number];
/** Whether `store` names one of admission's own stores — else it is a requirement's name. */
export declare const isAdmissionInfrastructureStore: (store: unknown) => store is AdmissionInfrastructureStore;
/**
 * What an `unavailable` admission is described as to the client: either of
 * admission's own stores by name, anything else as a requirement's outage,
 * never by the requirement's name (that is the operator's, for the log
 * line). One text for every consumer.
 */
export declare const describeAdmissionOutage: (store: string) => string;
declare const claimBrand: unique symbol;
declare const resolverBrand: unique symbol;
declare const establishmentBrand: unique symbol;
declare const interruptionBrand: unique symbol;
declare const issuedBrand: unique symbol;
/**
 * A remediation action core issued to a requirement at registration: branded
 * at the type level, and recognised by identity at run time, so a copy or a
 * literal is not one.
 */
export type IssuedRemediationAction = AdmissionAction & {
    readonly [issuedBrand]: true;
};
/**
 * What a consumer holds about the session before it is read: the one reading
 * of each carrier — the cookie, a code record, a link transaction — built by
 * `admit.mts`'s claim builders and nowhere else (branded, and checked at
 * runtime like the resolver).
 */
export interface SessionClaim {
    readonly [claimBrand]: true;
    readonly authenticated: boolean;
    /** A token carrier's is optional: without one the live read is skipped. */
    readonly sid: string | undefined;
    /** `undefined` only for a carrier that has none: the code record's first read. */
    readonly subject: string | undefined;
    readonly carrier: "cookie" | "code" | "link" | "token";
    /** A token carrier only: the `amr` the verified token carries, for the requirements; absent when the token carries none. */
    readonly tokenAmr?: readonly string[];
    /** A cookie carrier only: the cookie session's renewal nonce, compared with the record's; absent when it holds none. */
    readonly renewalNonce?: string;
}
/** What the request asks beyond the action: `acr_values`, at `/authorize` only. */
export interface AdmissionAsks {
    readonly acrValues?: readonly string[];
}
export interface AdmissionRequest {
    readonly claim: SessionClaim;
    /**
     * What the consumer is about to let the session do: the name of an action
     * a module registered under `contributes.admissionActions`, admitted with
     * the grade it registered, or a remediation action core issued to a
     * requirement.
     */
    readonly action: string | IssuedRemediationAction;
    readonly asks?: AdmissionAsks;
}
/** The consumer's own slots, as wired, and the resolver the planner built. */
export interface AdmissionDeps {
    readonly userSessionStore: UserSessionStore | undefined;
    readonly subjectRevocation: SubjectRevocation | undefined;
    /**
     * The consumer's `sessionLifecycleStore` slot, read after a live record:
     * its record closing or closed, or no record for the sid (an absent record
     * reads as closed), is `not_live` (`closing`). Required where
     * `userSessionStore` is handed: without it a live record is `unavailable`
     * (`session_lifecycle`).
     */
    readonly sessionLifecycleStore?: SessionLifecycleStore | undefined;
    /** The synthetic key `sessionRequirementResolver`; only the boot planner and `resolverForTests` build one. */
    readonly requirements: SessionRequirementResolver;
    /** The vouchable table; empty when the consumer has none. */
    readonly acrTable: AcrTable;
    readonly logger: Logger | undefined;
    /** The consumer's slot, for `session.admission.subject_mismatch`. */
    readonly auditSink: AuditSink | undefined;
    /** Defaults to the wall clock; a test seam. */
    readonly now?: () => Date;
}
/** The deployment's page for a step-up; `checkStepUpPage` validates it at registration. */
export interface StepUpPage {
    /** A path, or an absolute URL on the issuer's origin. */
    readonly url: string;
    /** Never the consumer's return parameter: `redirect_to` is reserved. */
    readonly params: Readonly<Record<string, string>>;
}
/**
 * The page as it is registered: validated, copied, and resolved once
 * on the issuer it was validated on — what a `step_up` admission carries.
 */
export interface RegisteredStepUpPage extends StepUpPage {
    /**
     * Where the step-up starts, as a browser is sent there: `url` resolved on
     * the issuer, `params` on the query — one absolute URL with no return
     * parameter (`stepUpPageUrl`). Every consumer answers or navigates from
     * it; none resolves the page itself.
     */
    readonly href: string;
}
/**
 * `page` as a requirement may declare it: `url` a path that stays on the
 * issuer's origin once resolved as a browser resolves a `Location` (not
 * `//host` or `/\host`), or an absolute `http(s)` URL on `issuer`'s origin
 * (any origin when no issuer is given); never a backslash, an encoded one or
 * a control character; `params` strings, without `redirect_to`. Answers a
 * frozen copy; anything else is a `RangeError` naming what is wrong.
 */
export declare function checkStepUpPage(page: unknown, issuer?: string): StepUpPage;
/**
 * The step-up page as a browser is sent to it: `page.url` resolved on
 * `issuer`, each param set on the query (`searchParams.set`, never
 * concatenation), as one absolute URL. Registration computes it once, as the
 * registered page's `href`. No return parameter is added: `/authorize` sets
 * its own on the `href`, and a JSON consumer answers it as it is.
 * @internal
 */
export declare function stepUpPageUrl(page: StepUpPage, issuer: string): string;
/** A projection of the live record — never the record itself, so a requirement cannot read the raw `amr`. */
export interface SessionView {
    readonly sid: string;
    readonly sub: string;
    readonly authTime: Date;
    readonly expiresAt: Date;
    /** A frozen copy of the record's `enrollmentFacts` when it holds ones the type admits; absent otherwise. Never the `User`. */
    readonly enrollmentFacts?: SessionEnrollmentFacts;
    /**
     * Whether a second factor verified in this session can be recorded on it:
     * the session store has the step-up capability
     * (`supportsSecondFactorUpdate`) and `canRecordSecondFactor` is true of
     * the record. Admission decides it once per admission over a live record,
     * when it reads the record into this view, and sets it on every view it
     * builds, so a requirement can choose `step_up` or `reauthenticate` on it,
     * and a route can refuse to open a step-up it is `false` for, without
     * either reading the store or the record's shape. A view built by hand
     * sets it too.
     */
    readonly secondFactorRecordable: boolean;
}
/**
 * How a live session was established and what it vouches for: built by
 * `requirementSession(session)`
 * (`../user-sessions/authentication.mts`) and nowhere else in product code.
 */
export interface RequirementSession {
    /** `sessionAuthentication(session)`: `undefined` when its primary cannot be told. */
    readonly authentication: SessionAuthentication | undefined;
    /** `vouchedAmr(session)`: what the provider vouches for, and all `acr` is matched against. */
    readonly amr: readonly string[];
}
export interface RequirementInput {
    /** The view of the record admission read once; `null` without a store. */
    readonly session: SessionView | null;
    /**
     * `requirementSession(session)` when a record was read — the primary,
     * `mfaAt`, the vouched `amr` — and, for a token carrier without one,
     * `requirementSessionFromAmr(tokenAmr)`; `null` otherwise.
     */
    readonly authentication: RequirementSession | null;
    /** What the claim was built from. */
    readonly carrier: SessionClaim["carrier"];
    /** The record's `sub` when one was read, else the claim's subject: `undefined` only on the code record's first read. */
    readonly subject: string | undefined;
    /** The action as registered, frozen; never a `remediation`, which no requirement is asked about. */
    readonly action: AdmissionAction;
    readonly asks: AdmissionAsks | undefined;
    readonly now: Date;
}
/**
 * A `step_up` names no page of its own: admission answers the requirement's
 * registered `stepUpPage`, copied and validated at registration, so nothing
 * a requirement answers at request time reaches a redirect unvalidated.
 */
export type RequirementVerdict = {
    readonly outcome: "met";
} | {
    readonly outcome: "reauthenticate";
} | {
    readonly outcome: "step_up";
    readonly whenStillUnmet: "reauthenticate" | "unmet";
} | {
    readonly outcome: "unmet";
};
/**
 * A condition an extension adds to admission, contributed under the
 * `sessionRequirements` kind by the key `name`. MFA is the first.
 */
export interface SessionRequirement {
    /** The key it is contributed under; refused at boot otherwise (the `mfaFactors` rule). */
    readonly name: string;
    /**
     * Whether this is the second-factor authority: the one requirement that may
     * reach and add `SECOND_FACTOR_AMR` values and `mfaAt`, bound at boot to
     * core's MFA ports. At most one per composition; absent is `false`. Core
     * weighs this, never a name.
     */
    readonly secondFactorAuthority?: boolean;
    /** The `amr` values a step-up through this requirement can add; empty when it offers none. */
    readonly reach: ReadonlySet<string>;
    /** Where that step-up starts: required when `reach` is not empty, allowed when it is (a re-consent). Copied and validated at registration; a `step_up` verdict names no page of its own. */
    readonly stepUpPage: StepUpPage | undefined;
    /** The names of this requirement's own remediation routes: the only actions admission accepts as `remediation`. */
    readonly remediations: readonly string[];
    /** The keys an interruption's `hints` may carry; declared at registration, so an out-of-tree requirement is held to it at runtime. */
    readonly hintKeys: readonly string[];
    /** Use-time: a view of the session, read once by admission, and the action. Throws only on an outage. */
    admit(input: RequirementInput): Promise<RequirementVerdict>;
    /**
     * Establishment-time; absent when the requirement never interrupts a
     * login. Never asked again in a login once its own interruption completes;
     * a requirement that answered `establish` is asked again on each
     * resumption.
     */
    admitPrimary?(primary: PrimaryAuthentication): Promise<"establish" | RequirementInterruption>;
}
/** Whether `key` may name a hint: the identifier form, and not a reserved name. */
export declare const isHintKey: (key: unknown) => key is string;
/** Whether `value` may be one hint's text: an enum-like token. */
export declare const isHintToken: (value: unknown) => value is string;
/**
 * Whether `value` is a copy `registeredRequirement` made — never the object
 * a factory returned, nor a copy of a registered one.
 * @internal
 */
export declare const isRegisteredRequirement: (value: unknown) => value is RegisteredRequirement;
/**
 * The remediation actions core issued to a requirement, keyed by route
 * (`step_up` for `mfa.step_up`), answered to the module that holds the
 * object its factory returned and to nothing else: the resolver hands out
 * the registered copy, which carries none of them, so a consumer holding
 * the resolver cannot obtain a `remediation` action. `undefined` for an
 * object that was never registered, a copy of one, or the registered copy.
 * A requirement object is registered once, and its actions are read in the
 * boot that registered it: registering the same object again (the last
 * registration wins) issues it new ones, which the earlier boot's resolver
 * refuses.
 */
export declare function issuedRemediationActions(requirement: SessionRequirement): Readonly<Record<string, IssuedRemediationAction>> | undefined;
/** The issued actions of a registered copy, for admission's own check. @internal */
export declare const issuedActionsOf: (copy: SessionRequirement) => Readonly<Record<string, IssuedRemediationAction>> | undefined;
/** Whether `action` is one core issued to a registered requirement — never a literal or a copy. */
export declare const isIssuedAction: (action: unknown) => action is IssuedRemediationAction;
/**
 * A requirement as the resolver answers it: the registered copy, with its
 * own resolved page, lists and sealed reach, and nothing more. The
 * remediation actions issued to it reach the contributing module through
 * `issuedRemediationActions`, never the resolver.
 */
export interface RegisteredRequirement extends SessionRequirement {
    readonly stepUpPage: RegisteredStepUpPage | undefined;
    /** The declaration as it was read once at registration: `false` when absent. */
    readonly secondFactorAuthority: boolean;
}
/**
 * `value` as it is registered: its shape held to the contract and copied,
 * each field read once, so what the resolver answers at request time is
 * what was registered. `name` must be RFC 6749 error-code characters and
 * not one of admission's own store names; `secondFactorAuthority` is `true`,
 * `false` or absent (read as `false`); `stepUpPage` is checked and resolved
 * once to its `href` on `issuer` (a path page with no issuer is refused);
 * `admit` and `admitPrimary` delegate to the value's.
 *
 * `reach` is NOT read here: it may be a getter over what registers in the
 * same pass (MFA's, over `mfaFactorResolver`). `sealRegisteredReach` reads
 * and seals it at the end of boot's stage 4, so request-time readers see
 * what boot checked; until then the copy answers the value's own. A
 * `RangeError` names what is wrong; the boot planner reports it as the
 * contribution's failure.
 */
export declare function registeredRequirement(value: unknown, issuer?: string): RegisteredRequirement;
/**
 * A registered requirement's `reach`, read once after the name-keyed pass
 * and held to the one home of these rules: an iterable of non-empty strings,
 * no primary's marker (`pwd`, `fed`), a `stepUpPage` when not empty, and a
 * second-factor value or any value at all only from the second-factor
 * authority (only its step-up is ever written into a live session). Boot,
 * `resolverForTests` and the contract suite all run it. Answers a read-only
 * snapshot and seals a registered copy on it; a refused reach is not sealed.
 * `remedy` is appended to the refusal of a non-empty reach from any other.
 */
export declare function sealRegisteredReach(requirement: RegisteredRequirement, remedy?: string): ReadonlySet<string>;
/**
 * Seals a registered copy's reach as boot does — read once, a frozen
 * snapshot the copy answers afterwards — without the rule
 * `sealRegisteredReach` holds it to, which the contract suite and boot do.
 * For `resolverForTests` alone.
 * @internal
 */
export declare function snapshotReach(requirement: RegisteredRequirement): ReadonlySet<string>;
/** The registered requirements among `requirements` that declare the second-factor authority, in order: at most one may. */
export declare const secondFactorAuthorities: (requirements: Iterable<RegisteredRequirement>) => RegisteredRequirement[];
/**
 * Refuses a registered requirement whose remediation is the name of a
 * registered action — `registrant` answers who registered it — naming the
 * registrant: as a remediation it would skip every requirement for that
 * action. Boot and `resolverForTests` run it once both kinds have registered.
 */
export declare function checkRemediationsAgainstActions(requirement: RegisteredRequirement, registrant: (name: string) => string | undefined): void;
/**
 * The read side of the `sessionRequirements` kind — the synthetic key
 * `sessionRequirementResolver`: `entries()` in registration order,
 * `get(name)` — and of the `admissionActions` kind: `action(name)`, the
 * registered action of that name. Branded: only the boot planner and
 * `resolverForTests` build one, and `admitSession` refuses any other.
 */
export interface SessionRequirementResolver {
    readonly [resolverBrand]: true;
    readonly get: (name: string) => RegisteredRequirement | undefined;
    readonly entries: () => IterableIterator<readonly [string, RegisteredRequirement]>;
    readonly action: (name: string) => AdmissionAction | undefined;
}
export type Admission = {
    readonly outcome: "admitted";
    readonly session: UserSession | null;
    /** Admission's view of the record, equal to what the requirements are handed; `null` without a record. */
    readonly view: SessionView | null;
    readonly acr: string | undefined;
    /**
     * What a code minted on this admission records of how its session had
     * authenticated — `CodeData`'s `amr` and `authentication` — from the
     * reading the requirements judged: a frozen copy. Over a record, what
     * it vouches for and its primary with `mfaAt`, the primary `undefined`
     * when it cannot be told; over a token or a code, what each carries;
     * without a record for a cookie or a code, nothing.
     */
    readonly codeFields: {
        readonly amr: CodeData["amr"];
        readonly authentication: CodeAuthentication | undefined;
    };
    /**
     * The record's renewal nonce as admission read it, absent when the record
     * holds none or a value that is not a nonce: what a consumer writing the
     * record next expects of it
     * (`recordSecondFactor`'s `expectedRenewalNonce`). When present for a
     * cookie carrier, the cookie session presented the same one; a cookie
     * session's nonce over a record without one is not carried.
     */
    readonly renewalNonce?: string;
} | {
    readonly outcome: "unauthenticated";
} | {
    readonly outcome: "not_live";
    /**
     * `renewed`: the record is bound to another cookie session, one a renewal moved it to.
     * `closing`: the session's lifecycle record is closing or closed, or
     * absent (an absent record reads as closed).
     */
    readonly reason: "no_subject" | "no_sid" | "gone" | "subject_mismatch" | "renewed" | "closing";
} | {
    readonly outcome: "revoked";
} | {
    readonly outcome: "reauthenticate";
    readonly requirement: string;
    readonly session: UserSession | null;
} | {
    readonly outcome: "step_up";
    readonly requirement: string;
    readonly session: UserSession;
    /** Admission's view of the record, equal to what the requirements are handed. */
    readonly view: SessionView;
    /** The requirement's page as registered: `href` is where a consumer sends the browser. */
    readonly page: RegisteredStepUpPage;
    readonly acrValues: readonly string[];
    readonly whenStillUnmet: "reauthenticate" | "unmet";
} | {
    readonly outcome: "unmet";
    readonly requirement: string;
    readonly session: UserSession | null;
} | {
    readonly outcome: "unavailable";
    /** One of admission's own stores (`user_session`, `revocation_boundary`), or the name of the requirement that could not answer; {@link describeAdmissionOutage} words it for a client. */
    readonly store: string;
};
/** A primary authentication that has just succeeded, as the login route hands it over. */
export interface PrimaryAuthentication {
    /** `User.id`. */
    readonly subject: string;
    /** What `req.session.user` will hold. */
    readonly user: Readonly<Record<string, unknown>>;
    /** What the session record's `claims` will hold: the route's `extractUserClaims(user)` for a password login, the merged envelope for a federated one. */
    readonly claims: UserSessionClaims;
    /** The `amr` and `authentication` the session would be created with. */
    readonly recorded: RecordedAuthentication;
    /** What the session will record of `user` for a first binding: derived from `user` by core's builders, never taken from a caller. */
    readonly enrollmentFacts: SessionEnrollmentFacts;
    readonly authTime: Date;
    /** Already held to `session.redirectAllowlist`. */
    readonly redirectTo: string | undefined;
    readonly request: {
        readonly ip?: string;
        readonly userAgent?: string;
    };
}
/** What a completing requirement verified: the `amr` it adds, and when a second factor was verified (the second-factor authority alone). */
export interface PrimaryAdditions {
    readonly amr: readonly string[];
    readonly mfaAt?: Date;
}
/** One requirement's completed ceremony, as `resumePrimary` is told of it. */
export interface CompletedRequirement {
    readonly requirement: string;
    readonly adds: PrimaryAdditions;
}
/** A primary as a continuation carries it: `authTime` as epoch milliseconds, so a JSON round trip through a store is exact. */
export interface PrimaryAuthenticationDto {
    readonly subject: string;
    readonly user: Readonly<Record<string, unknown>>;
    readonly claims: UserSessionClaims;
    readonly recorded: RecordedAuthentication;
    readonly authTimeMs: number;
    readonly redirectTo: string | undefined;
    readonly request: {
        readonly ip?: string;
        readonly userAgent?: string;
    };
}
/** What a completed requirement added, as a continuation carries it: `mfaAt` as epoch milliseconds. */
export interface PrimaryAdditionsDto {
    readonly amr: readonly string[];
    readonly mfaAtMs?: number;
}
/** One requirement's completed ceremony, as a continuation records it. */
export interface CompletedRequirementDto {
    readonly requirement: string;
    readonly adds: PrimaryAdditionsDto;
}
/**
 * An explicitly serialisable DTO a requirement persists in its own record —
 * the MFA transaction — and presents to `resumePrimary` when its ceremony
 * completes: the primary as the route built it, and what every completed
 * requirement added so far, every instant as epoch milliseconds, so a JSON
 * round trip through a store is exact. `resumePrimary` rehydrates and
 * validates it (`checkPrimaryContinuation`) before composing.
 */
export interface PrimaryContinuation {
    readonly primary: PrimaryAuthenticationDto;
    readonly done: readonly CompletedRequirementDto[];
    /** The requirement whose ceremony this continuation waits on: `resumePrimary` accepts its completion alone. */
    readonly interruptedBy: string;
}
/**
 * The closed body a login is answered with while a requirement's ceremony
 * runs: never `user`, `sub`, `sid`, or an unmasked address.
 */
export interface InterruptionAnswer {
    readonly status: 403;
    readonly body: {
        /** Held to the RFC 6749 error-text class. */
        readonly error: string;
        readonly transaction?: string;
        readonly expires_in?: number;
        readonly hints?: Readonly<Record<string, string | number | boolean | readonly string[]>>;
    };
}
/**
 * A requirement's answer at establishment time: the login does not
 * complete yet, and the browser is told what to do next. Core wraps it: the
 * route's `PrimaryAdmission.open(sessionId)` passes the continuation core
 * built, and the requirement persists what it receives.
 */
export interface RequirementInterruption {
    /** After the route regenerated the express session: opens the ceremony, bound to `sessionId`, over the continuation to persist. A throw is an outage. */
    open(sessionId: string, continuation: PrimaryContinuation): Promise<InterruptionAnswer>;
}
/**
 * The capability to establish a session: built by `admitPrimary`,
 * `resumePrimary` and `establishWithoutAsking` alone, checked at runtime
 * through a module-private set. `establishSession` requires one and writes
 * the session from `primary` alone.
 */
export type Establishment = {
    readonly [establishmentBrand]: true;
    readonly primary: PrimaryAuthentication;
};
/**
 * A requirement interrupted the login: built by `admitPrimary` and
 * `resumePrimary` alone, frozen, and checked at runtime through a
 * module-private set (`isInterruptAdmission`), like an `Establishment` — a
 * copy, or an object shaped like one, is not one. The session package's
 * `answerInterruption` answers only this.
 */
export type InterruptAdmission = {
    readonly [interruptionBrand]: true;
    readonly outcome: "interrupt";
    readonly requirement: string;
    /** What the requirement persists in its own record and presents to `resumePrimary` when its ceremony completes. */
    readonly continuation: PrimaryContinuation;
    /** Opens the requirement's ceremony bound to `sessionId`, over `continuation`; the answer is validated against the closed body. */
    open(sessionId: string): Promise<InterruptionAnswer>;
};
export type PrimaryAdmission = {
    readonly outcome: "establish";
    readonly establishment: Establishment;
} | InterruptAdmission | {
    readonly outcome: "unavailable";
    readonly store: string;
};
export {};
//# sourceMappingURL=requirement.d.mts.map