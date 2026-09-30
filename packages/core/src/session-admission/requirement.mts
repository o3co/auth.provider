/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The vocabulary of session admission (ADR 2026-09-28-session-admission):
 * the claim, the action, the `Admission` answer, `SessionRequirement` with
 * its input and verdict, the step-up page, and the establishment half
 * (`PrimaryAuthentication`, the interruption, the `PrimaryContinuation`,
 * the `Establishment` capability). Types and the registration checks only;
 * the decisions are `admit.mts`'s. The brands are type-level here and
 * runtime-checked there, so an `as` cast forges the type and nothing else.
 */

import type { AuditSink } from "../audit/types.mjs";
import { isWellFormedErrorCode } from "../errors/envelope.mjs";
import { FEDERATED_AMR, PASSWORD_AMR } from "../grants/authenticationClaims.mjs";
import type { Logger } from "../logging/Logger.mjs";
import type { RecordedAuthentication } from "../user-sessions/authentication.mjs";
import type {
	SessionAuthentication,
	SubjectRevocation,
	UserSession,
	UserSessionClaims,
	UserSessionStore,
} from "../user-sessions/types.mjs";
import { type AcrTable, SECOND_FACTOR_AMR } from "./acr.mjs";

/**
 * The stores admission reads itself, by the name an `unavailable` admission
 * gives each one's outage. Every other `Admission.store` is a requirement's
 * name, so no requirement may register under one of these: a consumer that
 * tells an outage by its store never takes a requirement's for a store's.
 */
export const ADMISSION_INFRASTRUCTURE_STORES = Object.freeze([
	"user_session",
	"revocation_boundary",
] as const);

/** A store admission reads itself, by the name its outage is given. */
export type AdmissionInfrastructureStore = (typeof ADMISSION_INFRASTRUCTURE_STORES)[number];

/** Whether `store` names one of admission's own stores — else it is a requirement's name. */
export const isAdmissionInfrastructureStore = (
	store: unknown,
): store is AdmissionInfrastructureStore =>
	(ADMISSION_INFRASTRUCTURE_STORES as readonly unknown[]).includes(store);

/** How each of admission's own stores is described when it could not answer: the revocation boundary's in the words the token side uses for it. */
const INFRASTRUCTURE_OUTAGES: Readonly<Record<AdmissionInfrastructureStore, string>> = {
	user_session: "session store unavailable",
	revocation_boundary: "revocation store unavailable",
};

/**
 * What an `unavailable` admission is described as to the client: either of
 * admission's own stores by name, anything else as a requirement's outage,
 * never by the requirement's name (that is the operator's, for the log
 * line). One text for every consumer.
 */
export const describeAdmissionOutage = (store: string): string =>
	isAdmissionInfrastructureStore(store)
		? INFRASTRUCTURE_OUTAGES[store]
		: "session requirement unavailable";

declare const claimBrand: unique symbol;
declare const resolverBrand: unique symbol;
declare const establishmentBrand: unique symbol;
declare const interruptionBrand: unique symbol;

// ---------------------------------------------------------------------------
// The claim and the action
// ---------------------------------------------------------------------------

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
}

/**
 * A grade decides how a requirement treats an action: `use` exercises the
 * session; `credential_change` adds or removes a way into the account;
 * `remediation` is a requirement's own route, by which the session meets
 * that requirement, accepted only for a name a registered requirement
 * declared.
 */
export type AdmissionGrade = "use" | "credential_change" | "remediation";

/** What the consumer is about to let the session do: a name and a grade. `ADMISSION_ACTIONS` names the bundled ones. */
export interface AdmissionAction {
	readonly name: string;
	readonly grade: AdmissionGrade;
}

/** What the request asks beyond the action: `acr_values`, at `/authorize` only. */
export interface AdmissionAsks {
	readonly acrValues?: readonly string[];
}

export interface AdmissionRequest {
	readonly claim: SessionClaim;
	readonly action: AdmissionAction;
	readonly asks?: AdmissionAsks;
}

/** The consumer's own slots, as wired, and the resolver the planner built. */
export interface AdmissionDeps {
	readonly userSessionStore: UserSessionStore | undefined;
	readonly subjectRevocation: SubjectRevocation | undefined;
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

// ---------------------------------------------------------------------------
// The step-up page
// ---------------------------------------------------------------------------

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

/** The parameter a consumer adds to the page itself, on the way to it: never a page's own. */
const RESERVED_PAGE_PARAM = "redirect_to";

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** Whether a page's `url` carries what it may not: a backslash (a browser reads it as a slash), an encoded one, or a control character. */
const forbiddenInPageUrl = (url: string): boolean =>
	/[\\]|%5c/i.test(url) ||
	Array.from(url, (char) => char.charCodeAt(0)).some((code) => code < 0x20 || code === 0x7f);

/** The origin a path is resolved against when no issuer is given: any path must keep it. */
const PATH_ORIGIN = "https://issuer.invalid";

/**
 * `page` as a requirement may declare it: `url` a path that stays on the
 * issuer's origin once resolved as a browser resolves a `Location` (not
 * `//host` or `/\host`), or an absolute `http(s)` URL on `issuer`'s origin
 * (any origin when no issuer is given); never a backslash, an encoded one or
 * a control character; `params` strings, without `redirect_to`. Answers a
 * frozen copy; anything else is a `RangeError` naming what is wrong.
 */
export function checkStepUpPage(page: unknown, issuer?: string): StepUpPage {
	if (!isPlainObject(page)) throw new RangeError("stepUpPage must be an object");
	const url = page.url;
	if (typeof url !== "string" || url.length === 0) {
		throw new RangeError("stepUpPage.url must be a non-empty string");
	}
	if (forbiddenInPageUrl(url)) {
		throw new RangeError(
			"stepUpPage.url must not carry a backslash, an encoded backslash or a control character",
		);
	}
	let resolved: URL;
	if (url.startsWith("/")) {
		const base = new URL(issuer ?? PATH_ORIGIN);
		// A path free of backslashes and control characters always resolves
		// against a base; what it may do is leave the base's origin.
		resolved = new URL(url, base);
		if (resolved.origin !== base.origin) {
			throw new RangeError(
				"stepUpPage.url must stay on the issuer's origin once resolved: a path, not a scheme-relative URL",
			);
		}
	} else {
		try {
			resolved = new URL(url);
		} catch {
			throw new RangeError("stepUpPage.url must be a path or an absolute URL");
		}
		if (resolved.protocol !== "https:" && resolved.protocol !== "http:") {
			throw new RangeError("stepUpPage.url must be an http or https URL");
		}
		if (issuer !== undefined && resolved.origin !== new URL(issuer).origin) {
			throw new RangeError("stepUpPage.url must be on the issuer's origin");
		}
	}
	if (resolved.searchParams.has(RESERVED_PAGE_PARAM)) {
		throw new RangeError(
			`stepUpPage.url must not carry ${RESERVED_PAGE_PARAM} in its query: it is the consumer's return parameter`,
		);
	}
	// The params: read once, copied from their own enumerable string keys
	// into a plain object that is what gets validated — a Proxy that answers
	// one thing to a probe and another to a read cannot get past.
	const paramsRead = page.params;
	if (!isPlainObject(paramsRead)) throw new RangeError("stepUpPage.params must be an object");
	const params: Record<string, unknown> = {};
	for (const key of Object.keys(paramsRead)) params[key] = paramsRead[key];
	// Every own key must be in the copy: a symbol, a non-enumerable key, or one
	// a Proxy lists but hides from the copy is refused.
	for (const key of Reflect.ownKeys(paramsRead)) {
		if (typeof key !== "string" || !Object.hasOwn(params, key)) {
			throw new RangeError(
				`stepUpPage.params.${String(key)} is not an enumerable string key the copy could read: params must be a plain object`,
			);
		}
	}
	if (Object.hasOwn(params, RESERVED_PAGE_PARAM)) {
		throw new RangeError(
			`stepUpPage.params must not carry ${RESERVED_PAGE_PARAM}: it is the consumer's return parameter`,
		);
	}
	for (const [key, value] of Object.entries(params)) {
		if (typeof value !== "string") {
			throw new RangeError(`stepUpPage.params.${key} must be a string`);
		}
	}
	return Object.freeze({ url, params: Object.freeze(params as Record<string, string>) });
}

/**
 * The step-up page as a browser is sent to it: `page.url` resolved on
 * `issuer`, each param set on the query (`searchParams.set`, never
 * concatenation), as one absolute URL. Registration computes it once, as the
 * registered page's `href`. No return parameter is added: `/authorize` sets
 * its own on the `href`, and a JSON consumer answers it as it is.
 * @internal
 */
export function stepUpPageUrl(page: StepUpPage, issuer: string): string {
	const url = new URL(page.url, issuer);
	for (const [name, value] of Object.entries(page.params)) url.searchParams.set(name, value);
	return url.href;
}

// ---------------------------------------------------------------------------
// What a requirement is asked and answers
// ---------------------------------------------------------------------------

/** A projection of the live record — never the record itself, so a requirement cannot read the raw `amr`. */
export interface SessionView {
	readonly sid: string;
	readonly sub: string;
	readonly authTime: Date;
	readonly expiresAt: Date;
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
	/** The action by its effective grade: an undeclared `remediation` arrives as `credential_change`. */
	readonly action: AdmissionAction;
	readonly asks: AdmissionAsks | undefined;
	readonly now: Date;
}

/**
 * A `step_up` names no page of its own: admission answers the requirement's
 * registered `stepUpPage`, copied and validated at registration, so nothing
 * a requirement answers at request time reaches a redirect unvalidated.
 */
export type RequirementVerdict =
	| { readonly outcome: "met" }
	| { readonly outcome: "reauthenticate" }
	| { readonly outcome: "step_up"; readonly whenStillUnmet: "reauthenticate" | "unmet" }
	| { readonly outcome: "unmet" };

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

const isNonEmptyString = (value: unknown): value is string =>
	typeof value === "string" && value.length > 0;

const isNameList = (value: unknown): value is readonly string[] =>
	Array.isArray(value) && value.every(isNonEmptyString);

/** A hint's key: a short lower-case identifier. */
const HINT_KEY = /^[a-z][a-z0-9_]{0,31}$/;
/** A hint's value: an enum-like token. A snapshot, a URL, an address or a name cannot take this form. */
const HINT_TOKEN = /^[a-z][a-z0-9_-]{0,63}$/;
/** The hint keys core reserves: what a page must never be told under any name. */
const RESERVED_HINT_KEYS: ReadonlySet<string> = new Set([
	"user",
	"sub",
	"sid",
	"subject",
	"email",
	"mail",
	"address",
	"phone",
	"name",
	"token",
	"secret",
	"password",
	"claims",
	"profile",
]);

/** Whether `key` may name a hint: the identifier form, and not a reserved name. */
export const isHintKey = (key: unknown): key is string =>
	typeof key === "string" && HINT_KEY.test(key) && !RESERVED_HINT_KEYS.has(key);

/** Whether `value` may be one hint's text: an enum-like token. */
export const isHintToken = (value: unknown): value is string =>
	typeof value === "string" && HINT_TOKEN.test(value);

// ---------------------------------------------------------------------------
// The actions
// ---------------------------------------------------------------------------

const action = <N extends string, G extends AdmissionGrade>(
	name: N,
	grade: G,
): { readonly name: N; readonly grade: G } => Object.freeze({ name, grade });

/**
 * The bundled consumers' actions, each with its grade. A deployment's
 * own route builds `{ name, grade }` for what it does and is treated by its
 * grade; `remediation` is accepted only for a name a registered requirement
 * declared, else treated as `credential_change`. The consumers' actions
 * alone: a remediation (`mfa.step_up`) is a requirement's own route, issued
 * to it at registration (`registeredRequirement`), and never a member.
 */
export const ADMISSION_ACTIONS = Object.freeze({
	"oauth.authorize": action("oauth.authorize", "use"),
	"oauth.consent": action("oauth.consent", "use"),
	"oauth.session_grant": action("oauth.session_grant", "use"),
	"oauth.code_exchange": action("oauth.code_exchange", "use"),
	"oauth.refresh": action("oauth.refresh", "use"),
	"device.lookup": action("device.lookup", "use"),
	"device.approve": action("device.approve", "use"),
	"device.deny": action("device.deny", "use"),
	"federation_grants.connect": action("federation_grants.connect", "use"),
	"federation_grants.consent": action("federation_grants.consent", "use"),
	"federation_grants.callback": action("federation_grants.callback", "use"),
	"session.link": action("session.link", "credential_change"),
	"session.link_callback": action("session.link_callback", "use"),
	"webauthn.register": action("webauthn.register", "credential_change"),
	"mfa.manage": action("mfa.manage", "credential_change"),
});

/** A bundled action's name. */
export type AdmissionActionName = keyof typeof ADMISSION_ACTIONS;

/** A remediation's route, after the requirement's own name and a dot: a lower-case identifier. */
const REMEDIATION_ROUTE = /^[a-z][a-z0-9_]*$/;

/**
 * `remediations` as a requirement may declare them: each `<name>.<route>`,
 * declared once, and never a name in `ADMISSION_ACTIONS`. A consumer's
 * action may share a requirement's namespace (`mfa.manage` beside `mfa`),
 * and registered as a remediation it would skip every requirement for that
 * action. Another requirement's name is impossible by construction: the
 * route holds no dot, and the kind refuses a second requirement of one name.
 */
function checkRemediations(name: string, value: unknown, refuse: (what: string) => never): void {
	if (!isNameList(value)) refuse("remediations must be a list of names");
	const prefix = `${name}.`;
	const seen = new Set<string>();
	for (const remediation of value as readonly string[]) {
		const route = remediation.startsWith(prefix) ? remediation.slice(prefix.length) : undefined;
		if (route === undefined || !REMEDIATION_ROUTE.test(route)) {
			refuse(
				`remediation "${remediation}" is not a route of this requirement's own: a remediation is named "${prefix}<route>", the route a lower-case identifier`,
			);
		}
		if (Object.hasOwn(ADMISSION_ACTIONS, remediation)) {
			refuse(
				`remediation "${remediation}" is a consumer's action in ADMISSION_ACTIONS: registered as a remediation it would skip every requirement for that action`,
			);
		}
		if (seen.has(remediation)) refuse(`remediation "${remediation}" is declared twice`);
		seen.add(remediation);
	}
}

/** Whether `value` is an iterable that is not a string: what a reach may be given as. */
const isIterableOfValues = (value: unknown): value is Iterable<unknown> =>
	typeof value === "object" &&
	value !== null &&
	typeof (value as { [Symbol.iterator]?: unknown })[Symbol.iterator] === "function";

/** The copies `registeredRequirement` made: what `sealRegisteredReach` seals. */
const registeredCopies = new WeakSet<SessionRequirement>();

/**
 * Whether `value` is a copy `registeredRequirement` made — never the object
 * a factory returned, nor a copy of a registered one.
 * @internal
 */
export const isRegisteredRequirement = (value: unknown): value is RegisteredRequirement =>
	typeof value === "object" && value !== null && registeredCopies.has(value as SessionRequirement);

/** Each registered copy's sealed reach: read once at the end of boot's stage 4, answered afterwards. */
const sealedReach = new WeakMap<SessionRequirement, ReadonlySet<string>>();

/**
 * A sealed reach: a read-only view over a private set — `has`, `size` and
 * iteration, no `add` or `delete` at all. Not a frozen native `Set`, which
 * still accepts both.
 */
class SealedReach implements ReadonlySet<string> {
	readonly #values: ReadonlySet<string>;

	constructor(values: Iterable<string>) {
		this.#values = new Set(values);
		Object.freeze(this);
	}

	get size(): number {
		return this.#values.size;
	}

	has(value: string): boolean {
		return this.#values.has(value);
	}

	keys(): SetIterator<string> {
		return this.#values.keys();
	}

	values(): SetIterator<string> {
		return this.#values.values();
	}

	entries(): SetIterator<[string, string]> {
		return this.#values.entries();
	}

	forEach(
		callback: (value: string, value2: string, set: ReadonlySet<string>) => void,
		thisArg?: unknown,
	): void {
		for (const value of this.#values) callback.call(thisArg, value, value, this);
	}

	[Symbol.iterator](): SetIterator<string> {
		return this.#values.values();
	}

	get [Symbol.toStringTag](): string {
		return "SealedReach";
	}

	// The set algebra `ReadonlySet` declares, each answered over a copy, so
	// nothing hands the private set out.
	union<U>(other: ReadonlySetLike<U>): Set<string | U> {
		return new Set(this.#values).union(other);
	}

	intersection<U>(other: ReadonlySetLike<U>): Set<string & U> {
		return new Set(this.#values).intersection(other);
	}

	difference<U>(other: ReadonlySetLike<U>): Set<string> {
		return new Set(this.#values).difference(other);
	}

	symmetricDifference<U>(other: ReadonlySetLike<U>): Set<string | U> {
		return new Set(this.#values).symmetricDifference(other);
	}

	isSubsetOf(other: ReadonlySetLike<unknown>): boolean {
		return this.#values.isSubsetOf(other);
	}

	isSupersetOf(other: ReadonlySetLike<unknown>): boolean {
		return this.#values.isSupersetOf(other);
	}

	isDisjointFrom(other: ReadonlySetLike<unknown>): boolean {
		return this.#values.isDisjointFrom(other);
	}
}

/** Seals `requirement` on `values` when it is a registered copy, and answers the sealed view. */
function seal(requirement: SessionRequirement, values: Iterable<string>): ReadonlySet<string> {
	const sealed = new SealedReach(values);
	if (registeredCopies.has(requirement)) sealedReach.set(requirement, sealed);
	return sealed;
}

/** The remediation actions core issued: the only ones admission keeps the `remediation` grade for. */
const issuedActions = new WeakSet<AdmissionAction>();

/** The issued actions by the ORIGINAL object a factory returned: what `issuedRemediationActions` answers the contributing module. */
const actionsByOriginal = new WeakMap<object, Readonly<Record<string, AdmissionAction>>>();

/** The issued actions by the registered copy: what admission checks a `remediation` action against. */
const actionsByCopy = new WeakMap<SessionRequirement, Readonly<Record<string, AdmissionAction>>>();

/**
 * The remediation actions core issued to a requirement, keyed by route
 * (`step_up` for `mfa.step_up`), answered to the module that holds the
 * object its factory returned and to nothing else: the resolver hands out
 * the registered copy, which carries none of them, so a consumer holding
 * the resolver cannot obtain a `remediation` action. `undefined` for an
 * object that was never registered, a copy of one, or the registered copy.
 */
export function issuedRemediationActions(
	requirement: SessionRequirement,
): Readonly<Record<string, AdmissionAction>> | undefined {
	return typeof requirement === "object" && requirement !== null
		? actionsByOriginal.get(requirement)
		: undefined;
}

/** The issued actions of a registered copy, for admission's own check. @internal */
export const issuedActionsOf = (
	copy: SessionRequirement,
): Readonly<Record<string, AdmissionAction>> | undefined => actionsByCopy.get(copy);

/** Whether `action` is one core issued to a registered requirement — never a literal, a copy or `ADMISSION_ACTIONS`' own entry. */
export const isIssuedAction = (action: unknown): action is AdmissionAction =>
	typeof action === "object" && action !== null && issuedActions.has(action as AdmissionAction);

/**
 * A requirement's page as it is registered: checked (`checkStepUpPage`, on
 * `issuer`'s origin when one is given) and resolved on that issuer, once, to
 * its `href`. A path has nothing to be resolved on without an issuer, and is
 * refused through `refuse`.
 */
function registeredPage(
	page: unknown,
	issuer: string | undefined,
	refuse: (what: string) => never,
): RegisteredStepUpPage {
	const checked = checkStepUpPage(page, issuer);
	if (issuer === undefined && checked.url.startsWith("/")) {
		refuse(
			`stepUpPage.url ${JSON.stringify(checked.url)} is a path, resolved on the issuer: none was given to register it on — boot registers on the oauthTokenSettings slot's issuer, or on oauth.jwt.issuer in a composition without one; a test passes resolverForTests(requirements, { issuer })`,
		);
	}
	return Object.freeze({
		url: checked.url,
		params: checked.params,
		href: stepUpPageUrl(checked, issuer ?? checked.url),
	});
}

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
export function registeredRequirement(value: unknown, issuer?: string): RegisteredRequirement {
	if (!isPlainObject(value)) throw new RangeError("a session requirement must be an object");
	// Each field is read once, into a local that is what gets validated and
	// copied: a getter answering differently to a second read changes nothing.
	const name = value.name;
	if (!isNonEmptyString(name)) {
		throw new RangeError("a session requirement's name must be a non-empty string");
	}
	// A `step_up` names the requirement on the wire, under RFC 6749's grammar
	// for an error code: a name outside it would be dropped there, and the
	// client left without the remediation. Quoted escaped: it may hold a
	// control character.
	if (!isWellFormedErrorCode(name)) {
		throw new RangeError(
			`session requirement ${JSON.stringify(name)}: the name must be RFC 6749's error-code characters — printable ASCII without " or \\ — the only ones a step_up is sent in`,
		);
	}
	const refuse = (what: string): never => {
		throw new RangeError(`session requirement "${name}": ${what}`);
	};
	if (isAdmissionInfrastructureStore(name)) {
		refuse(
			`the name is one admission gives an outage of its own stores (${ADMISSION_INFRASTRUCTURE_STORES.join(", ")}): a consumer telling an outage by its store would take the requirement's for the store's`,
		);
	}
	const declared = value.secondFactorAuthority;
	if (declared !== undefined && typeof declared !== "boolean") {
		refuse("secondFactorAuthority must be true, false or absent");
	}
	// A page that fails names what is wrong itself (`checkStepUpPage`); one
	// that passes is resolved here, once, on the issuer it was checked on.
	const page = value.stepUpPage;
	const stepUpPage = page === undefined ? undefined : registeredPage(page, issuer, refuse);
	const remediationsRead = value.remediations;
	checkRemediations(name, remediationsRead, refuse);
	const hintKeysRead = value.hintKeys;
	if (!isNameList(hintKeysRead) || !hintKeysRead.every(isHintKey)) {
		refuse(
			"hintKeys must be a list of hint names: lower-case identifiers of at most 32 characters, none a name core reserves",
		);
	}
	const admit = value.admit;
	if (typeof admit !== "function") refuse("admit must be a function");
	const primaryAsk = value.admitPrimary;
	if (primaryAsk !== undefined && typeof primaryAsk !== "function") {
		refuse("admitPrimary must be a function or absent");
	}
	const source = value as unknown as SessionRequirement;
	const remediations = Object.freeze([...(remediationsRead as readonly string[])]);
	// The remediation actions, issued here and nowhere else: handed to
	// the contributing module by the object it returned, never on the copy.
	const actions: Record<string, AdmissionAction> = {};
	for (const remediation of remediations) {
		const issued: AdmissionAction = Object.freeze({ name: remediation, grade: "remediation" });
		issuedActions.add(issued);
		actions[remediation.slice(name.length + 1)] = issued;
	}
	const copy: RegisteredRequirement = Object.freeze({
		name,
		secondFactorAuthority: declared === true,
		get reach() {
			return sealedReach.get(copy) ?? source.reach;
		},
		stepUpPage,
		remediations,
		hintKeys: Object.freeze([...(hintKeysRead as readonly string[])]),
		admit: (input: RequirementInput) => (admit as SessionRequirement["admit"]).call(source, input),
		...(primaryAsk === undefined
			? {}
			: {
					admitPrimary: (primary: PrimaryAuthentication) =>
						(primaryAsk as NonNullable<SessionRequirement["admitPrimary"]>).call(source, primary),
				}),
	});
	registeredCopies.add(copy);
	const issued = Object.freeze(actions);
	actionsByOriginal.set(value, issued);
	actionsByCopy.set(copy, issued);
	return copy;
}

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
export function sealRegisteredReach(
	requirement: RegisteredRequirement,
	remedy?: string,
): ReadonlySet<string> {
	const refuse = (what: string): never => {
		throw new RangeError(`session requirement "${requirement.name}": ${what}`);
	};
	if (!isRegisteredRequirement(requirement)) {
		return refuse("is not a registered copy: its declaration is the one registration read");
	}
	const authority = requirement.secondFactorAuthority;
	const reach: unknown = requirement.reach;
	if (!isIterableOfValues(reach)) return refuse("reach must be a Set of amr values");
	const read = new Set<string>();
	for (const entry of reach) {
		if (!isNonEmptyString(entry)) refuse("reach holds a value that is not a non-empty string");
		const value = entry as string;
		if (value === PASSWORD_AMR || value === FEDERATED_AMR) {
			refuse(`reach names "${value}", a primary's marker, which no step-up adds`);
		}
		if (!authority && SECOND_FACTOR_AMR.has(value)) {
			refuse(
				`reach names "${value}", a second-factor value only the second-factor authority may reach`,
			);
		}
		read.add(value);
	}
	if (read.size > 0 && requirement.stepUpPage === undefined) {
		refuse("a requirement that reaches something must declare where the step-up starts");
	}
	if (read.size > 0 && !authority) {
		refuse(
			`reaches ${[...read].map((value) => `"${value}"`).join(", ")}: in this release only the second-factor authority adds vouched values to a session, so any other reach must be empty${remedy === undefined ? "" : ` — ${remedy}`}`,
		);
	}
	return seal(requirement, read);
}

/**
 * Seals a registered copy's reach as boot does — read once, a frozen
 * snapshot the copy answers afterwards — without the rule
 * `sealRegisteredReach` holds it to, which the contract suite and boot do.
 * For `resolverForTests` alone.
 * @internal
 */
export function snapshotReach(requirement: RegisteredRequirement): ReadonlySet<string> {
	const reach: unknown = requirement.reach;
	if (!isIterableOfValues(reach)) {
		throw new RangeError(
			`session requirement "${requirement.name}": reach must be a Set of amr values`,
		);
	}
	return seal(requirement, reach as Iterable<string>);
}

/** The registered requirements among `requirements` that declare the second-factor authority, in order: at most one may. */
export const secondFactorAuthorities = (
	requirements: Iterable<RegisteredRequirement>,
): RegisteredRequirement[] =>
	[...requirements].filter((requirement) => requirement.secondFactorAuthority);

/**
 * The read side of the `sessionRequirements` kind — the synthetic key
 * `sessionRequirementResolver`: `entries()` in registration order,
 * `get(name)`. Branded: only the boot planner and `resolverForTests` build
 * one, and `admitSession` refuses any other.
 */
export interface SessionRequirementResolver {
	readonly [resolverBrand]: true;
	readonly get: (name: string) => RegisteredRequirement | undefined;
	readonly entries: () => IterableIterator<readonly [string, RegisteredRequirement]>;
}

// ---------------------------------------------------------------------------
// What admission answers
// ---------------------------------------------------------------------------

export type Admission =
	| {
			readonly outcome: "admitted";
			readonly session: UserSession | null;
			readonly acr: string | undefined;
	  }
	| { readonly outcome: "unauthenticated" }
	| {
			readonly outcome: "not_live";
			readonly reason: "no_subject" | "no_sid" | "gone" | "subject_mismatch";
	  }
	| { readonly outcome: "revoked" }
	| {
			readonly outcome: "reauthenticate";
			readonly requirement: string;
			readonly session: UserSession | null;
	  }
	| {
			readonly outcome: "step_up";
			readonly requirement: string;
			readonly session: UserSession;
			/** The requirement's page as registered: `href` is where a consumer sends the browser. */
			readonly page: RegisteredStepUpPage;
			readonly acrValues: readonly string[];
			readonly whenStillUnmet: "reauthenticate" | "unmet";
	  }
	| {
			readonly outcome: "unmet";
			readonly requirement: string;
			readonly session: UserSession | null;
	  }
	| {
			readonly outcome: "unavailable";
			/** One of admission's own stores (`user_session`, `revocation_boundary`), or the name of the requirement that could not answer; {@link describeAdmissionOutage} words it for a client. */
			readonly store: string;
	  };

// ---------------------------------------------------------------------------
// Establishment
// ---------------------------------------------------------------------------

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
	readonly authTime: Date;
	/** Already held to `session.redirectAllowlist`. */
	readonly redirectTo: string | undefined;
	readonly request: { readonly ip?: string; readonly userAgent?: string };
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
	readonly request: { readonly ip?: string; readonly userAgent?: string };
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

export type PrimaryAdmission =
	| { readonly outcome: "establish"; readonly establishment: Establishment }
	| InterruptAdmission
	| { readonly outcome: "unavailable"; readonly store: string };
