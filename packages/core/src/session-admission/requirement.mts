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
 * The vocabulary of session admission (the session-admission ADR's D1–D5):
 * what a consumer holds about a session before it is read (`SessionClaim`),
 * what it is about to let the session do (`AdmissionAction`), what admission
 * answers (`Admission`), what a requirement is (`SessionRequirement`) and is
 * asked (`RequirementInput`) and answers (`RequirementVerdict`), the
 * deployment's step-up page as it is validated (`checkStepUpPage`), and the
 * establishment half: `PrimaryAuthentication`, the `Interruption` a
 * requirement answers a login with, the `PrimaryContinuation` it persists,
 * and the `Establishment` capability `establishSession` requires.
 *
 * Types and the registration checks only; the decisions are `admit.mts`'s. The three
 * brands (`SessionClaim`, `SessionRequirementResolver`, `Establishment`) are
 * type-level here and runtime-checked there, through module-private sets:
 * an `as` cast forges the type and nothing else.
 */

import type { AuditSink } from "../audit/types.mjs";
import { FEDERATED_AMR, PASSWORD_AMR } from "../grants/authenticationClaims.mjs";
import type { Logger } from "../logging/Logger.mjs";
import type { RecordedAuthentication } from "../user-sessions/authentication.mjs";
import type {
	SessionAuthentication,
	SubjectRevocation,
	UserSession,
	UserSessionStore,
} from "../user-sessions/types.mjs";
import { type AcrTable, SECOND_FACTOR_AMR } from "./acr.mjs";

/** The one requirement that may reach or add a second-factor value, or a verification time (D3). */
export const MFA_REQUIREMENT_NAME = "mfa";

declare const claimBrand: unique symbol;
declare const resolverBrand: unique symbol;
declare const establishmentBrand: unique symbol;

// ---------------------------------------------------------------------------
// The claim and the action (D2, D4)
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
	/** A token carrier's is optional: without one the live read is skipped, as the refresh grant does (D9). */
	readonly sid: string | undefined;
	/** `undefined` only for a carrier that has none: the code record's first read. */
	readonly subject: string | undefined;
	readonly carrier: "cookie" | "code" | "link" | "token";
	/** A token carrier only: the `amr` the verified token carries, for the requirements (D9); absent when the token carries none. */
	readonly tokenAmr?: readonly string[];
}

/**
 * A grade decides how a requirement treats an action: `use` exercises the
 * session; `credential_change` adds or removes a way into the account;
 * `remediation` is a requirement's own route, by which the session meets
 * that requirement — accepted only for a name a registered requirement
 * declared (D4).
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

/** The consumer's own slots, as wired, and the resolver the planner built (D1). */
export interface AdmissionDeps {
	readonly userSessionStore: UserSessionStore | undefined;
	readonly subjectRevocation: SubjectRevocation | undefined;
	/** The synthetic key `sessionRequirementResolver` (D3); only the boot planner and `resolverForTests` build one. */
	readonly requirements: SessionRequirementResolver;
	/** The vouchable table (D6); empty when the consumer has none. */
	readonly acrTable: AcrTable;
	readonly logger: Logger | undefined;
	/** The consumer's slot; D10's one event. */
	readonly auditSink: AuditSink | undefined;
	/** Defaults to the wall clock; a test seam. */
	readonly now?: () => Date;
}

// ---------------------------------------------------------------------------
// The step-up page (D2, D3)
// ---------------------------------------------------------------------------

/** The deployment's page for a step-up; `checkStepUpPage` validates it at registration. */
export interface StepUpPage {
	/** A path, or an absolute URL on the issuer's origin. */
	readonly url: string;
	/** Never the consumer's return parameter: `redirect_to` is reserved. */
	readonly params: Readonly<Record<string, string>>;
}

/** The parameter a consumer adds to the page itself, on the way to it (D2): never a page's own. */
const RESERVED_PAGE_PARAM = "redirect_to";

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * `page` as a requirement may declare it (D3): `url` a path — one `/`, not
 * two — or an absolute `http(s)` URL on `issuer`'s origin (any absolute
 * `http(s)` URL when no issuer is given, which validates the shape alone);
 * `params` a plain object of strings without `redirect_to`. Anything else is
 * a `RangeError` naming what is wrong. Answers a frozen copy.
 */
export function checkStepUpPage(page: unknown, issuer?: string): StepUpPage {
	if (!isPlainObject(page)) throw new RangeError("stepUpPage must be an object");
	const url = page.url;
	if (typeof url !== "string" || url.length === 0) {
		throw new RangeError("stepUpPage.url must be a non-empty string");
	}
	if (url.startsWith("/")) {
		if (url.startsWith("//")) {
			throw new RangeError("stepUpPage.url must be a path or an absolute URL, not scheme-relative");
		}
	} else {
		let parsed: URL;
		try {
			parsed = new URL(url);
		} catch {
			throw new RangeError("stepUpPage.url must be a path or an absolute URL");
		}
		if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
			throw new RangeError("stepUpPage.url must be an http or https URL");
		}
		if (issuer !== undefined && parsed.origin !== new URL(issuer).origin) {
			throw new RangeError("stepUpPage.url must be on the issuer's origin");
		}
	}
	const params = page.params;
	if (!isPlainObject(params)) throw new RangeError("stepUpPage.params must be an object");
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
	return Object.freeze({ url, params: Object.freeze({ ...(params as Record<string, string>) }) });
}

// ---------------------------------------------------------------------------
// What a requirement is asked and answers (D3)
// ---------------------------------------------------------------------------

/** A projection of the live record — never the record itself, so a requirement cannot read the raw `amr`. */
export interface SessionView {
	readonly sid: string;
	readonly sub: string;
	readonly authTime: Date;
	readonly expiresAt: Date;
}

/**
 * How a live session was established and what it vouches for (the MFA
 * ADR's D9): built by `requirementSession(session)`
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
	/** What the claim was built from (D2, D9). */
	readonly carrier: SessionClaim["carrier"];
	/** The record's `sub` when one was read, else the claim's subject: `undefined` only on the code record's first read (D2, step 3). */
	readonly subject: string | undefined;
	/** The action by its effective grade: an undeclared `remediation` arrives as `credential_change` (D4). */
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
 * `sessionRequirements` kind by the key `name` (D3). MFA is the first.
 */
export interface SessionRequirement {
	/** The key it is contributed under; refused at boot otherwise (the `mfaFactors` rule). */
	readonly name: string;
	/** The `amr` values a step-up through this requirement can add; empty when it offers none. */
	readonly reach: ReadonlySet<string>;
	/** Where that step-up starts: required when `reach` is not empty, allowed when it is (a re-consent). Copied and validated at registration; a `step_up` verdict names no page of its own (D2, step 7). */
	readonly stepUpPage: StepUpPage | undefined;
	/** The names of this requirement's own remediation routes (D4): the only actions admission accepts as `remediation`. */
	readonly remediations: readonly string[];
	/** The keys an interruption's `hints` may carry (D5); declared at registration, so an out-of-tree requirement is held to it at runtime. */
	readonly hintKeys: readonly string[];
	/** Use-time: a view of the session, read once by admission, and the action. Throws only on an outage. */
	admit(input: RequirementInput): Promise<RequirementVerdict>;
	/** Establishment-time (D5); absent when the requirement never interrupts a login. */
	admitPrimary?(primary: PrimaryAuthentication): Promise<"establish" | RequirementInterruption>;
}

const isNonEmptyString = (value: unknown): value is string =>
	typeof value === "string" && value.length > 0;

const isNameList = (value: unknown): value is readonly string[] =>
	Array.isArray(value) && value.every(isNonEmptyString);

/** A hint's key (D5): a short lower-case identifier. */
const HINT_KEY = /^[a-z][a-z0-9_]{0,31}$/;
/** A hint's value (D5): an enum-like token. A snapshot, a URL, an address or a name cannot take this form. */
const HINT_TOKEN = /^[a-z][a-z0-9_-]{0,63}$/;
/** The hint keys core reserves (D5): what a page must never be told under any name. */
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

/** Whether `key` may name a hint (D5): the identifier form, and not a reserved name. */
export const isHintKey = (key: unknown): key is string =>
	typeof key === "string" && HINT_KEY.test(key) && !RESERVED_HINT_KEYS.has(key);

/** Whether `value` may be one hint's text (D5): an enum-like token. */
export const isHintToken = (value: unknown): value is string =>
	typeof value === "string" && HINT_TOKEN.test(value);

// ---------------------------------------------------------------------------
// The actions (D4)
// ---------------------------------------------------------------------------

const action = <N extends string, G extends AdmissionGrade>(
	name: N,
	grade: G,
): { readonly name: N; readonly grade: G } => Object.freeze({ name, grade });

/**
 * The bundled consumers' actions, each with its grade (D4). A deployment's
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

/** A remediation's route, after the requirement's own name and a dot (D4): a lower-case identifier. */
const REMEDIATION_ROUTE = /^[a-z][a-z0-9_]*$/;

/**
 * `remediations` as a requirement may declare them (D4): each the
 * requirement's own route, `<name>.<route>`, declared once. By construction
 * none collides with a consumer's action or another requirement's: the
 * route holds no dot, and the name-keyed kind refuses a second requirement
 * of one name.
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

/** Each registered copy's sealed reach (D3): read once at the end of boot's stage 4, answered afterwards. */
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

/** The remediation actions core issued (D4): what D2's step 5 keeps the `remediation` grade for. */
const issuedActions = new WeakSet<AdmissionAction>();

/** Whether `action` is one core issued to a registered requirement — never a literal, a copy or `ADMISSION_ACTIONS`' own entry. */
export const isIssuedAction = (action: unknown): action is AdmissionAction =>
	typeof action === "object" && action !== null && issuedActions.has(action as AdmissionAction);

/**
 * A requirement as the resolver answers it (D3, D4): the registered copy,
 * with the remediation actions core issued to it — one branded object per
 * declared route, keyed by the route (`actions.step_up` for `mfa.step_up`),
 * which the requirement's own route passes to `admitSession`.
 */
export interface RegisteredRequirement extends SessionRequirement {
	readonly actions: Readonly<Record<string, AdmissionAction>>;
}

/**
 * `value` as it is registered (D3): its shape held to the contract — a
 * non-empty `name`, `remediations` the requirement's own routes
 * (`checkRemediations`: `<name>.<route>`, each once), a `stepUpPage` that
 * is a page when present
 * (`checkStepUpPage`, on `issuer`'s origin when one is given), `hintKeys`
 * each a hint name (`isHintKey`), `admit` a function, `admitPrimary` one or
 * absent — and copied: the lists and the page are the copy's own, and a
 * getter is read once here, so what the resolver answers at request time is
 * what was registered. `reach` is NOT read here: a requirement's reach may
 * be a getter over what registers in the same pass (the MFA requirement's,
 * over `mfaFactorResolver`). It is read once, after the pass, by
 * `sealRegisteredReach` at the end of boot's stage 4, and sealed on the
 * copy as a read-only snapshot: what the copy answers from then on, so the
 * `acr` drop and admission at request time read what boot checked, and a
 * contributor's mutable `Set` changes nothing after boot. Until sealed, the
 * copy answers the value's own. `admit` and `admitPrimary` delegate to the
 * value's. A `RangeError` names what is wrong; the boot planner reports it
 * as the contribution's failure.
 */
export function registeredRequirement(value: unknown, issuer?: string): RegisteredRequirement {
	if (!isPlainObject(value)) throw new RangeError("a session requirement must be an object");
	const name = value.name;
	if (!isNonEmptyString(name)) {
		throw new RangeError("a session requirement's name must be a non-empty string");
	}
	const refuse = (what: string): never => {
		throw new RangeError(`session requirement "${name}": ${what}`);
	};
	// A page that fails names what is wrong itself (`checkStepUpPage`). Read
	// once: a getter is read here and never again.
	const page = value.stepUpPage;
	const stepUpPage = page === undefined ? undefined : checkStepUpPage(page, issuer);
	checkRemediations(name, value.remediations, refuse);
	if (!isNameList(value.hintKeys) || !value.hintKeys.every(isHintKey)) {
		refuse(
			"hintKeys must be a list of hint names: lower-case identifiers of at most 32 characters, none a name core reserves",
		);
	}
	if (typeof value.admit !== "function") refuse("admit must be a function");
	if (value.admitPrimary !== undefined && typeof value.admitPrimary !== "function") {
		refuse("admitPrimary must be a function or absent");
	}
	const source = value as unknown as SessionRequirement;
	const primaryAsk = source.admitPrimary;
	const remediations = Object.freeze([...(value.remediations as readonly string[])]);
	// The remediation actions, issued here and nowhere else (D4).
	const actions: Record<string, AdmissionAction> = {};
	for (const remediation of remediations) {
		const issued: AdmissionAction = Object.freeze({ name: remediation, grade: "remediation" });
		issuedActions.add(issued);
		actions[remediation.slice(name.length + 1)] = issued;
	}
	const copy: RegisteredRequirement = Object.freeze({
		name,
		get reach() {
			return sealedReach.get(copy) ?? source.reach;
		},
		stepUpPage,
		remediations,
		hintKeys: Object.freeze([...(value.hintKeys as readonly string[])]),
		actions: Object.freeze(actions),
		admit: (input: RequirementInput) => source.admit(input),
		...(primaryAsk === undefined
			? {}
			: { admitPrimary: (primary: PrimaryAuthentication) => primaryAsk.call(source, primary) }),
	});
	registeredCopies.add(copy);
	return copy;
}

/**
 * A registered requirement's `reach`, read once after the name-keyed pass
 * (D3): a `Set` — or any other iterable that is not a string, answered as a
 * `Set` — of non-empty strings, none a primary's marker (`pwd`, `fed`), none
 * a second-factor value unless the requirement is named `mfa`
 * (`SECOND_FACTOR_AMR`), and a `stepUpPage` when the reach is not empty —
 * a requirement that reaches nothing may still register one, a step-up that
 * adds no value. The end of boot's stage 4 runs it over every registration
 * (`contribute-factory-failed`, naming the requirement), and the contract
 * suite over a requirement under test. Answers the reach as read, a
 * read-only view over a set of its own — and seals a registered copy on it:
 * the copy answers the snapshot from then on, whatever the contributor's own
 * `Set` does.
 */
export function sealRegisteredReach(requirement: SessionRequirement): ReadonlySet<string> {
	const refuse = (what: string): never => {
		throw new RangeError(`session requirement "${requirement.name}": ${what}`);
	};
	const reach: unknown = requirement.reach;
	if (!isIterableOfValues(reach)) return refuse("reach must be a Set of amr values");
	const read = new Set<string>();
	for (const entry of reach) {
		if (!isNonEmptyString(entry)) refuse("reach holds a value that is not a non-empty string");
		const value = entry as string;
		if (value === PASSWORD_AMR || value === FEDERATED_AMR) {
			refuse(`reach names "${value}", a primary's marker, which no step-up adds`);
		}
		if (requirement.name !== MFA_REQUIREMENT_NAME && SECOND_FACTOR_AMR.has(value)) {
			refuse(
				`reach names "${value}", a second-factor value only the requirement named ${MFA_REQUIREMENT_NAME} may reach`,
			);
		}
		read.add(value);
	}
	if (read.size > 0 && requirement.stepUpPage === undefined) {
		refuse("a requirement that reaches something must declare where the step-up starts");
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
export function snapshotReach(requirement: SessionRequirement): ReadonlySet<string> {
	const reach: unknown = requirement.reach;
	if (!isIterableOfValues(reach)) {
		throw new RangeError(
			`session requirement "${requirement.name}": reach must be a Set of amr values`,
		);
	}
	return seal(requirement, reach as Iterable<string>);
}

/**
 * The read side of the `sessionRequirements` kind — the synthetic key
 * `sessionRequirementResolver` (D3): `entries()` in registration order,
 * `get(name)`. Branded: only the boot planner and `resolverForTests` build
 * one, and `admitSession` refuses any other.
 */
export interface SessionRequirementResolver {
	readonly [resolverBrand]: true;
	readonly get: (name: string) => RegisteredRequirement | undefined;
	readonly entries: () => IterableIterator<readonly [string, RegisteredRequirement]>;
}

// ---------------------------------------------------------------------------
// What admission answers (D2)
// ---------------------------------------------------------------------------

export type Admission =
	| {
			readonly outcome: "admitted";
			readonly session: UserSession | null;
			readonly acr: string | undefined;
	  }
	| { readonly outcome: "unauthenticated" }
	| { readonly outcome: "not_live"; readonly reason: "no_sid" | "gone" | "subject_mismatch" }
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
			readonly page: StepUpPage;
			readonly acrValues: readonly string[];
			readonly whenStillUnmet: "reauthenticate" | "unmet";
	  }
	| {
			readonly outcome: "unmet";
			readonly requirement: string;
			readonly session: UserSession | null;
	  }
	| { readonly outcome: "unavailable"; readonly store: string };

// ---------------------------------------------------------------------------
// Establishment (D5)
// ---------------------------------------------------------------------------

/** A primary authentication that has just succeeded, as the login route hands it over (moved from the coordinator slot, generalised). */
export interface PrimaryAuthentication {
	/** `User.id`. */
	readonly subject: string;
	/** What `req.session.user` will hold. */
	readonly user: Readonly<Record<string, unknown>>;
	/** The `amr` and `authentication` the session would be created with (#707). */
	readonly recorded: RecordedAuthentication;
	readonly authTime: Date;
	/** Already held to `session.redirectAllowlist`. */
	readonly redirectTo: string | undefined;
	readonly request: { readonly ip?: string; readonly userAgent?: string };
}

/** What a completing requirement verified: the `amr` it adds, and when a second factor was verified (the requirement named `mfa` alone). */
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
 * A requirement's answer at establishment time (D5): the login does not
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

export type PrimaryAdmission =
	| { readonly outcome: "establish"; readonly establishment: Establishment }
	| {
			readonly outcome: "interrupt";
			readonly requirement: string;
			/** What the requirement persists in its own record and presents to `resumePrimary` when its ceremony completes. */
			readonly continuation: PrimaryContinuation;
			open(sessionId: string): Promise<InterruptionAnswer>;
	  }
	| { readonly outcome: "unavailable"; readonly store: string };
