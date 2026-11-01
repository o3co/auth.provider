import type { HttpRequest } from "@mod/http";
import { contract, extensionPoint } from "@mod/kernel";
import type { LoginFacts, Session } from "@mod/session";

export type LoginOutcome =
	| { readonly kind: "opened"; readonly session: Session; readonly cookies: readonly string[] }
	/** A gate holds the login; its answer and cookies are for the client, passed on unread. */
	| {
			readonly kind: "held";
			readonly gate: string;
			readonly answer: unknown;
			readonly cookies: readonly string[];
	  }
	/** A gate refused the login: no session, and no cookies; the caller answers it with its own failure, telling nothing of why. */
	| {
			readonly kind: "refused";
			readonly gate: string;
			readonly cookies: readonly [];
	  }
	/** `session` refused it, its subject revoked since the proof began: no session, and no cookies; the caller answers it as a refusal. */
	| { readonly kind: "revoked"; readonly cookies: readonly [] };

/** A held login resumed at or past the deadline its caller set; no gate ran. */
export type ResumeOutcome = LoginOutcome | { readonly kind: "expired" };

/** The caller to tell once a held login opens, and what it carries until then, never read here. */
export interface LoginFrom {
	readonly caller: string;
	readonly carry: string;
	/** Epoch ms on `kernel`'s clock: from then on, `resume` answers expired. */
	readonly deadline?: number;
}

export interface Logins {
	/** `done` is what the caller answers once the session opens; a gate that holds keeps it and `from`, unread. */
	login(
		request: HttpRequest,
		facts: LoginFacts,
		done?: unknown,
		from?: LoginFrom,
	): Promise<LoginOutcome>;
	/** Goes on with a login a gate held, through the gates after that one; `after` names a gate. */
	resume(
		request: HttpRequest,
		facts: LoginFacts,
		after: string,
		done?: unknown,
		from?: LoginFrom,
	): Promise<ResumeOutcome>;
	/** Whether the declared ways of logging in, together, can prove every one of these amr. */
	achievable(amr: readonly string[]): boolean;
	/**
	 * Whether a login may send the browser back to this target: a listed https target exactly, or a
	 * contributed path on the public origin with any query, never a fragment, userinfo, whitespace or
	 * control character.
	 */
	returnAllowed(target: string): boolean;
}

export const logins = contract<Logins>("login-gates");

/**
 * A step a login must pass before its session opens; one that holds it writes and cleans up its own
 * state, and one that refuses it ends it, writing nothing the login keeps.
 */
export interface LoginGate {
	readonly name: string;
	/**
	 * Asked again when a login a gate after it held resumes, before the gates after that one: it may
	 * only pass or refuse there, as one that never holds.
	 */
	readonly rechecked?: boolean;
	hold(
		request: HttpRequest,
		facts: LoginFacts,
		done: unknown,
		from?: LoginFrom,
	): Promise<
		| { readonly kind: "pass" }
		| { readonly kind: "held"; readonly answer: unknown; readonly cookies?: readonly string[] }
		| { readonly kind: "refused" }
	>;
}

export const loginGates = extensionPoint<LoginGate>("login-gates.gates", {
	multiplicity: "keyed",
	keyOf: (gate) => gate.name,
});

/** The amr a way of logging in can prove; the names are its own words, never read here. */
export interface AmrSource {
	readonly name: string;
	readonly amr: readonly string[];
}

export const amrSources = extensionPoint<AmrSource>("login-gates.amr-sources", {
	multiplicity: "keyed",
	keyOf: (source) => source.name,
});

/**
 * A path on the public origin a login may return to, contributed by the module that owns it; with
 * `segment`, the paths one name segment below it instead (letters, digits, `-` or `_`, up to 64),
 * as a route that takes a name there.
 */
export interface ReturnPath {
	readonly path: string;
	readonly segment?: true;
}

export const returnPaths = extensionPoint<ReturnPath>("login-gates.return-paths", {
	multiplicity: "keyed",
	keyOf: (p) => (p.segment ? `${p.path}/*` : p.path),
});

/** A caller told when a login it asked for opens after a gate held it. */
export interface OpenedAfterHold {
	readonly caller: string;
	opened(session: Session, carry: string): Promise<void>;
}

export const openedAfterHold = extensionPoint<OpenedAfterHold>("login-gates.opened-after-hold", {
	multiplicity: "keyed",
	keyOf: (told) => told.caller,
});
