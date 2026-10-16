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
	  };

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

/** A step a login must pass before its session opens; one that holds it writes and cleans up its own state. */
export interface LoginGate {
	readonly name: string;
	hold(
		request: HttpRequest,
		facts: LoginFacts,
		done: unknown,
		from?: LoginFrom,
	): Promise<
		| { readonly kind: "pass" }
		| { readonly kind: "held"; readonly answer: unknown; readonly cookies?: readonly string[] }
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

/** A path on the public origin a login may return to, contributed by the module that owns it. */
export interface ReturnPath {
	readonly path: string;
}

export const returnPaths = extensionPoint<ReturnPath>("login-gates.return-paths", {
	multiplicity: "keyed",
	keyOf: (p) => p.path,
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
