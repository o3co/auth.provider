import type { HttpRequest, HttpResponse } from "@mod/http";
import { contract, extensionPoint } from "@mod/kernel";

declare const intentRef: unique symbol;
/** A grant's intent as federation-grants hands it to the browser half: opaque, read back by it alone. */
export type IntentRef = { readonly [intentRef]: true };

declare const heldTokens: unique symbol;
/** An upstream's tokens federation-grants judged fit to hold for an intent: opaque, read back by it alone. */
export type HeldTokens = { readonly [heldTokens]: true };

/** Where a request came from, as `request-source` determined it, for the audit. */
export interface Sourced {
	readonly source?: string;
}

/** A link's intent: whose it is, for which client and connection, and the session holding it, if any. */
export interface LinkView {
	readonly subject: string;
	readonly client: string;
	readonly connection: string;
	readonly session?: string;
}

/** An open question: what the user is asked, and the session it was asked of. */
export interface QuestionView {
	readonly subject: string;
	readonly client: string;
	readonly connection: string;
	readonly scopes: readonly string[];
	readonly resource?: string;
	/** How long the grant lives once connected. */
	readonly grantLifetimeMs: number;
	/** What is left of the question's time. */
	readonly expiresInMs: number;
	readonly session: string;
}

/** An upstream account: the issuer and the subject there. */
export interface UpstreamAccount {
	readonly issuer: string;
	readonly subject: string;
}

/** A taken round trip's intent, at its connection, as a callback checks and exchanges it. */
export interface CallbackView {
	readonly subject: string;
	readonly connection: string;
	/** The IdP the connection names: its delegation at `upstreams`, and its name as `users` takes it by upstream identity. */
	readonly idp: string;
	/** The upstream account the grant already holds, and the upstream subject the intent expects. */
	readonly expected: { readonly held?: UpstreamAccount; readonly subject?: string };
	readonly scopes: readonly string[];
	readonly resource?: string;
	readonly session: string;
}

/** How to send a decided question upstream: what the round trip carries and for how long, and the start's parts. */
export interface Start {
	readonly carried: Readonly<Record<string, string>>;
	readonly lifetimeMs: number;
	/** The IdP whose delegation the browser half starts at `upstreams`. */
	readonly idp: string;
	readonly redirectUri: string;
	readonly scopes: readonly string[];
	readonly resource?: string;
}

/** Where the browser goes back to the client, or none: the intent's return is no longer listed, or it ended. */
export type Back =
	| { readonly kind: "back"; readonly location: string }
	| { readonly kind: "stale" };

/**
 * A grant's intent through the browser, as federation-grants owns it: each step reads or changes the
 * grant and its steps, the records, sealing, retention and audit staying with federation-grants. The
 * browser half sees views and refs, never a record.
 */
export interface GrantIntents {
	/**
	 * For now, the browser half's settings as federation-grants' section still holds them, for a
	 * browser half whose own section leaves them out; it goes once the settings have moved (TODO 96).
	 */
	readonly legacySettings: {
		readonly page?: string;
		readonly loginPage?: string;
		readonly stepUpPage?: string;
		readonly identityCheck: "required" | "none";
	};
	/** Whether the operator configured any connection: a browser half refuses boot then without the page that asks the user. */
	readonly connected: boolean;
	/** The connect link a client sends the user to, on the public origin. */
	connectUrl(handle: string): string;
	/** A connection's upstream callback, on the public origin. */
	callbackUrl(connection: string): string;
	/** The connection a callback's path names, or none for a path that names no connection. */
	callbackOf(path: string): string | undefined;
	/** The link's live intent, without spending the link: a login or a step-up comes back to it. */
	linked(
		handle: string,
	): Promise<
		| { readonly kind: "linked"; readonly ref: IntentRef; readonly view: LinkView }
		| { kind: "stale" }
	>;
	/** Whether the client may still use the connection. */
	permitted(ref: IntentRef): Promise<boolean>;
	/** Whether the client may still use the connection, and the connection is still configured. */
	available(ref: IntentRef): Promise<boolean>;
	/** Marks a trip to raise the session for `requirement`, once per requirement and login; true only for the request that marked it. */
	steppedUp(ref: IntentRef, requirement: string, authenticatedAt: number): Promise<boolean>;
	/** Binds the intent to the first session to take it, then makes a question for that session: two writes, not one. */
	bound(
		ref: IntentRef,
		session: string,
	): Promise<{ readonly kind: "bound"; readonly challenge: string } | { readonly kind: "stale" }>;
	/** An open question and its intent, without spending it. */
	asked(
		challenge: string,
	): Promise<
		| { readonly kind: "asked"; readonly ref: IntentRef; readonly view: QuestionView }
		| { readonly kind: "invalid" }
	>;
	/** Spends the question of the intent `asked` read, ends that intent as denied, audits it, and answers where to go back. */
	denied(
		ref: IntentRef,
		challenge: string,
		from: Sourced,
	): Promise<Back | { readonly kind: "invalid" }>;
	/** What a decided question's start needs; none where its connection is gone. */
	starting(ref: IntentRef): Start | undefined;
	/** Spends the question; called only once the upstream start is built, or the upstream refused it. */
	accepted(challenge: string): Promise<boolean>;
	/**
	 * A taken round trip's intent, by what it carried: stale where it is no longer live, unconfigured
	 * where its connection or the IdP's delegation is gone (the browser half then ends it).
	 */
	resumed(
		carried: unknown,
	): Promise<
		| { readonly kind: "resumed"; readonly ref: IntentRef; readonly view: CallbackView }
		| { readonly kind: "unconfigured"; readonly ref: IntentRef }
		| { readonly kind: "stale" }
	>;
	/** Whether the intent's subject, or a renewed grant, was revoked since; asked before and after the exchange. */
	stillValid(ref: IntentRef): Promise<"access_denied" | undefined>;
	/**
	 * Judges the upstream's tokens for the intent's connection, writing nothing: held, or refused
	 * with why (the browser half then ends the intent). Asked before the last check.
	 */
	judged(
		ref: IntentRef,
		tokens: unknown,
	):
		| { readonly kind: "held"; readonly tokens: HeldTokens }
		| { readonly kind: "refused"; readonly why: string };
	/**
	 * Activates the grant with the tokens judged: seals the credentials, writes over its own intent
	 * alone, audits it, and tidies; an intent a race refuses ends there.
	 */
	activated(
		ref: IntentRef,
		reached: {
			readonly upstream: UpstreamAccount;
			readonly tokens: HeldTokens;
			/** The identity check the browser half made, as the audit names it. */
			readonly identityCheck: string;
		} & Sourced,
	): Promise<Back>;
	/** Ends the intent with `error`, audits it by `outcome` (else the error), and answers where to go back. */
	failed(
		ref: IntentRef,
		error: string,
		from: Sourced & { readonly outcome?: string },
	): Promise<Back>;
	/** Audits a refusal that leaves the intent as it is. */
	noted(ref: IntentRef, outcome: string, from: Sourced): void;
	/** Audits a browser step that could not be answered, its grant unknown. */
	unanswered(from: Sourced): void;
}

/** The intents federation-grants owns, for the browser half. */
export const grantIntents = contract<GrantIntents>("federation-grants.intents");

/** The browser half's answers to the routes federation-grants declares. */
export interface GrantsBrowser {
	readonly connect: (request: HttpRequest) => Promise<HttpResponse>;
	readonly question: (request: HttpRequest) => Promise<HttpResponse>;
	readonly decide: (request: HttpRequest) => Promise<HttpResponse>;
	readonly callback: (request: HttpRequest) => Promise<HttpResponse>;
}

/** The browser half, contributed by the package that runs it. */
export const grantsBrowsers = extensionPoint<GrantsBrowser>("federation-grants.browsers", {
	multiplicity: "many",
});
