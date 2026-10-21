import { contract, extensionPoint } from "@mod/kernel";
import type { Session } from "@mod/session";
import type { z } from "zod";

/**
 * When a refreshed access token ends: where the upstream hands the same token again, the earlier of
 * its new end and the end it held, so a refresh never lengthens a token; else its new end.
 */
export function refreshedExpiry(
	answered: { readonly accessToken: string; readonly expiresAt: number },
	held: { readonly accessToken: string; readonly expiresAt?: number | undefined } | undefined,
): number {
	return held?.expiresAt !== undefined && held.accessToken === answered.accessToken
		? Math.min(answered.expiresAt, held.expiresAt)
		: answered.expiresAt;
}

/** What the implementation asks an upstream to authorize, for one login. */
export interface AuthorizationStart {
	readonly state: string;
	readonly nonce: string;
	/** The PKCE challenge of the verifier the implementation keeps, by the method it chose. */
	readonly challenge: string;
	readonly challengeMethod: "S256";
	readonly redirectUri: string;
	/** The browser asked to log in again upstream. */
	readonly prompt?: "login";
	readonly maxAgeSeconds?: number;
}

/** What the implementation hands back to exchange the code the callback carried. */
export interface CodeExchange {
	readonly code: string;
	readonly verifier: string;
	readonly redirectUri: string;
	readonly nonce: string;
	/** The `iss` the callback carried (RFC 9207), if any. */
	readonly iss: string | undefined;
}

/** Who the upstream says logged in, once its answer was checked. */
export interface UpstreamLogin {
	readonly subject: string;
	/** The upstream's own amr, as it spells it; the implementation maps it to ours by the operator's table. */
	readonly amr: readonly string[];
	/** When the upstream says the user logged in there (epoch ms, on the upstream's clock). */
	readonly authenticatedAt?: number;
	readonly tokens?: UpstreamTokens;
	readonly profile?: UpstreamProfile;
}

export interface UpstreamProfile {
	readonly email?: string;
	readonly emailVerified?: boolean;
	readonly name?: string;
	readonly picture?: string;
}

/** The tokens an upstream's token endpoint gave, as its type read them. */
export interface UpstreamTokens {
	readonly accessToken: string;
	readonly tokenType: string;
	readonly refreshToken?: string;
	readonly idToken?: string;
	/** Counted from when they are handed over. */
	readonly expiresInSeconds?: number;
	readonly scope: readonly string[];
}

/** One configured upstream, opened at boot by its type. */
export interface Upstream {
	/** The issuer the upstream's logins come from, as the type knows it: its own, or the one its settings name. */
	readonly issuer: string;
	/** How the upstream sends the browser back: in the query (the default) or a posted form. */
	readonly responseMode?: "query" | "form_post";
	/** How far this upstream's clock may be from ours; none when not given. */
	readonly clockSkewMs?: number;
	authorizationUrl(start: AuthorizationStart): string;
	/** Exchanges the code; throws UpstreamRefused for an answer that does not hold, Unavailable when unreachable. */
	exchange(code: CodeExchange): Promise<UpstreamLogin>;
	/** Throws as `exchange` does; an upstream that fails (5xx) is unavailable. */
	refresh?(refreshToken: string, scopes: readonly string[]): Promise<UpstreamRefresh>;
	/** The upstream's end-session URL. */
	endSession?(at: {
		readonly idTokenHint?: string;
		readonly postLogoutRedirectUri?: string;
		readonly state?: string;
	}): string;
	readonly delegation?: Delegation;
}

export type UpstreamRefresh =
	| { readonly kind: "refreshed"; readonly tokens: UpstreamTokens }
	| { readonly kind: "invalid_grant" }
	/** The grant stands, but the upstream asks the user to act there (log in, consent, choose an account) first. */
	| { readonly kind: "interaction_required" }
	| { readonly kind: "limited"; readonly retryAfterSeconds?: number };

/** A delegation's start the upstream does not take, such as scopes it does not delegate. */
export interface DelegationRefused {
	readonly kind: "refused";
}

/** Offline access an upstream grants, to be delegated; `exchange` and `refresh` throw as the upstream's own. */
export interface Delegation {
	/** Never throws: a start the upstream does not take is refused as a value. */
	authorizationUrl(start: DelegationStart): string | DelegationRefused;
	exchange(
		code: DelegatedExchange,
	): Promise<UpstreamLogin & { readonly issuer: string; readonly tokens: UpstreamTokens }>;
	refresh(
		refreshToken: string,
		scopes: readonly string[],
		resource?: string,
	): Promise<UpstreamRefresh>;
}

export interface DelegationStart extends AuthorizationStart {
	readonly scopes: readonly string[];
	readonly resource?: string;
}

/** A delegation's code to exchange, with the scopes and resource its start asked for. */
export interface DelegatedExchange extends CodeExchange {
	readonly scopes: readonly string[];
	readonly resource?: string;
}

/** The marks a mismatch and a refusal carry, the same in every copy of upstreams a bundle may hold. */
const mismatchMark = Symbol.for("@mod/upstreams.mismatch");
const refusedMark = Symbol.for("@mod/upstreams.refused");
const marked = (error: unknown, mark: symbol) =>
	typeof error === "object" &&
	error !== null &&
	(error as { readonly [key: symbol]: unknown })[mark] === true;

/**
 * Why `open` refuses an IdP's settings, under `at`, the key path in the IdP's settings it is about
 * (`issuer`, say). Its reason names no configuration value, so boot can tell it to the operator.
 */
export class UpstreamMismatch extends Error {
	readonly at: readonly string[];
	readonly [mismatchMark] = true;
	constructor(reason: string, at: readonly string[] = []) {
		super(reason);
		this.name = "UpstreamMismatch";
		this.at = at;
	}
	/** Whether `error` is a mismatch, by its mark rather than its class, so two copies of upstreams agree. */
	static is(error: unknown): error is UpstreamMismatch {
		return marked(error, mismatchMark);
	}
}

/** The upstream refused, or its answer did not hold; never says why to the browser. */
export class UpstreamRefused extends Error {
	readonly [refusedMark] = true;
	constructor() {
		super("upstream refused");
		this.name = "UpstreamRefused";
	}
	/** Whether `error` is a refusal, by its mark rather than its class, so two copies of upstreams agree. */
	static is(error: unknown): error is UpstreamRefused {
		return marked(error, refusedMark);
	}
}

/** A kind of upstream IdP: what it reads from an IdP's settings, and how it opens one at boot. */
export interface IdpType<S extends z.ZodType = z.ZodType> {
	readonly type: string;
	/** The settings of one IdP of this type, beside `type` and the settings the implementation reads. */
	readonly settings: S;
	/** Refuses boot (throws) when the upstream's own description does not match its settings; `UpstreamMismatch` says why. */
	open(
		settings: z.output<S>,
		at: {
			/** The IdP's name, as `upstreams.of` and the receivers take it. */
			readonly idp: string;
			readonly redirectUri: string;
		},
	): Promise<Upstream>;
}

/** Types a type's `open` by its own schema at compile time, then widens it to the one shape the extension point holds. */
export const idpType = <S extends z.ZodType>(type: IdpType<S>): IdpType => type;

export const idpTypes = extensionPoint<IdpType>("upstreams.idp-types", {
	multiplicity: "keyed",
	keyOf: (type) => type.type,
});

/** What a receiver kept at `received`, read by that receiver alone; its caller only holds it and hands it back. */
export type Receipt = string;

/** Takes the upstream tokens of a login once its session opens. */
export interface UpstreamLoginReceiver {
	readonly name: string;
	/** Answers a receipt of what it kept, or none. */
	received(at: {
		readonly session: Session;
		readonly idp: string;
		readonly tokens: UpstreamTokens;
	}): Promise<Receipt | undefined | void>;
	/**
	 * When a later step fails, deletes what `received` kept and nothing written since, by its receipt,
	 * whatever the session's state; idempotent. With none, `received` kept nothing, and nothing goes.
	 */
	withdrawn(sessionId: string, idp: string, receipt: Receipt | undefined): Promise<void>;
}

export const upstreamLoginReceivers = extensionPoint<UpstreamLoginReceiver>(
	"upstreams.upstream-login-receivers",
	{ multiplicity: "keyed", keyOf: (receiver) => receiver.name },
);

/** The upstreams of the configured IdPs, by name. */
export interface Upstreams {
	of(idp: string): Pick<Upstream, "refresh" | "endSession" | "delegation"> | undefined;
}

export const upstreams = contract<Upstreams>("upstreams");
