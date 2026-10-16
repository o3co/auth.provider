import { contract, extensionPoint } from "@mod/kernel";
import type { Session } from "@mod/session";
import type { z } from "zod";

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
	/** How the upstream sends the browser back: in the query (the default) or a posted form. */
	readonly responseMode?: "query" | "form_post";
	/** How far this upstream's clock may be from ours; none when not given. */
	readonly clockSkewMs?: number;
	authorizationUrl(start: AuthorizationStart): string;
	/** Exchanges the code; throws UpstreamRefused for an answer that does not hold, Unavailable when unreachable. */
	exchange(code: CodeExchange): Promise<UpstreamLogin>;
	/** Throws as `exchange` does; an upstream that fails (5xx) is unavailable. */
	refresh?(refreshToken: string, scope: readonly string[]): Promise<UpstreamRefresh>;
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
		scope: readonly string[],
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

/** The upstream refused, or its answer did not hold; never says why to the browser. */
export class UpstreamRefused extends Error {
	constructor() {
		super("upstream refused");
		this.name = "UpstreamRefused";
	}
}

/** A kind of upstream IdP: what it reads from an IdP's settings, and how it opens one at boot. */
export interface IdpType<S extends z.ZodType = z.ZodType> {
	readonly type: string;
	/** The settings of one IdP of this type, beside `type` and the settings the implementation reads. */
	readonly settings: S;
	/** Refuses boot (throws) when the upstream's own description does not match its settings. */
	open(
		settings: z.output<S>,
		at: { readonly name: string; readonly redirectUri: string },
	): Promise<Upstream>;
}

/** Types a type's `open` by its own schema at compile time, then widens it to the one shape the extension point holds. */
export const idpType = <S extends z.ZodType>(type: IdpType<S>): IdpType => type;

export const idpTypes = extensionPoint<IdpType>("upstreams.idp-types", {
	multiplicity: "keyed",
	keyOf: (type) => type.type,
});

/** Takes the upstream tokens of a login once its session opens. */
export interface UpstreamLoginReceiver {
	readonly name: string;
	received(at: {
		readonly session: Session;
		readonly idp: string;
		readonly tokens: UpstreamTokens;
	}): Promise<void>;
	/** When a later step fails, deletes what `received` kept, whatever the session's state; idempotent. */
	withdrawn(sessionId: string, idp: string): Promise<void>;
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
