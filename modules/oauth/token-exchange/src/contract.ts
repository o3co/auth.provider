import { extensionPoint } from "@mod/kernel";
import type { Binding } from "@mod/sender-binding";
import type { Actor } from "@mod/tokens";

export const accessTokenType = "urn:ietf:params:oauth:token-type:access_token";

/** What every token a verifier accepts answers. */
export interface ExchangedToken {
	readonly subject: string;
	readonly issuer: string;
	/** Epoch ms. */
	readonly expiresAt: number;
	/** Epoch ms: when the token stands from, as its subject's revocation boundary is compared; one not a finite number is read as 0. */
	readonly standingAt: number;
}

/** A token naming the client by issued-to or audience, holding its own scope and audience. */
export interface OwnToken extends ExchangedToken {
	readonly kind: "own";
	/** The client the token was issued to (`azp`). */
	readonly issuedTo?: string;
	readonly audience: readonly string[];
	readonly scope: readonly string[];
	readonly binding?: Binding;
	/** The actor chain the token already holds. */
	readonly actor?: Actor;
	/** Who may act for the subject (`may_act`). */
	readonly mayAct?: readonly { readonly sub?: string; readonly iss?: string }[];
	/** Only the built-in verifier's amr, authentication time, acr and `issued` are read. */
	readonly amr?: readonly string[];
	/** Epoch ms. */
	readonly authenticatedAt?: number;
	readonly acr?: string;
	/** The id of a token this provider issued, by which its family and session are found. */
	readonly issued?: string;
}

/**
 * A token another issuer gave an app, for the clients listed alone: what it may give is the
 * client's allowance, its own scope and audience unread; it never acts.
 */
export interface ForeignToken extends ExchangedToken {
	readonly kind: "foreign";
	/** The clients that may exchange it, at least one. */
	readonly clients: readonly [string, ...string[]];
	/** BASE64URL(SHA-256(the holder's key thumbprint)); read only for a public client. */
	readonly holderDigest?: string;
}

/** What a verifier answers for a token it accepts, told apart by `kind`. */
export type Exchanged = OwnToken | ForeignToken;

/** Verifies one token type; throws Unavailable when it cannot tell. */
export interface ExchangeVerifier {
	readonly tokenType: string;
	verify(token: string): Promise<Exchanged | { readonly kind: "invalid" }>;
	/** Records a once-only token, once, after the token it is exchanged for is issued; throws Unavailable when it cannot tell. */
	consume?(token: string): Promise<"consumed" | "replayed">;
}

/** The verifiers of the tokens a client may exchange, one per token type. */
export const exchangeVerifiers = extensionPoint<ExchangeVerifier>("token-exchange.verifiers", {
	multiplicity: "keyed",
	keyOf: (verifier) => verifier.tokenType,
});
