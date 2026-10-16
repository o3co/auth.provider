import { extensionPoint } from "@mod/kernel";
import type { Binding } from "@mod/sender-binding";
import type { Actor } from "@mod/tokens";

export const accessTokenType = "urn:ietf:params:oauth:token-type:access_token";

/** What a verifier answers for a token it accepts. */
export interface Exchanged {
	readonly subject: string;
	readonly issuer: string;
	/** The client the token was issued to (`azp`). */
	readonly issuedTo?: string;
	readonly audience: readonly string[];
	readonly scope: readonly string[];
	/** Epoch ms. */
	readonly expiresAt: number;
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

/** Verifies one token type; throws Unavailable when it cannot tell. */
export interface ExchangeVerifier {
	readonly tokenType: string;
	verify(token: string): Promise<Exchanged | { readonly kind: "invalid" }>;
}

/** The verifiers of the tokens a client may exchange, one per token type. */
export const exchangeVerifiers = extensionPoint<ExchangeVerifier>("token-exchange.verifiers", {
	multiplicity: "keyed",
	keyOf: (verifier) => verifier.tokenType,
});
