import type { Target } from "@mod/claims-selection";
import { contract } from "@mod/kernel";

/** A released claim's value: a string, a boolean, or a list of strings. */
export type Claim = string | boolean | readonly string[];

export interface ReleasedClaims {
	/**
	 * The subject's attributes mapped through the claim table, for the scopes asked only; never `sub`.
	 * They come from users, or the login of the session `handle` names when users cannot look the
	 * subject up; none when neither can say. Throws Unavailable when users or session fails.
	 */
	of(
		subject: string,
		scope: readonly string[],
		handle?: string,
		/** The claims a request names beyond its scope, and the constraints on all it releases. */
		asked?: Target,
	): Promise<Readonly<Record<string, Claim>>>;
}

export const releasedClaims = contract<ReleasedClaims>("oidc.claims");

export type Hint =
	/** `client` is the one the token was issued to, when its audience tells. */
	| {
			readonly kind: "valid";
			readonly subject: string;
			readonly session: string;
			readonly client?: string;
			/** Epoch ms. */
			readonly issuedAt: number;
	  }
	/** An ID token the provider signed, naming no session. */
	| { readonly kind: "sessionless" }
	| { readonly kind: "invalid" };

export interface IdTokenHints {
	/** Judges an ID token given back as a hint: one the provider signed, as its own ID token, expired or not. */
	check(token: string): Promise<Hint>;
}

export const idTokenHints = contract<IdTokenHints>("oidc.id-token-hints");
