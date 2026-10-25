import { contract } from "@mod/kernel";

export { type UsedIdTokens, usedIdTokens, usedIdTokensNeeds } from "./store.ts";

/** An id_token taken: the account users links its upstream subject to, and the one client of this provider it is for. */
export interface IdTokenTaken {
	readonly kind: "taken";
	readonly subject: string;
	/** The kind's issuer, as users is told it. */
	readonly issuer: string;
	/** In ms. */
	readonly issuedAt: number;
	/** In ms. */
	readonly expiresAt: number;
	readonly client: string;
	/** The nonce, where it has a SHA-256 digest's shape (43 base64url characters): the digest of the key its holder proves. */
	readonly holderDigest?: string;
}

/** Apple's and Google's id_tokens, checked by this module's rules, for any grant that takes them. */
export interface IdTokenChecks {
	/** Each written kind's `iss` values. */
	readonly issuers: readonly string[];
	/** The id_token taken, or invalid; throws Unavailable when the keys, users or revocations cannot tell. */
	check(idToken: string): Promise<IdTokenTaken | { readonly kind: "invalid" }>;
	/** Takes it once, in the record the exchange takes it in too; throws Unavailable when the record cannot tell. */
	consume(idToken: string): Promise<"consumed" | "replayed">;
}

/** Taken by this module, for the exchange, and by the module taking these id_tokens as JWT bearer assertions. */
export const idTokenChecks = contract<IdTokenChecks>("exchange-id-tokens.checks", {
	takenBy: ["exchange-id-tokens", "jwt-bearer-id-tokens"],
});
