import { contract } from "@mod/kernel";

export * from "./store.ts";

/** The session a token was issued for, by its handle; unbound when none was recorded for it. */
export type TokenSession =
	| { readonly kind: "bound"; readonly handle: string }
	| { readonly kind: "unbound" };

export interface SessionTokens {
	/** Throws Unavailable when the index cannot tell. */
	sessionOf(tokenId: string): Promise<TokenSession>;
}

export const sessionTokens = contract<SessionTokens>("session-tokens");
