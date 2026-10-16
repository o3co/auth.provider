import type { Client } from "@mod/clients";
import { contract } from "@mod/kernel";
import type { Binding } from "@mod/sender-binding";

declare const handle: unique symbol;
/** A family as `lineage` names it to others; only refresh reads it. */
export type FamilyHandle = { readonly [handle]: true };

export type TokenFamily =
	| { readonly kind: "family"; readonly family: FamilyHandle; readonly expiresAt: number }
	| { readonly kind: "none" }
	| { readonly kind: "ended" };

/** An issued access token, as `tokens` answered it. */
export interface IssuedToken {
	readonly id: string;
	/** Epoch ms. */
	readonly expiresAt: number;
}

/** A family bound to no session, and the access token issued with it. */
export interface Beginning {
	readonly client: Client;
	readonly subject: string;
	readonly scope: readonly string[];
	readonly audience: readonly string[];
	/** Epoch ms. */
	readonly authenticatedAt: number;
	/** The authentication time is not known: no access token of the family states one. */
	readonly authenticatedAtUnknown?: true;
	readonly amr: readonly string[];
	readonly acr?: string;
	readonly binding?: Binding;
	readonly access: IssuedToken;
}

/** The families access tokens belong to. Every call throws Unavailable when it cannot tell. */
export interface Lineage {
	/** The family a token was issued from; ask only for a token already verified. */
	of(tokenId: string): Promise<TokenFamily>;
	/** Adds a token that ends by the family's end; when not adopted, the token is revoked. */
	adopt(family: FamilyHandle, issued: IssuedToken): Promise<"adopted" | "ended">;
	/** Starts a family and answers its first refresh token; nothing when the client may not refresh. */
	start(beginning: Beginning): Promise<string | undefined>;
}

export const lineage = contract<Lineage>("refresh.lineage");

export * from "./store.ts";

export const refreshGrantType = "refresh_token";
