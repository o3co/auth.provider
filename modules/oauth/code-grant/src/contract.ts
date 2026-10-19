import type { Client } from "@mod/clients";
import { contract, extensionPoint } from "@mod/kernel";
import type { Binding } from "@mod/sender-binding";
import type { IssuedAccess } from "@mod/tokens";

export interface CodeFacts {
	readonly clientId: string;
	readonly redirectUri: string;
	readonly challenge: string;
	readonly nonce?: string;
	readonly scope: readonly string[];
	readonly audience: readonly string[];
	readonly session: string;
	readonly subject: string;
	/** The authentication context class the issuer judged met; carried to the ID token as it is. */
	readonly acr?: string;
}

export interface Codes {
	issue(facts: CodeFacts): Promise<string>;
	idTokenScope(): string | undefined;
}

export const codes = contract<Codes>("code-grant");

/** The grant's type (RFC 6749 §4.1.3). */
export const codeGrantType = "authorization_code";

/** RFC 7636: an S256 challenge is 43 base64url characters; a code is issued only for one of this shape. */
export const challengeShape = /^[A-Za-z0-9_-]{43}$/;

export interface IdTokenRequest {
	readonly subject: string;
	readonly clientId: string;
	readonly nonce?: string;
	/** Epoch ms. */
	readonly authenticatedAt: number;
	readonly authenticatedAtUnknown?: true;
	readonly amr: readonly string[];
	readonly acr?: string;
	readonly scope: readonly string[];
	/** The session's handle, which never lets anyone into it. */
	readonly session: string;
}

export interface IdTokenMaker {
	readonly scope: string;
	make(request: IdTokenRequest): Promise<string>;
}

export const idTokens = extensionPoint<IdTokenMaker>("code-grant.id-tokens", {
	multiplicity: "many",
});

/** Told of each code redeemed in a session, so it can act on the session's clients when it closes. */
export interface SessionRedemption {
	readonly name: string;
	/** Answers once noted; a failure voids the code. Safe to repeat. */
	redeemed(session: string, clientId: string): Promise<void>;
}

export const sessionRedemptions = extensionPoint<SessionRedemption>(
	"code-grant.session-redemptions",
	{ multiplicity: "keyed", keyOf: (contribution) => contribution.name },
);

export interface Redeemed {
	/** Names this redemption, for taking back what was issued alongside if the code comes again. */
	readonly redemption: string;
	readonly client: Client;
	readonly subject: string;
	readonly scope: readonly string[];
	readonly audience: readonly string[];
	readonly session: string;
	/** Epoch ms. */
	readonly authenticatedAt: number;
	readonly authenticatedAtUnknown?: true;
	readonly amr: readonly string[];
	/** The acr the code met, when it met one. */
	readonly acr?: string;
	readonly access: Omit<IssuedAccess, "token">;
	readonly binding?: Binding;
}

export interface Addition {
	readonly field: string;
	/** Nothing when it has nothing to add for this code. */
	issue(redeemed: Redeemed): Promise<string | undefined>;
	/** Ends what `issue` gave for a redemption; safe to repeat, and from several hosts at once. */
	revoke?(redemption: string): Promise<void>;
}

export const additions = extensionPoint<Addition>("code-grant.additions", {
	multiplicity: "keyed",
	keyOf: (addition) => addition.field,
});

export * from "./store.ts";
