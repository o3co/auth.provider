import { area } from "@mod/conformance";

export interface UserScene {
	readonly identifier: string;
	/** Plain; each target stores it in its own form. */
	readonly password: string;
	readonly subject?: string;
	/** Store the password as a bcrypt hash, where the scene is about bcrypt. */
	readonly bcrypt?: boolean;
	/** The upstream identity linked to this user. */
	readonly upstream?: UpstreamScene;
	/** The address the user's account states, as its claimed email. */
	readonly email?: string;
	/** Whether the user's account states that email verified; stated by neither when left out. */
	readonly emailVerified?: boolean;
}

/** An upstream identity: an IdP's name and the upstream subject there. */
export interface UpstreamScene {
	readonly idp: string;
	readonly subject: string;
}

/** A user ledger the deployment asks over HTTP to verify passwords. */
export interface LedgerScene {
	/** Where a password is verified: `POST {"email", "password"}`, answering `{"id", "username", ...}`. */
	readonly verifyUrl: string;
	readonly credential: string;
	/** How long the deployment waits for an answer. */
	readonly timeoutMs?: number;
	/** Where a user is looked up by upstream identity, `POST {"idp", "subject"}`, on the same host; with no lookup by subject beside it. */
	readonly upstreamUrl?: string;
}

/** A ledger that revokes subjects over HTTP, from its sources with its credential. */
export interface RevocationScene {
	readonly credential: string;
	readonly sources: readonly string[];
}

/** People who log in with a password at a public origin, and what a login may do. */
export interface IdentityPart {
	/** The origin browsers reach the deployment at, behind its proxy. */
	readonly origin: string;
	readonly users: readonly UserScene[];
	/** Users answered from a ledger over HTTP, beside or instead of `users`. */
	readonly ledger?: LedgerScene;
	readonly login?: {
		/** Where a login may send the user back to. */
		readonly returnTargets?: readonly string[];
		/** How many attempts each sender gets in the window. */
		readonly attempts?: number;
		readonly windowSeconds?: number;
		/** Failed attempts at one identifier, from any sender, before each next one waits. */
		readonly accountAttempts?: number;
		readonly accountWindowSeconds?: number;
		/** The longest an identifier waits between attempts. */
		readonly accountMaxWaitSeconds?: number;
	};
	readonly revocations?: RevocationScene;
	/** How recent a sign-in a step that changes credentials asks, in seconds (`recentAuthenticationWindow`). */
	readonly recentAuthenticationSeconds?: number;
	/** The https origins whose pages may read the routes that take cross-origin requests. */
	readonly corsOrigins?: readonly string[];
	/** How a request limit answers while the store cannot count (`rate-limit.fail-mode`); the deployment's default unless set. */
	readonly rateLimitWhileStoreFails?: "open" | "closed";
}

export const identityArea = area<IdentityPart>("identity");

/** The need for a user ledger asked over HTTP. */
export const httpLedger = "identity:http-ledger";
/** The need for such a ledger set beside users in the settings. */
export const ledgerBesideUsers = "identity:ledger-beside-users";
/** The need for a ledger that revokes subjects over HTTP. */
export const ledgerRevocation = "identity:ledger-revocation";
/** The need for a recent-authentication window the scene sets. */
export const recentAuthenticationWindow = "identity:recent-authentication-window";
