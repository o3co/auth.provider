import { contract } from "@mod/kernel";

/** A reference kept for a session, and how long it still lives. */
export interface IssuedToken {
	readonly member: string;
	readonly remainingMs: number;
}

/** The references of the tokens issued in each session, each kept for its lifetime. Every call throws Unavailable when the place cannot tell. */
export interface IssuedTokens {
	/** Adds a reference for its lifetime, answering the references the place had to push out to keep within its size. */
	add(
		session: string,
		reference: string,
		lifetimeMs: number,
	): Promise<{ readonly pushedOut: readonly string[] }>;
	/** The references kept for the session now, and how long each still lives. */
	members(session: string): Promise<readonly IssuedToken[]>;
	/** The references an add pushed out of the session's set, kept in that same write, until settled or their tokens end. */
	awaiting(session: string): Promise<readonly string[]>;
	/** Takes a pushed-out reference off what awaits, once its token is revoked. */
	settled(session: string, reference: string): Promise<void>;
	/** How many references the place keeps to a session before it pushes one out. */
	readonly size: number;
}

export const issuedTokens = contract<IssuedTokens>("session-tokens.issued-tokens");

/** A lost reference would let its token outlive the session's close. */
export const issuedTokensNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
} as const;

/** Which session each token was issued for, by token id. Every call throws Unavailable when the place cannot tell. */
export interface TokenIndex {
	/** Keeps the token's session for its lifetime, unless the id holds one. */
	save(tokenId: string, handle: string, lifetimeMs: number): Promise<"created" | "exists">;
	read(tokenId: string): Promise<string | undefined>;
}

export const tokenIndex = contract<TokenIndex>("session-tokens.token-index");

/**
 * A lost entry would answer a session's token as bound to none. A token id opens nothing (it is a
 * readable claim of the token), so it names its entry as it is.
 */
export const tokenIndexNeeds = issuedTokensNeeds;

/**
 * The sessions whose sets may hold pushed-out references awaiting revocation, each listed before
 * an add that may push one out, and kept until done. Every call throws Unavailable when the place cannot tell.
 */
export interface PendingSessions {
	add(session: string): Promise<void>;
	done(session: string): Promise<void>;
	/** Hands each listed session to `handle`; one whose handling fails stays, and is counted. */
	each(handle: (session: string) => Promise<void>): Promise<{ readonly failed: number }>;
}

export const pendingSessions = contract<PendingSessions>("session-tokens.pending-sessions");

/** A lost session would leave its pushed-out tokens alive after a crash. */
export const pendingSessionsNeeds = issuedTokensNeeds;
