import { contract } from "@mod/kernel";

declare const stored: unique symbol;
/** A session's record as the store keeps it: the store never reads it, and only session-lifecycle opens it. */
export type StoredSession = { readonly [stored]: true };

/** A record as a change leaves it. `lifetimeMs` restarts its lifetime at the write ("endless": it never ends); without it, the lifetime stays. */
export interface ChangedSession {
	readonly value: StoredSession;
	readonly lifetimeMs?: number | "endless";
}

/** Where sessions are kept, by handle. Every call throws Unavailable when the place cannot tell. */
export interface SessionStore {
	/** Keeps a new session's record for its lifetime, unless the handle holds one already. */
	save(handle: string, record: StoredSession, lifetimeMs: number): Promise<"created" | "exists">;
	read(handle: string): Promise<StoredSession | undefined>;
	/** Changes the record from what it holds; `change` reruns on a race, so it is pure. Nothing when gone. */
	update(
		handle: string,
		change: (record: StoredSession) => ChangedSession | undefined,
	): Promise<{ readonly before: StoredSession; readonly after: StoredSession } | undefined>;
}

/** Which session a cookie opens, by the cookie's secret; the place never keeps the secret in clear. */
export interface CookieIndex {
	save(secret: string, handle: string, lifetimeMs: number): Promise<"created" | "exists">;
	read(secret: string): Promise<string | undefined>;
	/** Takes the secret out whatever it holds; a lost answer is settled, so a removal stays removed. */
	remove(secret: string): Promise<void>;
}

/** The sessions whose closing must still be finished, kept until done. */
export interface ClosingList {
	add(handle: string): Promise<void>;
	done(handle: string): Promise<void>;
	/** Hands each kept closing to `handle`; one whose handling fails stays, and is counted. */
	each(handle: (handle: string) => Promise<void>): Promise<{ readonly failed: number }>;
}

/** Each subject's live sessions, listed for their lifetime, so a revocation closes them all. Every call throws Unavailable when the place cannot tell. */
export interface SubjectSessions {
	/** Lists the handle for its lifetime; answers the others pushed out over the place's cap, never the handle being added. */
	add(
		subject: string,
		handle: string,
		lifetimeMs: number,
	): Promise<{ readonly pushedOut: readonly string[] }>;
	members(subject: string): Promise<readonly { readonly member: string }[]>;
	remove(subject: string, handle: string): Promise<void>;
}

export const sessionStore = contract<SessionStore>("session-lifecycle.session-store");
export const cookieIndex = contract<CookieIndex>("session-lifecycle.cookie-index");
export const closingList = contract<ClosingList>("session-lifecycle.closing-list");
export const subjectSessions = contract<SubjectSessions>("session-lifecycle.subject-sessions");

/** Losing a closing would skip its participants; a retired cookie coming back would enter a raised session. An entry decides on what other requests wrote, so it reads only what a failover keeps. */
export const sessionStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	readsConfirmed: true,
} as const;

/** The cookie index's needs: those of the others, and names that derive from the cookie's secret. */
export const cookieIndexNeeds = {
	...sessionStoreNeeds,
	namesFromSecret: true,
} as const;

/** A revocation closes what the listing names, so its reads must answer only from writes a failover keeps: a stale read would skip a session just opened. */
export const subjectSessionsNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	readsConfirmed: true,
} as const;
