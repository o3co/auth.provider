import type {
	MigrationReport,
	SetReading,
	SpaceReport,
	SubjectReading,
	Walk,
} from "@mod/erasure-extensions";
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
	/**
	 * Keeps a new session's record for its lifetime and its subject, unless the handle holds one
	 * already (`exists`) or, where the Store fences saves past a subject's erasure, the subject is
	 * erased there (`erased`). The subject comes last: keep this value, this long, for this subject.
	 */
	save(
		handle: string,
		record: StoredSession,
		lifetimeMs: number,
		subject: string,
	): Promise<"created" | "exists" | "erased">;
	read(handle: string): Promise<StoredSession | undefined>;
	/**
	 * Changes the record from what it holds; `change` reruns on a race, so it is pure. Nothing when
	 * gone, or, where the Store fences saves past a subject's erasure, when its subject is erased.
	 */
	update(
		handle: string,
		change: (record: StoredSession) => ChangedSession | undefined,
	): Promise<{ readonly before: StoredSession; readonly after: StoredSession } | undefined>;
	/**
	 * Erases a subject's sessions here, where the Store can: optional in 0.20, required in 0.22, as a
	 * Store not built through `subject-records` cannot be erased. `eachRemoved`, where given, is told
	 * each record a committed write removed, once, and must not throw or write. This store's `erase`
	 * and `migrate` and the listing's come together or none; a part refuses the boot.
	 */
	erase?(
		subject: string,
		signal: AbortSignal,
		eachRemoved?: (record: StoredSession) => void,
	): Promise<SpaceReport>;
	/** Once, under the maintenance key, each record read by session-lifecycle's reading; optional as `erase` is. */
	migrate?(walk: Walk, subjectOf: SubjectReading, signal: AbortSignal): Promise<MigrationReport>;
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
	/**
	 * Lists the handle for its lifetime; answers the others pushed out over the place's cap, never the
	 * handle being added. Where the Store fences saves past a subject's erasure, `erased` for an
	 * erased subject; a Store keying listings otherwise may answer `another-subject`. Either is a refusal.
	 */
	add(
		subject: string,
		handle: string,
		lifetimeMs: number,
	): Promise<{ readonly pushedOut: readonly string[] } | "erased" | "another-subject">;
	members(subject: string): Promise<readonly { readonly member: string }[]>;
	remove(subject: string, handle: string): Promise<void>;
	/** Erases a subject's listing, where the Store can; with the session store's ports, or none. */
	erase?(subject: string, signal: AbortSignal): Promise<SpaceReport>;
	/** Once, under the maintenance key: raw listings of a space keyed by subject stay raw (0/0). */
	migrate?(walk: Walk, reading: SetReading, signal: AbortSignal): Promise<MigrationReport>;
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
