import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { contract } from "@mod/kernel";

/** A client kept for a session, and how long it is still kept. */
export interface SessionClient {
	readonly member: string;
	readonly remainingMs: number;
}

/** The clients that redeemed a code in each session, each kept for a lifetime. Every call throws Unavailable when the place cannot tell. */
export interface SessionClients {
	/** Adds a client for its lifetime, answering the clients the place had to push out to keep within its size. */
	add(
		session: string,
		client: string,
		lifetimeMs: number,
	): Promise<{ readonly pushedOut: readonly string[] }>;
	members(session: string): Promise<readonly SessionClient[]>;
}

export const sessionClients = contract<SessionClients>("rp-logout.session-clients");

/** A lost client would never hear that its session closed. */
export const sessionClientsNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
} as const;

/**
 * The back-channel notices not yet delivered, kept until done, as 0.19 kept them. Read and drained:
 * from the switch to bodies kept apart, no new caller adds. Every call throws Unavailable when the
 * place cannot tell. TODO(0.22): removed, with the drain and the space retired.
 */
export interface PendingNotices {
	add(notice: string): Promise<void>;
	done(notice: string): Promise<void>;
	/** Hands each listed notice to `handle`; one whose handling fails stays, and is counted. */
	each(handle: (notice: string) => Promise<void>): Promise<{ readonly failed: number }>;
}

export const pendingNotices = contract<PendingNotices>("rp-logout.pending-notices");

/** A lost notice would leave a client holding a session that closed. */
export const pendingNoticesNeeds = sessionClientsNeeds;

/**
 * Each notice's body, by its id (the SHA-256 of the body), kept under its subject until the notice
 * is given up, and never changed. Every call throws Unavailable when the place cannot tell.
 */
export interface NoticeBodies {
	/**
	 * Keeps a body for its lifetime and its subject, unless the id holds one already (`exists`) or,
	 * where the Store fences creation past a subject's erasure, the subject is erased (`erased`).
	 */
	create(
		id: string,
		body: string,
		lifetimeMs: number,
		subject: string,
	): Promise<"created" | "exists" | "erased">;
	read(id: string): Promise<string | undefined>;
	/** Removes a body whose notice is settled; what it answers is not read. */
	remove(id: string): Promise<unknown>;
	/**
	 * Erases a subject's bodies here, where the Store can, handing each body removed to `eachRemoved`:
	 * optional in 0.20, required in 0.22. With `migrate`, both or neither.
	 */
	erase?(
		subject: string,
		signal: AbortSignal,
		eachRemoved?: (body: string) => void,
	): Promise<SpaceReport>;
	/** Once, under the maintenance key; optional as `erase` is. */
	migrate?(walk: Walk, reading: SubjectReading, signal: AbortSignal): Promise<MigrationReport>;
}

export const noticeBodies = contract<NoticeBodies>("rp-logout.notice-bodies");

/** A lost notice would leave a client holding a session that closed. */
export const noticeBodiesNeeds = sessionClientsNeeds;

/** The notices to try, each an entry (a body's id, and the time before which it is not tried), kept until done. Every call throws Unavailable when the place cannot tell. */
export interface NoticeQueue {
	add(entry: string): Promise<void>;
	done(entry: string): Promise<void>;
	/** Hands each listed entry to `handle`; one whose handling fails stays, and is counted. */
	each(handle: (entry: string) => Promise<void>): Promise<{ readonly failed: number }>;
}

export const noticeQueue = contract<NoticeQueue>("rp-logout.notice-queue");

/** A lost entry would leave its notice untried, and its client holding a session that closed. */
export const noticeQueueNeeds = sessionClientsNeeds;
