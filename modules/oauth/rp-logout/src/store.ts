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

/** The back-channel notices not yet delivered, kept until done. Every call throws Unavailable when the place cannot tell. */
export interface PendingNotices {
	add(notice: string): Promise<void>;
	done(notice: string): Promise<void>;
	/** Hands each listed notice to `handle`; one whose handling fails stays, and is counted. */
	each(handle: (notice: string) => Promise<void>): Promise<{ readonly failed: number }>;
}

export const pendingNotices = contract<PendingNotices>("rp-logout.pending-notices");

/** A lost notice would leave a client holding a session that closed. */
export const pendingNoticesNeeds = sessionClientsNeeds;
