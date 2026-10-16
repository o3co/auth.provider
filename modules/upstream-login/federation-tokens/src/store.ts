import { contract } from "@mod/kernel";

declare const stored: unique symbol;
/** A session's upstream tokens as the store keeps them: sealed per IdP, with a version; only federation-tokens opens them. */
export type StoredUpstreamTokens = { readonly [stored]: true };

/** One record per session, by its handle. Every call throws Unavailable when the place cannot tell. */
export interface UpstreamTokenStore {
	/** Keeps a session's first record for its lifetime, unless the session holds one. */
	save(
		session: string,
		record: StoredUpstreamTokens,
		lifetimeMs: number,
	): Promise<"created" | "exists">;
	read(session: string): Promise<StoredUpstreamTokens | undefined>;
	/** Changes the record from what it holds, with a new lifetime; `change` reruns on a race, so it is pure. Nothing when gone. */
	update(
		session: string,
		change: (
			record: StoredUpstreamTokens,
		) => { readonly value: StoredUpstreamTokens; readonly lifetimeMs: number } | undefined,
	): Promise<
		{ readonly before: StoredUpstreamTokens; readonly after: StoredUpstreamTokens } | undefined
	>;
	remove(session: string): Promise<void>;
}

export const upstreamTokenStore = contract<UpstreamTokenStore>(
	"federation-tokens.upstream-token-store",
);

/** A record evicted or rolled back would lose a link, or bring back tokens a logout removed. */
export const upstreamTokenStoreNeeds = { neverEvicted: true, survivesFailover: true } as const;

/** A lock as a change leaves it: its holder's mark, for its lifetime. */
export interface HeldLock {
	readonly value: string;
	readonly lifetimeMs: number;
}

/** Locks by name, each held until let go or its lifetime ends. Every call throws Unavailable when the place cannot tell. */
export interface RefreshLocks {
	/** Takes the lock under its holder's mark unless another holds it. */
	hold(name: string, mark: string, lifetimeMs: number): Promise<"created" | "exists">;
	/** Changes a held lock from the mark it holds now, writing only over what it read; nothing when none is held. */
	update(name: string, change: (held: string) => HeldLock | undefined): Promise<unknown>;
}

export const refreshLocks = contract<RefreshLocks>("federation-tokens.refresh-locks");

/** A lock evicted while held would let two hosts refresh at once. */
export const refreshLocksNeeds = { neverEvicted: true } as const;
