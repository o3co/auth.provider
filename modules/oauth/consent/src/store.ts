import { contract } from "@mod/kernel";

declare const storedGrant: unique symbol;
/** A subject's agreed range for a client, as the store keeps it: only consent opens it. */
export type StoredGrant = { readonly [storedGrant]: true };

declare const storedAsk: unique symbol;
/** A pending consent, as the store keeps it: only consent opens it. */
export type StoredAsk = { readonly [storedAsk]: true };

/** A record as a change leaves it; its lifetime stays. */
export interface Changed<T> {
	readonly value: T;
}

/** A Store interface: records by key, each changed only from what it holds. Every call throws Unavailable when the Store cannot tell. */
export interface RecordStore<T> {
	/** Keeps a new record (for its lifetime, or without end), unless the key holds one. */
	save(key: string, record: T, lifetimeMs: number | "endless"): Promise<"created" | "exists">;
	read(key: string): Promise<T | undefined>;
	/** Changes the record from what it holds; `change` runs again on a race, so it is pure. Nothing when gone. */
	update(
		key: string,
		change: (record: T) => Changed<T> | undefined,
	): Promise<{ readonly before: T; readonly after: T } | undefined>;
}

export type GrantStore = RecordStore<StoredGrant>;
/** Pending consents by a key holding the challenge, an unguessable value: the Store never keeps the key in clear. */
export type AskStore = RecordStore<StoredAsk>;

export const grantStore = contract<GrantStore>("consent.grant-store");
export const askStore = contract<AskStore>("consent.ask-store");

/** An agreement read to skip the consent page was written by another request, so reads must be confirmed. */
export const grantStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	confirmedReads: true,
} as const;

/** An answer whose mark was lost would let the same ask be answered twice. */
export const askStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	/** Names derive from the key, so the Store never keeps it in clear. */
	namesFromSecret: true,
} as const;
