import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
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
	/**
	 * Keeps a new record (for its lifetime, or without end) for its subject, unless the key holds one
	 * (`exists`) or, where the Store fences erasure, the subject is erased there (`erased`), which
	 * consent takes as refused. The subject comes last: keep this value, this long, for this subject.
	 */
	save(
		key: string,
		record: T,
		lifetimeMs: number | "endless",
		subject: string,
	): Promise<"created" | "exists" | "erased">;
	read(key: string): Promise<T | undefined>;
	/** Changes the record from what it holds; `change` runs again on a race, so it is pure. Nothing when gone. */
	update(
		key: string,
		change: (record: T) => Changed<T> | undefined,
	): Promise<{ readonly before: T; readonly after: T } | undefined>;
	/**
	 * Erases a subject's records here, where the Store can: optional in 0.20, required in 0.22. A
	 * Store without it holds records consent's eraser cannot erase.
	 */
	erase?(subject: string, signal: AbortSignal): Promise<SpaceReport>;
	/**
	 * Once, under the maintenance key: puts the records written before indexing into the index, each
	 * read by `subjectOf`, consent's, so the Store never opens a record. Optional as `erase` is.
	 */
	migrate?(walk: Walk, subjectOf: SubjectReading, signal: AbortSignal): Promise<MigrationReport>;
}

export type GrantStore = RecordStore<StoredGrant>;
/** Pending consents by a key holding the challenge, an unguessable value: the Store never keeps the key in clear. */
export type AskStore = RecordStore<StoredAsk>;

/** The longest an ask lives (`challenge-lifetime` at most): a Store that fences asks by a bound declares it. */
export const askLifetimeMaxMs = 3_600_000;

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
