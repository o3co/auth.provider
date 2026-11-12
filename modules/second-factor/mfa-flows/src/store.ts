import type {
	MigrationReport,
	SetReading,
	SpaceReport,
	SubjectReading,
	Walk,
} from "@mod/erasure-extensions";
import { contract } from "@mod/kernel";
import { longestRecentMs } from "@mod/session";

declare const storedTransaction: unique symbol;
/** A transaction as the store keeps it: only mfa-flows opens it. */
export type StoredTransaction = { readonly [storedTransaction]: true };

/** A transaction as a change leaves it; its lifetime stays. */
export interface ChangedTransaction {
	readonly value: StoredTransaction;
}

/** Transactions by their identifier, never kept in clear, each kept for its lifetime and changed only from what it holds. Every call throws Unavailable when the place cannot tell. */
export interface TransactionStore {
	/**
	 * Keeps a new record for its lifetime, at most `storedLifetimeMaxMs`, and its subject,
	 * unless the identifier holds one already (`exists`) or, where the Store fences saves past a
	 * subject's erasure, the subject is erased there (`erased`). The subject comes last.
	 */
	save(
		id: string,
		record: StoredTransaction,
		lifetimeMs: number,
		subject: string,
	): Promise<"created" | "exists" | "erased">;
	read(id: string): Promise<StoredTransaction | undefined>;
	/**
	 * Changes the transaction from what it holds; `change` runs again on a race, so it is pure; none
	 * leaves it. Nothing when gone. Not fenced by its subject's erasure: a record saved before it is
	 * changed and used until its end, as a bounded space fences only a save.
	 */
	update(
		id: string,
		change: (record: StoredTransaction) => ChangedTransaction | undefined,
	): Promise<{ readonly before: StoredTransaction; readonly after: StoredTransaction } | undefined>;
	/**
	 * Fences a subject's transactions and permits here, where the Store can: optional in 0.20, required in 0.22,
	 * as a Store not built through `subject-records` cannot be erased. This store's `erase` and
	 * `migrate` and the listings' come together or none; a part refuses the boot.
	 */
	erase?(subject: string, signal: AbortSignal): Promise<SpaceReport>;
	/** Once, under the maintenance key, each transaction read by mfa-flows' reading; optional as `erase` is. */
	migrate?(walk: Walk, reading: SubjectReading, signal: AbortSignal): Promise<MigrationReport>;
}

/** The longest a transaction may be kept: the section's ceiling, refused past it by the transactions. */
export const transactionLifetimeMaxMs = 1_800_000;

/**
 * The longest the transaction store keeps a record: the longer of a transaction's ceiling and a
 * release permit's (`session`'s longest recent window), the bound a Store fencing the store declares.
 */
export const storedLifetimeMaxMs = Math.max(transactionLifetimeMaxMs, longestRecentMs);

/** @deprecated `storedLifetimeMaxMs`; removed once the store wiring reads it, in this release. */
export const heldLifetimeMaxMs = storedLifetimeMaxMs;

export const transactionStore = contract<TransactionStore>("mfa-flows.transaction-store");

/** A transaction taken once must stay taken: one that came back could finish a login twice. */
export const transactionStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	/** Names derive from the identifier, so the place never keeps it in clear. */
	namesFromSecret: true,
} as const;

/**
 * Each holder's live transactions, by a key mfa-flows names (a session's handle, or a held login's
 * subject), each listed by a digest of its identifier for its lifetime. Every call throws Unavailable
 * when the place cannot tell.
 */
export interface TransactionListings {
	/**
	 * Lists the member for its lifetime, for the holder's subject, last; answers the others pushed out
	 * over the cap, never the one being added. Where the Store fences saves past a subject's erasure,
	 * `erased` for an erased subject; a Store may answer `another-subject` where the listing under
	 * the key is another subject's. Either is a refusal.
	 */
	add(
		key: string,
		member: string,
		lifetimeMs: number,
		subject: string,
	): Promise<{ readonly pushedOut: readonly string[] } | "erased" | "another-subject">;
	members(key: string): Promise<readonly { readonly member: string }[]>;
	remove(key: string, member: string): Promise<void>;
	/** Erases a subject's listings here, where the Store can; with the transaction store's ports, or none. */
	erase?(subject: string, signal: AbortSignal): Promise<SpaceReport>;
	/** Once, under the maintenance key, each raw listing read by its key; optional as `erase` is. */
	migrate?(walk: Walk, reading: SetReading, signal: AbortSignal): Promise<MigrationReport>;
}

export const transactionListings = contract<TransactionListings>("mfa-flows.transaction-listings");

/**
 * @deprecated A store wiring sets its listing's cap (mfa-flows-store's `transactions-per-holder`, 5 by
 * default); nothing reads this.
 */
export const transactionsPerHolder = 5;

/** A transaction counts only while listed, so a listing that loses or misreads a member refuses a live one. */
export const transactionListingsNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	readsConfirmed: true,
} as const;
