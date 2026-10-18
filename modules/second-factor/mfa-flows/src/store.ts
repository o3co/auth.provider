import { contract } from "@mod/kernel";

declare const storedTransaction: unique symbol;
/** A transaction as the store keeps it: only mfa-flows opens it. */
export type StoredTransaction = { readonly [storedTransaction]: true };

/** A transaction as a change leaves it; its lifetime stays. */
export interface ChangedTransaction {
	readonly value: StoredTransaction;
}

/** Transactions by their identifier, never kept in clear, each kept for its lifetime and changed only from what it holds. Every call throws Unavailable when the place cannot tell. */
export interface TransactionStore {
	save(id: string, record: StoredTransaction, lifetimeMs: number): Promise<"created" | "exists">;
	read(id: string): Promise<StoredTransaction | undefined>;
	/** Changes the transaction from what it holds; `change` runs again on a race, so it is pure; none leaves it. Nothing when gone. */
	update(
		id: string,
		change: (record: StoredTransaction) => ChangedTransaction | undefined,
	): Promise<{ readonly before: StoredTransaction; readonly after: StoredTransaction } | undefined>;
}

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
	/** Lists the member for its lifetime; answers the others pushed out over the cap, never the one being added. */
	add(
		key: string,
		member: string,
		lifetimeMs: number,
	): Promise<{ readonly pushedOut: readonly string[] }>;
	members(key: string): Promise<readonly { readonly member: string }[]>;
	remove(key: string, member: string): Promise<void>;
}

export const transactionListings = contract<TransactionListings>("mfa-flows.transaction-listings");

/** The live transactions one holder keeps; one more pushes out the one ending first. A constant, not a setting. */
export const transactionsPerHolder = 5;

/** A transaction counts only while listed, so a listing that loses or misreads a member refuses a live one. */
export const transactionListingsNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	readsConfirmed: true,
} as const;
