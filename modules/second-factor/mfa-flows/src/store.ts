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
