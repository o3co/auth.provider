import { contract } from "@mod/kernel";

declare const stored: unique symbol;
/** A login's transaction as the store keeps it: the store never reads it, and only federation opens it. */
export type StoredTransaction = { readonly [stored]: true };

/** Where transactions are kept, by their cookie, never kept in clear. Every call throws Unavailable when the place cannot tell. */
export interface TransactionStore {
	/** Keeps a new record for its lifetime, unless the cookie holds one already. */
	save(
		cookie: string,
		record: StoredTransaction,
		lifetimeMs: number,
	): Promise<"created" | "exists">;
	/** Changes the record from what it holds; `change` reruns on a race, so it is pure. Nothing when gone. */
	update(
		cookie: string,
		change: (record: StoredTransaction) => { readonly value: StoredTransaction } | undefined,
	): Promise<{ readonly before: StoredTransaction; readonly after: StoredTransaction } | undefined>;
	remove(cookie: string): Promise<void>;
}

export const transactionStore = contract<TransactionStore>("federation.transaction-store");

/** A taken transaction back after a failover could finish a login twice; a lost one only restarts it. */
export const transactionStoreNeeds = {
	survivesFailover: true,
	/** Names derive from the cookie, so the place never keeps it in clear. */
	namesFromSecret: true,
} as const;
