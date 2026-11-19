/** A space the store has seen declared, and whether any declaration may have held a subject's data. */
export interface KeptSpace {
	readonly name: string;
	readonly subjectDataEver: boolean;
}

/** The ledger's part of `StoreUpkeep`; no contract of its own. */
export interface StoreLedger {
	/** Every space ever declared to the store's data, until retired. */
	kept(): Promise<readonly KeptSpace[]>;
	/** Takes a space off the ledger, under the maintenance key alone; never one this process declares. */
	retire(
		name: string,
	): Promise<
		| { readonly kind: "retired" }
		| { readonly kind: "declared" }
		| { readonly kind: "missing" }
		| { readonly kind: "not-in-maintenance" }
	>;
}
