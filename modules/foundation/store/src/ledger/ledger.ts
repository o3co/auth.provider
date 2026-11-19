/** A space the store has seen declared, and whether any declaration may have held a subject's data. */
export interface KeptSpace {
	readonly name: string;
	readonly subjectDataEver: boolean;
}

/**
 * A page of a kept space's walk: counts, never keys. `live` counts the live keys this page met (the
 * space's values, counters, idempotency marks and the store's own keys of it), each physical key
 * once each time a page meets it, so a sum is exact only at zero; `noExpiry` those whose expiry is
 * never; `latestExpiry` the latest expiry, on the store clock, among the rest. The walk's first page
 * alone answers the space's generation. The cursor is an opaque handle to the walk, holding no key.
 */
export interface KeptPage {
	readonly kind: "page";
	readonly live: number;
	readonly noExpiry: number;
	readonly latestExpiry?: number;
	readonly generation?: string;
	readonly cursor?: string;
	readonly server: string;
}

/** The ledger's part of `StoreUpkeep`; no contract of its own. */
export interface StoreLedger {
	/** Every space ever declared to the store's data, until retired. */
	kept(): Promise<readonly KeptSpace[]>;
	/**
	 * Takes a space off the ledger, under the maintenance key alone, as of the generation a walk
	 * read where one is given; never one this process declares.
	 */
	retire(
		name: string,
		generation?: string,
	): Promise<
		| { readonly kind: "retired" }
		| { readonly kind: "declared" }
		| { readonly kind: "redeclared" }
		| { readonly kind: "missing" }
		| { readonly kind: "not-in-maintenance" }
	>;
	/**
	 * A page of a kept space's walk, by its name: a space on the ledger that this process doesn't
	 * declare. It walks every key of the space, page by page as `sweep` does, removing for good each
	 * expired one it meets, its answer confirmed as a write wherever the store confirms writes,
	 * whatever the space once declared. Under the maintenance key alone. It answers counts, never
	 * keys: operational metadata inside the maintenance boundary. Offered until every implementation
	 * offers it; a reader finding none cannot walk, and so retires nothing.
	 */
	sweepKept?(
		name: string,
		cursor?: string,
	): Promise<
		| KeptPage
		| { readonly kind: "declared" }
		| { readonly kind: "missing" }
		| { readonly kind: "not-in-maintenance" }
	>;
}
