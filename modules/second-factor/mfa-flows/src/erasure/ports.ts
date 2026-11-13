import type { TransactionListings, TransactionStore } from "../store.ts";

/** The stores' erasure ports, offered whole: the transaction store's and the listings', each called on its store. */
export interface TransactionPorts {
	readonly erase: Required<TransactionStore>["erase"];
	readonly migrate: Required<TransactionStore>["migrate"];
	readonly eraseListings: Required<TransactionListings>["erase"];
	readonly migrateListings: Required<TransactionListings>["migrate"];
}

/** Why the stores' ports cannot be used, or none: the one statement of the set, as the card gives it. */
export function portsRefused(
	store: TransactionStore,
	listings: TransactionListings,
): string | undefined {
	const offered = [store.erase, store.migrate, listings.erase, listings.migrate].filter(
		(port) => port !== undefined,
	);
	if (offered.length === 0 || offered.length === 4) return undefined;
	return "the transaction store and the listings offer part of erase and migrate: both offer both, or neither does";
}

/** The set, where the stores offer it whole; none otherwise, `portsRefused` refusing a part at build. */
export function portsOf(
	store: TransactionStore,
	listings: TransactionListings,
): TransactionPorts | undefined {
	const { erase, migrate } = store;
	const { erase: eraseListings, migrate: migrateListings } = listings;
	if (!erase || !migrate || !eraseListings || !migrateListings) return undefined;
	// Called on the store, so an implementation keeps its own `this`.
	return {
		erase: (subject, signal) => erase.call(store, subject, signal),
		migrate: (walk, reading, signal) => migrate.call(store, walk, reading, signal),
		eraseListings: (subject, signal) => eraseListings.call(listings, subject, signal),
		migrateListings: (walk, reading, signal) =>
			migrateListings.call(listings, walk, reading, signal),
	};
}
