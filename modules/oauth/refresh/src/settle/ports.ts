import type { FamilyStore } from "../store.ts";

/** The family store's erasure ports, offered whole, each called on the store. */
export type FamilyPorts = Required<Pick<FamilyStore, "erase" | "migrate" | "unowned">>;

/** Why the family store's ports cannot be used, or none: the one statement of the set, as the card gives it. */
export function portsRefused(families: FamilyStore): string | undefined {
	const offered = [families.erase, families.migrate, families.unowned].filter(
		(port) => port !== undefined,
	);
	if (offered.length === 0 || offered.length === 3) return undefined;
	return "the family store offers part of erase, migrate and unowned: it offers all three, or none";
}

/** The set, where the store offers it whole; none otherwise, `portsRefused` refusing a part at build. */
export function portsOf(families: FamilyStore): FamilyPorts | undefined {
	const { erase, migrate, unowned } = families;
	if (!erase || !migrate || !unowned) return undefined;
	// Called on the store, so an implementation keeps its own `this`.
	return {
		erase: (subject, signal) => erase.call(families, subject, signal),
		migrate: (walk, reading, signal) => migrate.call(families, walk, reading, signal),
		unowned: (id, record, lifetimeMs) => unowned.call(families, id, record, lifetimeMs),
	};
}
