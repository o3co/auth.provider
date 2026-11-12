import type { HeldLoginStore } from "./store.ts";

/** The held login store's erasure ports, offered whole, each called on the Store. */
export type HeldPorts = Required<Pick<HeldLoginStore, "erase" | "migrate">>;

/** Why the Store's ports cannot be used, or none: the one statement of the pair, as the card gives it. */
export function portsRefused(held: HeldLoginStore): string | undefined {
	if ((held.erase === undefined) === (held.migrate === undefined)) return undefined;
	return "the held login store offers one of erase and migrate: it offers both, or neither";
}

/** The pair, where the Store offers it whole; none otherwise, `portsRefused` refusing a half at build. */
export function portsOf(held: HeldLoginStore): HeldPorts | undefined {
	const { erase, migrate } = held;
	if (!erase || !migrate) return undefined;
	// Called on the Store, so an implementation keeps its own `this`.
	return {
		erase: (subject, signal) => erase.call(held, subject, signal),
		migrate: (walk, reading, signal) => migrate.call(held, walk, reading, signal),
	};
}
