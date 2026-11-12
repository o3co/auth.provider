import type { UpstreamTokenStore } from "../store.ts";

/** The upstream token store's erasure ports, offered whole, each called on the store. */
export type TokenPorts = Required<Pick<UpstreamTokenStore, "erase" | "migrate">>;

/** Why the store's ports cannot be used, or none: the one statement of the pair, as the card gives it. */
export function portsRefused(store: UpstreamTokenStore): string | undefined {
	if ((store.erase === undefined) === (store.migrate === undefined)) return undefined;
	return "the upstream token store offers one of erase and migrate: it offers both, or neither";
}

/** The pair, where the store offers it whole; none otherwise, `portsRefused` refusing a half at build. */
export function portsOf(store: UpstreamTokenStore): TokenPorts | undefined {
	const { erase, migrate } = store;
	if (!erase || !migrate) return undefined;
	// Called on the store, so an implementation keeps its own `this`.
	return {
		erase: (subject, signal) => erase.call(store, subject, signal),
		migrate: (walk, reading, signal) => migrate.call(store, walk, reading, signal),
	};
}
