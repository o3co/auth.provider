import type { CodeStore, RedemptionRecords } from "./store.ts";

/** The two places code-grant keeps a subject's data in, each with its erase and migrate. */
export interface ErasableStores {
	readonly codes: CodeStore;
	readonly kept: RedemptionRecords;
}

const portsIn = (stores: ErasableStores) =>
	[stores.codes, stores.kept].flatMap((one) => [one.erase, one.migrate]);

/** Why the stores' ports cannot be used, or none: the one statement of the set, as the card gives it. */
export function portsRefused(stores: ErasableStores): string | undefined {
	const offered = portsIn(stores).filter((port) => port !== undefined).length;
	if (offered === 0 || offered === 4) return undefined;
	return "the code store and the redemption records offer part of their erase and migrate: all four, or none";
}
