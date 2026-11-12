import type { CodeStore, RedemptionRecords } from "../store.ts";

/** The two places code-grant keeps a subject's data in, each with its erase and migrate. */
export interface ErasableStores {
	readonly codes: CodeStore;
	readonly kept: RedemptionRecords;
}

/** Each place's erasure ports, offered whole, each called on its place. */
export interface StorePorts {
	readonly codes: Required<Pick<CodeStore, "erase" | "migrate">>;
	readonly kept: Required<Pick<RedemptionRecords, "erase" | "migrate">>;
}

const portsIn = (stores: ErasableStores) =>
	[stores.codes, stores.kept].flatMap((one) => [one.erase, one.migrate]);

/** Why the stores' ports cannot be used, or none: the one statement of the set, as the card gives it. */
export function portsRefused(stores: ErasableStores): string | undefined {
	const offered = portsIn(stores).filter((port) => port !== undefined).length;
	if (offered === 0 || offered === 4) return undefined;
	return "the code store and the redemption records offer part of their erase and migrate: all four, or none";
}

/** The set, where the stores offer it whole; none otherwise, `portsRefused` refusing a part at build. */
export function portsOf(stores: ErasableStores): StorePorts | undefined {
	const { codes, kept } = stores;
	if (!codes.erase || !codes.migrate || !kept.erase || !kept.migrate) return undefined;
	const [ce, cm, ke, km] = [codes.erase, codes.migrate, kept.erase, kept.migrate];
	// Called on each place, so an implementation keeps its own `this`.
	return {
		codes: {
			erase: (subject, signal) => ce.call(codes, subject, signal),
			migrate: (walk, reading, signal) => cm.call(codes, walk, reading, signal),
		},
		kept: {
			erase: (subject, signal) => ke.call(kept, subject, signal),
			migrate: (walk, reading, signal) => km.call(kept, walk, reading, signal),
		},
	};
}
