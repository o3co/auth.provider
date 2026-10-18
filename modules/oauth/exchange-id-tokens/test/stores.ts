import { memoryRecords } from "@mod/records/testing";
import type { UsedIdTokens } from "../src/store.ts";

/** exchange-id-tokens' store interface on the records stand-in, its clock moved by hand. */
export function memoryUsedIdTokens() {
	let now = 0;
	const kept = memoryRecords<{ readonly taken: true }>(() => now, { shards: 1, perShard: 1 });
	const used: UsedIdTokens = {
		save: (kind, name, lifetimeMs) =>
			kept.records.create(`${kind}/${name}`, { taken: true }, lifetimeMs),
	};
	const advance = (ms: number) => {
		now += ms;
	};
	return { used, advance };
}
