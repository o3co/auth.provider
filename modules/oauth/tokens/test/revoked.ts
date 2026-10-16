import { defineModule, Unavailable } from "@mod/kernel";
import { memoryRecords } from "@mod/records/testing";
import { revokedTokens } from "../src/store.ts";

/** Revoked tokens kept in memory, on a place clock that may run apart from the composition's, and that can stop answering. */
export function revokedInMemory(now: () => number) {
	const place = { shift: 0, down: false };
	const stand = memoryRecords<true>(() => now() + place.shift, { shards: 1, perShard: 1 });
	const module = defineModule({ name: "revoked-tokens" }, (m) => [
		m.provide(revokedTokens).by(() => ({
			save: async (id: string, lifetimeMs: number) => {
				if (place.down) throw new Unavailable("revoked tokens");
				return stand.records.create(id, true, lifetimeMs);
			},
			holds: async (id: string) => {
				if (place.down) throw new Unavailable("revoked tokens");
				return (await stand.records.read(id)) !== undefined;
			},
		})),
	]);
	return { module, place };
}
