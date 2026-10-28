import { defineModule, Unavailable } from "@mod/kernel";
import { memoryRecords } from "@mod/records/testing";
import { revokedTokens } from "@mod/token-denylist";

/** Revoked tokens kept in memory, on a place clock that may run apart from the composition's, and that can stop answering; it keeps what it was asked. */
export function revokedInMemory(now: () => number) {
	const place = { shift: 0, down: false, asked: [] as [string, ...unknown[]][] };
	const stand = memoryRecords<true>(() => now() + place.shift, { shards: 1, perShard: 1 });
	const module = defineModule({ name: "revoked-tokens", replicaSafe: false, takes: [] }, (m) => [
		m.provide(revokedTokens).by(() => ({
			save: async (id: string, lifetimeMs: number) => {
				place.asked.push(["save", id, lifetimeMs]);
				if (place.down) throw new Unavailable("revoked tokens");
				return stand.records.create(id, true, lifetimeMs);
			},
			holds: async (id: string) => {
				place.asked.push(["holds", id]);
				if (place.down) throw new Unavailable("revoked tokens");
				return (await stand.records.read(id)) !== undefined;
			},
		})),
	]);
	return { module, place };
}
