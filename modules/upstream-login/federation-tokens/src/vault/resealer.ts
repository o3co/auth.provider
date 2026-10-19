import { isUnavailable } from "@mod/kernel";
import type { Resealer } from "@mod/seal";
import type { UpstreamTokenStore } from "../store.ts";
import type { Vault } from "./vault.ts";

/** Walks every session's record, sealing again each entry a past key sealed; one no key opens is left. */
export function resealerOver(store: UpstreamTokenStore, vault: Vault): Resealer {
	return {
		name: "federation-tokens",
		reseal: async () => {
			let resealed = 0;
			let left = 0;
			let cursor: string | undefined;
			do {
				const page = await store.scan(cursor);
				for (const session of page.keys) {
					for (const [idp, entry] of Object.entries(vault.entriesOf(await store.read(session)))) {
						let read: ReturnType<Vault["read"]>;
						try {
							read = vault.read(session, idp, entry);
						} catch (error) {
							// The seal is unavailable only for a key the ring no longer holds.
							if (!isUnavailable(error)) throw error;
							read = undefined;
						}
						if (!read) left++;
						const next = read?.resealed;
						if (!next) continue;
						// Written only over the entry read, keeping the record's lifetime.
						const changed = await store.update(session, (record) => {
							const entries = vault.entriesOf(record);
							if (entries[idp]?.sealed !== entry.sealed) return undefined;
							return { value: vault.recordOf({ ...entries, [idp]: next }) };
						});
						if (changed && vault.entriesOf(changed.after)[idp]?.sealed === next.sealed) resealed++;
					}
				}
				cursor = page.cursor;
			} while (cursor !== undefined);
			return { resealed, left };
		},
	};
}
