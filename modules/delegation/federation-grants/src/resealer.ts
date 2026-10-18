import { isUnavailable } from "@mod/kernel";
import type { Resealer } from "@mod/seal";
import type { Grant, Records } from "./grant/grant.ts";
import type { GrantStore } from "./store.ts";

/** Walks every grant, sealing again credentials a past key sealed; ones no key opens are left. */
export function resealerOver(grants: GrantStore, records: Records): Resealer {
	const resealed = (grant: Grant) => {
		try {
			return records.resealed(grant);
		} catch (error) {
			if (!isUnavailable(error)) throw error;
			return undefined;
		}
	};
	return {
		name: "federation-grants",
		reseal: async () => {
			let done = 0;
			let left = 0;
			let cursor: string | undefined;
			do {
				const page = await grants.scan(cursor);
				for (const id of page.keys) {
					const grant = records.grantOf(await grants.read(id));
					if (!grant) continue;
					const next = resealed(grant);
					if (!next) left++;
					if (!next || next === grant) continue;
					const changed = await grants.change(id, (record) =>
						records.grantOf(record)?.sealed === grant.sealed
							? {
									value: records.stored({
										...(records.grantOf(record) as Grant),
										sealed: next.sealed,
									}),
								}
							: undefined,
					);
					if (changed && records.grantOf(changed.after)?.sealed === next.sealed) done++;
				}
				cursor = page.cursor;
			} while (cursor !== undefined);
			return { resealed: done, left };
		},
	};
}
