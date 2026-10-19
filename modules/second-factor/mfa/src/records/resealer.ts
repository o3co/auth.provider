import { isUnavailable } from "@mod/kernel";
import type { Resealer, Seal } from "@mod/seal";
import type { FactorStore } from "../store.ts";
import { clearsOf, factorsOf, listKeyOf, sealContext, storedList, subjectOf } from "./records.ts";

/** Walks every factor list, sealing again secrets a past key sealed; ones it cannot open are left. */
export function resealerOver(store: FactorStore, seal: Seal): Resealer {
	/** The secret resealed, the same when current, or none when no key opens it (a key gone, too). */
	const resealed = (subject: string, id: string, secret: string) => {
		try {
			const read = seal.open(secret, sealContext(subject, id));
			if (read.kind !== "opened") return undefined;
			return read.stale ? seal.seal(read.plain, sealContext(subject, id)) : secret;
		} catch (error) {
			if (!isUnavailable(error)) throw error;
			return undefined;
		}
	};
	return {
		name: "mfa",
		reseal: async () => {
			let done = 0;
			let left = 0;
			let cursor: string | undefined;
			do {
				const page = await store.scan(cursor);
				// Claims share the store; only lists hold secrets.
				for (const key of page.keys.filter((k) => k.startsWith("s-"))) {
					const record = await store.read(key);
					const subject = subjectOf(record);
					const factors = factorsOf(record);
					if (subject === undefined || listKeyOf(subject) !== key) {
						left += factors.length;
						continue;
					}
					for (const factor of factors) {
						const next = resealed(subject, factor.id, factor.secret);
						if (next === undefined) left++;
						if (next === undefined || next === factor.secret) continue;
						const changed = await store.update(key, (current) => {
							const all = factorsOf(current);
							if (all.find((f) => f.id === factor.id)?.secret !== factor.secret) return undefined;
							const moved = all.map((f) => (f.id === factor.id ? { ...f, secret: next } : f));
							return { value: storedList(subject, moved, clearsOf(current)) };
						});
						const after = changed && factorsOf(changed.after).find((f) => f.id === factor.id);
						if (after?.secret === next) done++;
					}
				}
				cursor = page.cursor;
			} while (cursor !== undefined);
			return { resealed: done, left };
		},
	};
}
