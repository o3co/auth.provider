import { isUnavailable } from "@mod/kernel";
import type { Resealer, Seal } from "@mod/seal";
import type { FactorStore } from "../store.ts";
import {
	type Factor,
	factorsOf,
	fencesOf,
	listKeyOf,
	sealContext,
	storedList,
	subjectOf,
} from "./records.ts";

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
	/** One factor of a list sealed again: `done` where the store took it, `left` where no key opens it, `same` otherwise. */
	const resealFactor = async (
		key: string,
		subject: string,
		factor: Factor,
	): Promise<"done" | "left" | "same"> => {
		const next = resealed(subject, factor.id, factor.secret);
		if (next === undefined) return "left";
		if (next === factor.secret) return "same";
		const changed = await store.update(key, (current) => {
			const all = factorsOf(current);
			if (all.find((f) => f.id === factor.id)?.secret !== factor.secret) return undefined;
			const moved = all.map((f) => (f.id === factor.id ? { ...f, secret: next } : f));
			return { value: storedList(subject, moved, fencesOf(current)) };
		});
		const after = changed && factorsOf(changed.after).find((f) => f.id === factor.id);
		return after?.secret === next ? "done" : "same";
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
						const outcome = await resealFactor(key, subject, factor);
						if (outcome === "done") done++;
						if (outcome === "left") left++;
					}
				}
				cursor = page.cursor;
			} while (cursor !== undefined);
			return { resealed: done, left };
		},
	};
}
