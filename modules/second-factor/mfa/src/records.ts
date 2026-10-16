import { createHash } from "node:crypto";
import { Unavailable } from "@mod/kernel";
import type { FactorStore, StoredFactors } from "./store.ts";

export interface Factor {
	readonly id: string;
	readonly kind: string;
	readonly label?: string;
	/** The kind's secret, sealed under the subject and this id. */
	readonly secret: string;
	readonly state: unknown;
	readonly boundAt?: number;
}

export interface Decision<T> {
	readonly next?: readonly Factor[] | undefined;
	readonly verdict: T;
}

interface Claim {
	readonly listKey: string;
	readonly factor: string;
}

const hashOf = (value: string) => createHash("sha256").update(value).digest("base64url");
export const sealContext = (subject: string, factor: string) => `${subject}\n${factor}`;

const factorsOf = (record: StoredFactors | undefined): readonly Factor[] =>
	(record as unknown as { factors: readonly Factor[] } | undefined)?.factors ?? [];
const stored = (factors: readonly Factor[]) => ({ factors }) as unknown as StoredFactors;
const claimOf = (record: StoredFactors | undefined) => record as unknown as Claim | undefined;
const asClaim = (claim: Claim) => claim as unknown as StoredFactors;
const sameClaim = (a: Claim | undefined, b: Claim) =>
	a?.listKey === b.listKey && a.factor === b.factor;

export function factorRecords(store: FactorStore) {
	const keyOf = (subject: string) => `s-${hashOf(subject)}`;
	/** Changes the factors from what they are, or saves a first list when none is held; none leaves them. */
	const change = async (
		subject: string,
		next: (factors: readonly Factor[]) => readonly Factor[] | undefined,
	): Promise<void> => {
		const key = keyOf(subject);
		const changing = (record: StoredFactors) => {
			const after = next(factorsOf(record));
			return after && { value: stored(after) };
		};
		if (await store.update(key, changing)) return;
		const first = next([]);
		if (!first || (await store.save(key, stored(first))) === "created") return;
		// Another request saved one first, yet it cannot be found.
		if (!(await store.update(key, changing))) throw new Unavailable("mfa");
	};
	const claimKey = (kind: string, value: string) => `u-${hashOf(`${kind}\n${value}`)}`;
	/** A factor is written before its claim, so a claim whose list lacks its factor is stale. */
	const holding = async (claim: Claim) =>
		factorsOf(await store.read(claim.listKey)).some((f) => f.id === claim.factor);
	return {
		list: async (subject: string) => factorsOf(await store.read(keyOf(subject))),
		/** Decides on the factors as written; on a race `judge` runs again, and the run written answers. */
		decide: async <T>(
			subject: string,
			judge: (factors: readonly Factor[]) => Decision<T>,
		): Promise<T> => {
			let last: Decision<T> | undefined;
			await change(subject, (factors) => {
				last = judge(factors);
				return last.next;
			});
			return (last as Decision<T>).verdict;
		},
		taken: async (kind: string, value: string) => {
			const held = claimOf(await store.read(claimKey(kind, value)));
			return held !== undefined && (await holding(held));
		},
		/** Claims a kind's unique value for a factor already written; answers whether the factor holds it. */
		claim: async (subject: string, kind: string, value: string, factor: string) => {
			const key = claimKey(kind, value);
			const mine: Claim = { listKey: keyOf(subject), factor };
			if ((await store.save(key, asClaim(mine))) === "created") return true;
			const held = claimOf(await store.read(key));
			if (!held) throw new Unavailable("mfa");
			if (await holding(held)) return false;
			const taken = await store.update(key, (record) =>
				sameClaim(claimOf(record), held) ? { value: asClaim(mine) } : undefined,
			);
			return sameClaim(claimOf(taken?.after), mine);
		},
	};
}
