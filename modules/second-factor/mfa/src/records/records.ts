import { createHash } from "node:crypto";
import { Unavailable } from "@mod/kernel";
import type { FactorStore, StoredFactors } from "../store.ts";

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
	/** Counts the write as a clear of the subject's factors, which no binding begun before survives. */
	readonly clear?: true;
	readonly verdict: T;
}

interface Claim {
	readonly listKey: string;
	readonly factor: string;
}

const hashOf = (value: string) => createHash("sha256").update(value).digest("base64url");
export const sealContext = (subject: string, factor: string) => `${subject}\n${factor}`;

export const factorsOf = (record: StoredFactors | undefined): readonly Factor[] =>
	(record as unknown as { factors: readonly Factor[] } | undefined)?.factors ?? [];
/** A list keeps its subject, so its secrets can be sealed again; none for one written before. */
export const subjectOf = (record: StoredFactors | undefined): string | undefined => {
	const subject = (record as unknown as { subject?: unknown } | undefined)?.subject;
	return typeof subject === "string" ? subject : undefined;
};
/** How many times the subject's factors were cleared; none for a list written before clears were counted. */
export const clearsOf = (record: StoredFactors | undefined): number => {
	const clears = (record as unknown as { clears?: unknown } | undefined)?.clears;
	return typeof clears === "number" && Number.isSafeInteger(clears) && clears > 0 ? clears : 0;
};
export const storedList = (subject: string, factors: readonly Factor[], clears = 0) =>
	({ subject, factors, ...(clears > 0 ? { clears } : {}) }) as unknown as StoredFactors;
export const listKeyOf = (subject: string) => `s-${hashOf(subject)}`;
const claimOf = (record: StoredFactors | undefined) => record as unknown as Claim | undefined;
const asClaim = (claim: Claim) => claim as unknown as StoredFactors;
const sameClaim = (a: Claim | undefined, b: Claim) =>
	a?.listKey === b.listKey && a.factor === b.factor;

export function factorRecords(store: FactorStore) {
	const keyOf = listKeyOf;
	/** Changes the factors from what they are, or saves a first list when none is held; none leaves them. */
	const change = async (
		subject: string,
		next: (
			factors: readonly Factor[],
			clears: number,
		) => { readonly factors: readonly Factor[]; readonly clears: number } | undefined,
	): Promise<void> => {
		const key = keyOf(subject);
		const changing = (record: StoredFactors) => {
			const after = next(factorsOf(record), clearsOf(record));
			return after && { value: storedList(subject, after.factors, after.clears) };
		};
		if (await store.update(key, changing)) return;
		const first = next([], 0);
		if (
			!first ||
			(await store.save(key, storedList(subject, first.factors, first.clears), "endless")) ===
				"created"
		)
			return;
		// Another request saved one first, yet it cannot be found.
		if (!(await store.update(key, changing))) throw new Unavailable("mfa");
	};
	const claimKey = (kind: string, value: string) => `u-${hashOf(`${kind}\n${value}`)}`;
	/** A factor is written before its claim, so a claim whose list lacks its factor is stale. */
	const holding = async (claim: Claim) =>
		factorsOf(await store.read(claim.listKey)).some((f) => f.id === claim.factor);
	return {
		list: async (subject: string) => factorsOf(await store.read(keyOf(subject))),
		/** How many times the subject's factors have been cleared. */
		clears: async (subject: string) => clearsOf(await store.read(keyOf(subject))),
		/** Decides on the factors and clears as written; on a race `judge` runs again, and the run written answers. */
		decide: async <T>(
			subject: string,
			judge: (factors: readonly Factor[], clears: number) => Decision<T>,
		): Promise<T> => {
			let last: Decision<T> | undefined;
			await change(subject, (factors, clears) => {
				last = judge(factors, clears);
				const { next, clear } = last;
				return next && { factors: next, clears: clear ? clears + 1 : clears };
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
			if ((await store.save(key, asClaim(mine), "endless")) === "created") return true;
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
