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
	/** Written with a factor whose kind gives a unique value: it holds that value only through its claim. One written before claims were kept carries none. */
	readonly claims?: true;
}

export interface Decision<T> {
	readonly next?: readonly Factor[] | undefined;
	/** Advances the subject's fence with the write: no binding begun before it binds. */
	readonly fence?: true;
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
/** How far the subject's fence has moved: once per reset and per `fence` asked; 0 for a list written before. */
export const fencesOf = (record: StoredFactors | undefined): number => {
	const fences = (record as unknown as { fences?: unknown } | undefined)?.fences;
	return typeof fences === "number" && Number.isSafeInteger(fences) && fences > 0 ? fences : 0;
};
export const storedList = (subject: string, factors: readonly Factor[], fences = 0) =>
	({ subject, factors, ...(fences > 0 ? { fences } : {}) }) as unknown as StoredFactors;
export const listKeyOf = (subject: string) => `s-${hashOf(subject)}`;
export const claimKeyOf = (kind: string, value: string) => `u-${hashOf(`${kind}\n${value}`)}`;
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
			fences: number,
		) => { readonly factors: readonly Factor[]; readonly fences: number } | undefined,
	): Promise<void> => {
		const key = keyOf(subject);
		const changing = (record: StoredFactors) => {
			const after = next(factorsOf(record), fencesOf(record));
			return after && { value: storedList(subject, after.factors, after.fences) };
		};
		if (await store.update(key, changing)) return;
		const first = next([], 0);
		if (
			!first ||
			(await store.save(key, storedList(subject, first.factors, first.fences), "endless")) ===
				"created"
		)
			return;
		// Another request saved one first, yet it cannot be found.
		if (!(await store.update(key, changing))) throw new Unavailable("mfa");
	};
	const claimKey = claimKeyOf;
	/** A claim whose list lacks its factor is stale: the factor was removed since. */
	const holding = async (claim: Claim) =>
		factorsOf(await store.read(claim.listKey)).some((f) => f.id === claim.factor);
	return {
		list: async (subject: string) => factorsOf(await store.read(keyOf(subject))),
		/** Moves the subject's fence, writing a list even where none is held. */
		fence: (subject: string) =>
			change(subject, (factors, fences) => ({ factors, fences: fences + 1 })),
		/** How far the subject's fence has moved. */
		fences: async (subject: string) => fencesOf(await store.read(keyOf(subject))),
		/** Decides on the factors and the fence as written; on a race `judge` runs again, and the run written answers. */
		decide: async <T>(
			subject: string,
			judge: (factors: readonly Factor[], fences: number) => Decision<T>,
		): Promise<T> => {
			let last: Decision<T> | undefined;
			await change(subject, (factors, fences) => {
				last = judge(factors, fences);
				const { next, fence } = last;
				return next && { factors: next, fences: fence ? fences + 1 : fences };
			});
			return (last as Decision<T>).verdict;
		},
		taken: async (kind: string, value: string) => {
			const held = claimOf(await store.read(claimKey(kind, value)));
			return held !== undefined && (await holding(held));
		},
		/** Whether the kind's unique value is claimed for `factor` of the subject. */
		claimedFor: async (subject: string, kind: string, value: string, factor: string) =>
			sameClaim(claimOf(await store.read(claimKey(kind, value))), {
				listKey: keyOf(subject),
				factor,
			}),
		/** Whether a factor other than `factor` holds the kind's unique value: a binding of it ends as a duplicate. */
		heldByAnother: async (subject: string, kind: string, value: string, factor: string) => {
			const held = claimOf(await store.read(claimKey(kind, value)));
			if (held === undefined || sameClaim(held, { listKey: keyOf(subject), factor })) return false;
			return holding(held);
		},
		/**
		 * Decides on the factors as `decide` does, and writes the list with the claim on the kind's unique
		 * value for `factor` in the same write, where the place writes them together: `duplicate` where
		 * another factor holds the value (its claim's list lists it), and a claim whose factor is gone is
		 * taken. The judge answers first, so a write it refuses answers as it does.
		 */
		decideClaiming: async <T>(
			subject: string,
			claimed: { readonly kind: string; readonly value: string; readonly factor: string },
			judge: (factors: readonly Factor[], fences: number) => Decision<T>,
		): Promise<T | "duplicate"> => {
			const mine: Claim = { listKey: keyOf(subject), factor: claimed.factor };
			let last: Decision<T> | "duplicate" | undefined;
			await store.updateTogether(keyOf(subject), claimKey(claimed.kind, claimed.value), {
				// The claim's own list tells whether it still holds the value.
				watch: (_list, claim) => {
					const held = claimOf(claim);
					return held ? [held.listKey] : [];
				},
				change: (list, claim, [holder]) => {
					const decision = judge(factorsOf(list), fencesOf(list));
					last = decision;
					if (!decision.next) return {};
					const held = claimOf(claim);
					if (held && factorsOf(holder).some((f) => f.id === held.factor)) {
						last = "duplicate";
						return {};
					}
					const fences = fencesOf(list) + (decision.fence ? 1 : 0);
					return {
						list: { value: storedList(subject, decision.next, fences) },
						claim: { value: asClaim(mine) },
					};
				},
			});
			return last === "duplicate" ? "duplicate" : (last as Decision<T>).verdict;
		},
	};
}
