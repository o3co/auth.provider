import type { Eraser, SubjectOf, SubjectReading } from "@mod/erasure-extensions";
import { factorsOf, listKeyOf, subjectOf } from "../records/records.ts";
import type { FactorStore, StoredFactors } from "../store.ts";

/** Why a list holding no subject cannot be read, and what to do: a 0.18.0-rc.1 list never rewritten. */
const rcList =
	"a list written by 0.18.0-rc.1 and never rewritten since; rewrite it (mfa-reset of its subject, whose key is `s-<sha256(subject)>`) or accept that erasure stays off";

/** A list's subject: the one it holds, where the list's key is that subject's; else unreadable, never an orphan. */
const listSubject = (key: string, list: StoredFactors | undefined): SubjectOf => {
	const subject = subjectOf(list);
	if (subject === undefined) return { kind: "unreadable", reason: rcList };
	if (listKeyOf(subject) !== key) {
		return { kind: "unreadable", reason: "a list whose subject is not its key's" };
	}
	return { kind: "subject", subject };
};

/** A claim's shape: its list's key and its factor's id, and nothing else. */
const claimOf = (
	value: unknown,
): { readonly listKey: string; readonly factor: string } | undefined => {
	if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
	const { listKey, factor, ...rest } = value as Record<string, unknown>;
	if (typeof listKey !== "string" || typeof factor !== "string" || Object.keys(rest).length > 0) {
		return undefined;
	}
	return { listKey, factor };
};

/**
 * Whose a record of the factor store is, as the migration reads it. A list: the subject it holds,
 * where its key is that subject's. A claim: its list's subject, where that list holds its factor;
 * an orphan where its list, read during the migration's maintenance window (AE §5.1), does not hold
 * its factor, as no provider writes then, so that reading stands until the claim is removed. A
 * claim whose list is gone, a list holding no subject, any other shape, or a read that fails:
 * unreadable.
 */
export const factorSubjectOf =
	(store: Pick<FactorStore, "read">): SubjectReading =>
	async (key, value) => {
		if (key.startsWith("s-")) return listSubject(key, value as StoredFactors);
		const claim = key.startsWith("u-") ? claimOf(value) : undefined;
		if (claim === undefined) return { kind: "unreadable", reason: "a record of another shape" };
		let list: StoredFactors | undefined;
		try {
			list = await store.read(claim.listKey);
		} catch (error) {
			const kind = error instanceof Error ? error.name : typeof error;
			return { kind: "unreadable", reason: `its list could not be read (${kind})` };
		}
		if (list === undefined) return { kind: "unreadable", reason: "a claim whose list is gone" };
		const owner = listSubject(claim.listKey, list);
		if (owner.kind !== "subject") return owner;
		// Its list, read in the window, no longer holds the factor: the claim states something false.
		return factorsOf(list).some((f) => f.id === claim.factor) ? owner : { kind: "orphan" };
	};

/**
 * mfa's eraser, `mfa`, as its space's `erasedBy` names it: a subject's lists and claims erased
 * through the factor store's own ports. `erasable` only where the store offers `erase` and
 * `migrate`; where it does not, empty reports, the field carrying the fact.
 */
export function factorEraser(store: FactorStore): Eraser {
	const { erase, migrate } = store;
	if (!erase || !migrate) {
		const none = { reports: [], logoutGaps: 0 };
		return {
			name: "mfa",
			erasable: false,
			online: async () => none,
			window: async () => none,
			migrate: async () => [],
		};
	}
	const online = async (subject: string, signal: AbortSignal) => ({
		reports: [await erase.call(store, subject, signal)],
		logoutGaps: 0,
	});
	return {
		name: "mfa",
		erasable: true,
		online,
		// Lists and claims are indexed by their subject: no walk reaches more, so a window erases each.
		window: async (subjects, _walk, signal) => {
			const reports = [];
			for (const subject of subjects) reports.push(...(await online(subject, signal)).reports);
			return { reports, logoutGaps: 0 };
		},
		migrate: async (walk, signal) => [
			await migrate.call(store, walk, factorSubjectOf(store), signal),
		],
	};
}
