import type { Eraser, SubjectOf, SubjectReading } from "@mod/erasure-extensions";
import { listKeyOf, recordKindOf, strictClaimOf, strictListOf } from "../records/records.ts";
import type { FactorStore } from "../store.ts";

/**
 * Why a list holding no subject cannot be read, and what to do: one 0.18.0-rc.1 wrote and nothing
 * has rewritten since. Its key is named, a hash the operator matches against their subjects' keys.
 */
const rcList = (key: string) =>
	`the list ${key} was written by 0.18.0-rc.1 and never rewritten since, so it holds no subject (its key is s- and the base64url SHA-256 of the subject); the subject's next proof or change of a factor rewrites it with its subject, mfa-reset of the subject rewrites it by clearing its factors (to be bound again), or accept that erasure stays off`;

/**
 * A list's subject, read strictly: the one it holds, where its key is that subject's. One of
 * another shape is malformed; a list holding no subject, otherwise a list, is rc.1's. Unreadable
 * either way, never an orphan.
 */
const listSubject = (key: string, value: unknown): SubjectOf => {
	const list = strictListOf(value);
	if (list === undefined)
		return { kind: "unreadable", reason: "a list of another shape (malformed)" };
	if (list.subject === undefined) return { kind: "unreadable", reason: rcList(key) };
	if (listKeyOf(list.subject) !== key) {
		return { kind: "unreadable", reason: "a list whose subject is not its key's" };
	}
	return { kind: "subject", subject: list.subject };
};

/**
 * Whose a record of the factor store is, as the migration reads it. A list: the subject it holds,
 * where its key is that subject's. A claim: its list's subject, where that list holds its factor;
 * an orphan where its list, read during the migration's maintenance window (AE §5.1), does not hold
 * its factor, as no provider writes then, so that reading stands until the claim is removed. A
 * claim whose list is gone or malformed, a list holding no subject, any other shape, or a read
 * that fails: unreadable.
 */
export const factorSubjectOf =
	(store: Pick<FactorStore, "read">): SubjectReading =>
	async (key, value) => {
		const kind = recordKindOf(key);
		if (kind === "list") return listSubject(key, value);
		const claim = kind === "claim" ? strictClaimOf(value) : undefined;
		if (claim === undefined) return { kind: "unreadable", reason: "a record of another shape" };
		let held: unknown;
		try {
			held = await store.read(claim.listKey);
		} catch (error) {
			const name = error instanceof Error ? error.name : typeof error;
			return { kind: "unreadable", reason: `its list could not be read (${name})` };
		}
		if (held === undefined) return { kind: "unreadable", reason: "a claim whose list is gone" };
		const owner = listSubject(claim.listKey, held);
		if (owner.kind !== "subject") return owner;
		const list = strictListOf(held);
		// Its list, read in the window, no longer holds the factor: the claim states something false.
		return list?.factors.some((f) => f.id === claim.factor) ? owner : { kind: "orphan" };
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
