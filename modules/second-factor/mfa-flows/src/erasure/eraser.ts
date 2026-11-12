import {
	type Eraser,
	ownerStopped,
	type SetReading,
	type SubjectReading,
} from "@mod/erasure-extensions";
import type { Sessions } from "@mod/session";
import type { TransactionListings, TransactionStore } from "../store.ts";
import { portsOf } from "./ports.ts";

/** The transactions' reading, never asked: a bounded space has nothing to index. */
const transactionsUnread: SubjectReading = async () => ({
	kind: "unreadable",
	reason: "a bounded space's record is never read",
});

/**
 * Whose a raw listing is, from its key alone: `login:<subject>` that subject's; `session:<handle>`
 * its session's subject, read through `subjectOf`; anything else, or a session with no record
 * naming its subject, unreadable, as a confirmed "none" proves nothing of the listing.
 */
export const listingSubjectOf =
	(subjectOf: (handle: string) => Promise<string | undefined>): SetReading =>
	async (key) => {
		const [form, ...rest] = key.split(":");
		const named = rest.join(":");
		if (form === "login" && named !== "") return { kind: "subject", subject: named };
		if (form !== "session" || named === "") {
			return { kind: "unreadable", reason: "a listing keyed in no form mfa-flows writes" };
		}
		const subject = await subjectOf(named);
		if (subject !== undefined) return { kind: "subject", subject };
		return {
			kind: "unreadable",
			reason:
				"a listing whose session has no record naming its subject: it ends with its transactions, within 30 min; run again then",
		};
	};

/** Where `session` offers no `subjectOf`: no listing kept by session handle can be read, so none is. */
const noSubjectOf = ownerStopped(
	"session offers no subjectOf: listings kept by session handle cannot be read; 0.22 requires it",
);

/**
 * mfa-flows' eraser, `mfa-flows`, as its spaces' `erasedBy` names it: a subject's transactions fenced
 * and its listings erased through the stores' own ports. `erasable` only where the stores offer their
 * ports whole; where they do not, empty reports, the field carrying the fact.
 */
export function flowsEraser(
	store: TransactionStore,
	listings: TransactionListings,
	sessions: () => Pick<Sessions, "subjectOf">,
): Eraser {
	const ports = portsOf(store, listings);
	if (!ports) {
		const none = { reports: [], logoutGaps: 0 };
		return {
			name: "mfa-flows",
			erasable: false,
			online: async () => none,
			window: async () => none,
			migrate: async () => [],
		};
	}
	const online = async (subject: string, signal: AbortSignal) => ({
		reports: [await ports.erase(subject, signal), await ports.eraseListings(subject, signal)],
		logoutGaps: 0,
	});
	return {
		name: "mfa-flows",
		erasable: true,
		online,
		// Transactions are fenced by their subject, listings indexed by it: no walk reaches more.
		window: async (subjects, _walk, signal) => {
			const reports = [];
			for (const subject of subjects) reports.push(...(await online(subject, signal)).reports);
			return { reports, logoutGaps: 0 };
		},
		// `session` is read once, at the migration's start; the transactions migrate without it.
		migrate: async (walk, signal) => {
			const transactions = await ports.migrate(walk, transactionsUnread, signal);
			const kept = sessions();
			const { subjectOf } = kept;
			if (!subjectOf) return [transactions, noSubjectOf];
			const read = (handle: string) => subjectOf.call(kept, handle);
			return [transactions, await ports.migrateListings(walk, listingSubjectOf(read), signal)];
		},
	};
}
