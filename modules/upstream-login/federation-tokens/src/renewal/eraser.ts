import { type Eraser, ownerStopped, type SubjectReading } from "@mod/erasure-extensions";
import type { Sessions } from "@mod/session";
import type { UpstreamTokenStore } from "../store.ts";
import { portsOf } from "./ports.ts";

/** Whose a record written before indexing is: its session's subject, read through `subjectOf`, as the card gives it. */
export const tokensSubjectOf =
	(subjectOf: (handle: string) => Promise<string | undefined>): SubjectReading =>
	async (key) => {
		const subject = await subjectOf(key);
		if (subject !== undefined) return { kind: "subject", subject };
		return {
			kind: "unreadable",
			reason:
				"a record whose session has no record naming its subject: it ends by its own lifetime; run again then",
		};
	};

/** Where `session` offers no `subjectOf`: no record kept by a session handle can be read, so none is. */
const noSubjectOf = ownerStopped(
	"session offers no subjectOf: records kept by session handle cannot be read; 0.22 requires it",
);

/** federation-tokens' eraser, `federation-tokens`, through the store's own ports, as the card gives it. */
export function tokensEraser(
	store: UpstreamTokenStore,
	sessions: () => Pick<Sessions, "subjectOf">,
): Eraser {
	const ports = portsOf(store);
	if (!ports) {
		const none = { reports: [], logoutGaps: 0 };
		return {
			name: "federation-tokens",
			erasable: false,
			online: async () => none,
			window: async () => none,
			migrate: async () => [],
		};
	}
	const online = async (subject: string, signal: AbortSignal) => ({
		reports: [await ports.erase(subject, signal)],
		logoutGaps: 0,
	});
	return {
		name: "federation-tokens",
		erasable: true,
		online,
		// Records are indexed by their subject: no walk reaches more, so a window erases each subject.
		window: async (subjects, _walk, signal) => {
			const reports = [];
			for (const subject of subjects) reports.push(...(await online(subject, signal)).reports);
			return { reports, logoutGaps: 0 };
		},
		// `session` is read once, at the migration's start.
		migrate: async (walk, signal) => {
			const kept = sessions();
			const { subjectOf } = kept;
			if (!subjectOf) return [noSubjectOf];
			const read = (handle: string) => subjectOf.call(kept, handle);
			return [await ports.migrate(walk, tokensSubjectOf(read), signal)];
		},
	};
}
