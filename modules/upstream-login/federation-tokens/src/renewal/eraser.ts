import type { Eraser, SubjectReading } from "@mod/erasure-extensions";
import type { Sessions } from "@mod/session";
import type { UpstreamTokenStore } from "../store.ts";
import { portsOf } from "./ports.ts";

/** Whose a record written before indexing is: its session's subject, as the card gives it. */
export const tokensSubjectOf =
	(sessions: Pick<Sessions, "entryOf">): SubjectReading =>
	async (key) => {
		const entry = await sessions.entryOf(key, "none");
		if (entry.kind === "entered")
			return { kind: "subject", subject: entry.session.context.subject };
		return {
			kind: "unreadable",
			reason: "a record whose session no longer enters: it ends with that session; run again then",
		};
	};

/** federation-tokens' eraser, `federation-tokens`, through the store's own ports, as the card gives it. */
export function tokensEraser(
	store: UpstreamTokenStore,
	sessions: Pick<Sessions, "entryOf">,
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
		migrate: async (walk, signal) => [await ports.migrate(walk, tokensSubjectOf(sessions), signal)],
	};
}
