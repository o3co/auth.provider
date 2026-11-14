import {
	type Eraser,
	type MigrationReport,
	type OwnerStopped,
	ownerStopped,
	type SubjectReading,
} from "@mod/erasure-extensions";
import type { Clock, Log } from "@mod/kernel";
import { bodyRead, move, pendingOf } from "../notice-body/notice-body.ts";
import type { NoticeBodies, NoticeQueue, PendingNotices } from "../store.ts";
import { portsOf } from "./ports.ts";

/** The places rp-logout keeps a subject's notices in, the 0.19 notices among them until drained. */
export interface NoticeStores {
	readonly bodies: NoticeBodies;
	readonly queue: NoticeQueue;
	readonly pending: PendingNotices;
}

/** Whose a body written before indexing is: the subject it names, where it reads and hashes to its id. */
const bodySubjectOf: SubjectReading = async (key, value) => {
	const told = typeof value === "string" ? bodyRead(key, value) : undefined;
	return told && told !== "newer"
		? { kind: "subject", subject: told.subject }
		: { kind: "unreadable", reason: "a notice body of another shape or format, or not its id's" };
};

/**
 * rp-logout's eraser, `rp-logout`, as its bodies' space's `erasedBy` names it: a subject's bodies
 * erased through the store's own ports, each removed counted by its session; and, once, the 0.19
 * notices drained into bodies. `erasable` only where the bodies offer both ports.
 */
export function noticesEraser(stores: NoticeStores, log: Log, clock: Clock): Eraser {
	const ports = portsOf(stores.bodies);
	if (!ports) {
		const none = { reports: [], logoutGaps: 0 };
		return {
			name: "rp-logout",
			erasable: false,
			online: async () => none,
			window: async () => none,
			migrate: async () => [],
		};
	}
	const online = async (subject: string, signal: AbortSignal) => {
		const sessions = new Set<string>();
		let unread = 0;
		const report = await ports.erase(subject, signal, (body) => {
			// Removed by its own id: its session read as it stands, a body of a newer format too.
			const session = pendingOf(body)?.session;
			if (session !== undefined) sessions.add(session);
			else unread += 1;
		});
		return { reports: [report], logoutGaps: sessions.size + unread };
	};
	/** Moves each 0.19 notice to a body and an entry; why it did not finish, or none. TODO(0.22): goes. */
	const drained = async (signal: AbortSignal): Promise<string | undefined> => {
		try {
			const { failed } = await stores.pending.each(async (notice) => {
				if (signal.aborted) throw new Error("aborted");
				await move(stores, notice, log, clock.now());
			});
			if (signal.aborted) return "aborted";
			if (failed > 0) return `${failed} 0.19 notices not moved yet; run again`;
			return undefined;
		} catch (error) {
			return `the 0.19 notices could not be gone through (${error instanceof Error ? error.name : typeof error}); run again`;
		}
	};
	return {
		name: "rp-logout",
		erasable: true,
		online,
		// The bodies are indexed by their subject: no walk reaches more, so a window erases each subject.
		window: async (subjects, _walk, signal) => {
			const reports = [];
			let logoutGaps = 0;
			for (const subject of subjects) {
				const erased = await online(subject, signal);
				reports.push(...erased.reports);
				logoutGaps += erased.logoutGaps;
			}
			return { reports, logoutGaps };
		},
		migrate: async (walk, signal) => {
			// The drain first, so the bodies it keeps are migrated; the bodies' migrate runs either way.
			const stop = await drained(signal);
			const bodies = await ports.migrate(walk, bodySubjectOf, signal);
			const answers: (MigrationReport | OwnerStopped)[] = [bodies];
			if (stop) answers.push(ownerStopped(stop));
			return answers;
		},
	};
}
