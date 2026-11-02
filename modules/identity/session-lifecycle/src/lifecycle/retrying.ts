import type { Clock, Log } from "@mod/kernel";
import type { SessionStore } from "../store.ts";
import { fromStored, type SessionRecord, toStored } from "./record.ts";

const maxRetryMs = 3_600_000;

type ClosingRecord = Extract<SessionRecord, { state: "closing" }>;

/** When closings that failed are tried again: in their record, or by this host for one it cannot read. */
export function retryingWith(parts: {
	readonly kept: SessionStore;
	readonly clock: Clock;
	readonly log: Log;
	readonly sweepMs: number;
}) {
	const { kept, clock, log, sweepMs } = parts;
	/** When this host may next sweep a closing whose record it cannot read, and since when it failed. */
	const unread = new Map<string, { readonly since: number; readonly retryAt: number }>();
	/** When to retry a closing that failed: after half its age, from the sweep interval up to an hour. Logged. */
	const retryOf = (handle: string, since: number | undefined) => {
		const at = clock.now();
		const from = since ?? at;
		log.warn("session-lifecycle.closing_pending", {
			handle,
			ageSeconds: Math.round((at - from) / 1000),
		});
		return { since: from, retryAt: at + Math.min(maxRetryMs, Math.max(sweepMs, (at - from) / 2)) };
	};
	return {
		/** Puts off a closing whose record this cannot read: the record is left as it is, so only this host knows. */
		putOffUnread: (handle: string) => {
			unread.set(handle, retryOf(handle, unread.get(handle)?.since));
		},
		/** Puts off a closing whose participants failed, in its record. */
		putOff: async (handle: string, record: ClosingRecord) => {
			const { retryAt } = retryOf(handle, record.closingSince);
			await kept.update(handle, (stored) => {
				// Only a closing waits for a retry: one closed meanwhile, or its mark, is left as it is.
				const was = fromStored(stored);
				return was?.state === "closing" ? { value: toStored({ ...was, retryAt }) } : undefined;
			});
		},
		/** When a kept closing is next due: its record's retry time, or this host's for one it cannot read. */
		dueOf: (handle: string, record: SessionRecord | undefined) =>
			(record ? ("retryAt" in record ? record.retryAt : undefined) : unread.get(handle)?.retryAt) ??
			0,
		/** Forgets the closings no longer kept, finished here or by another host. */
		keepOnly: (seen: ReadonlySet<string>) => {
			for (const handle of unread.keys()) if (!seen.has(handle)) unread.delete(handle);
		},
	};
}
