import type { MigrationReport, SpaceReport } from "@mod/erasure-extensions";
import { defineModule } from "@mod/kernel";
import { memoryRecords } from "@mod/records/testing";
import {
	type NoticeBodies,
	noticeBodies,
	noticeQueue,
	pendingNotices,
	sessionClients,
} from "../src/store.ts";

/** rp-logout's stores on the records stand-in, at most `cap` clients to a session, on the given clock. */
export function memoryStores(now: () => number, cap = 4) {
	const stand = memoryRecords<string>(now, { shards: 4, perShard: 100 });
	const clients = stand.keyedSets(cap);
	const kept = memoryRecords<string>(now, { shards: 4, perShard: 100 });
	/** Subjects erased: no body is created for them, as a Store fencing creation answers. */
	const erased = new Set<string>();
	/** Each body's subject, so an erasure finds a subject's bodies. */
	const owners = new Map<string, string>();
	const bodies: NoticeBodies = {
		create: async (id, body, ms, subject) => {
			if (erased.has(subject)) return "erased";
			const made = await kept.records.create(id, body, ms);
			if (made === "created") owners.set(id, subject);
			return made;
		},
		read: kept.records.read,
		remove: kept.records.remove,
		// In memory, standing in for subject-records' report, which only it makes.
		erase: async (subject, _signal, eachRemoved) => {
			erased.add(subject);
			for (const [id, owner] of owners) {
				const body = owner === subject ? await kept.records.read(id) : undefined;
				if (body === undefined) continue;
				await kept.records.remove(id);
				eachRemoved?.(body);
			}
			return { kind: "erased" } as unknown as SpaceReport;
		},
		migrate: async () =>
			({ kind: "migrated", indexed: 0, removed: 0 }) as unknown as MigrationReport,
	};
	const module = defineModule({ name: "rp-logout-stores", replicaSafe: false, takes: [] }, (m) => [
		m.provide(sessionClients).by(() => clients),
		m.provide(pendingNotices).by(() => stand.deferred),
		m.provide(noticeBodies).by(() => bodies),
		m.provide(noticeQueue).by(() => kept.deferred),
	]);
	return {
		module,
		clients,
		notices: stand.deferred,
		bodies,
		queue: kept.deferred,
		erased,
		size: cap,
	};
}
