import type { Client } from "@mod/clients";
import { recordingLog } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import { expect, it } from "vitest";
import { keep } from "../../notice-body/notice-body.ts";
import type { NoticeBodies, NoticeQueue } from "../../store.ts";
import { noticesOver } from "../notices.ts";

const now = 1_800_000_000_000;
const retryMs = 60_000;

/**
 * A queue going through a live set meets, in the same pass, an entry added while it goes through, as
 * the store's does where a replaced entry hashes into a later shard (Codex's case on #2876, there with
 * 64 shards). records' stand-in goes through a snapshot, so it never shows it.
 */
it("tries each notice once a sweep, a replaced entry met again in the same pass passed over", async () => {
	const random = { bytes: (n: number) => crypto.getRandomValues(new Uint8Array(n)) };
	const log = recordingLog().log;
	const kept = memoryRecords<string>(() => now, { shards: 1, perShard: 100 });
	const listed = new Set<string>();
	const queue: NoticeQueue = {
		add: async (entry) => void listed.add(entry),
		done: async (entry) => void listed.delete(entry),
		each: async (handle) => {
			let failed = 0;
			for (const entry of listed) await handle(entry).catch(() => failed++);
			return { failed };
		},
	};
	const bodies: NoticeBodies = {
		create: async (id, body, ms) => kept.records.create(id, body, ms),
		read: kept.records.read,
		remove: kept.records.remove,
	};
	// Twenty notices, each long overdue after a downtime: a replaced entry is overdue still.
	for (let n = 0; n < 20; n++) {
		const notice = {
			client: "app",
			session: `s-${n}`,
			subject: "alice",
			until: now + 86_400_000,
			jti: `j-${n}`,
		};
		await keep({ bodies, queue }, notice, now, now - 10 * retryMs);
	}
	const sent: string[] = [];
	const client = {
		id: "app",
		kind: "confidential",
		method: "client_secret_basic",
		registered: true,
		section: <T>() => ({ "backchannel-logout-uri": "https://app.example/bc" }) as T,
	} as Client;
	const notices = noticesOver({
		keys: { sign: async () => "token" },
		outbound: {
			fetch: async (url) => {
				sent.push(url);
				return { status: 503, headers: new Map(), body: new Uint8Array() };
			},
		},
		clients: { find: async () => client },
		issuer: "https://as.example",
		pending: memoryRecords<string>(() => now, { shards: 1, perShard: 1 }).deferred,
		bodies,
		queue,
		sessionClients: { members: async () => [] },
		clock: { now: () => now },
		random,
		log,
		notifyMs: 86_400_000,
		tokenSeconds: 300,
		retryMs,
	});
	await notices.sweep();
	expect(sent).toHaveLength(20);
});
