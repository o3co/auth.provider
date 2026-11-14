import type { Client } from "@mod/clients";
import { recordingLog } from "@mod/kernel/testing";
import { OutboundUnavailable } from "@mod/outbound";
import { memoryRecords } from "@mod/records/testing";
import { expect, it } from "vitest";
import { bodyOf, entryOf, idOf, keep } from "../../notice-body/notice-body.ts";
import type { NoticeBodies, PendingNotices } from "../../store.ts";
import { noticesOver } from "../notices.ts";

const retryMs = 60_000;
const notifyMs = 86_400_000;
const uri = "https://app.example/bc";
const unavailable = async () => 503;
const noAnswer = async (): Promise<number> => {
	throw new OutboundUnavailable("timeout");
};

/**
 * The notices over a clock the test moves, a store kept in memory holding one notice made now, and a
 * client answering in turn, then with 200. The store holds a notice once, as every store does, and
 * goes through what it holds as it is then, so a sweep comes upon a notice kept again while it runs,
 * as one that reads another shard later does.
 */
function noticesFor(answers: (() => Promise<number>)[] = []) {
	let now = 1_800_000_000_000;
	const made = now;
	const notice = JSON.stringify({
		client: "app",
		session: "s-1",
		subject: "alice",
		until: made + notifyMs,
		jti: "j-1",
		added: "x",
	});
	const kept = new Set<string>([notice]);
	const pending: PendingNotices = {
		add: async (added) => {
			kept.add(added);
		},
		done: async (settled) => {
			kept.delete(settled);
		},
		each: async (handle) => {
			let failed = 0;
			for (const listed of kept) await handle(listed).catch(() => failed++);
			return { failed };
		},
	};
	// The bodies and their queue in memory.
	const stand = memoryRecords<string>(() => now, { shards: 1, perShard: 100 });
	const bodies: NoticeBodies = {
		create: async (id, body, ms) => stand.records.create(id, body, ms),
		read: stand.records.read,
		remove: stand.records.remove,
	};
	const sent: string[] = [];
	const client: Client = {
		id: "app",
		kind: "confidential",
		method: "client_secret_basic",
		registered: true,
		section: <T>() =>
			({ "backchannel-logout-uri": uri, "backchannel-logout-session-required": true }) as T,
	};
	const notices = noticesOver({
		keys: { sign: async () => "token" },
		outbound: {
			fetch: async (url) => {
				sent.push(url);
				const status = await (answers.shift() ?? (async () => 200))();
				return { status, headers: new Map(), body: new Uint8Array() };
			},
		},
		clients: { find: async () => client },
		issuer: "https://as.example",
		pending,
		bodies,
		queue: stand.deferred,
		sessionClients: { members: async () => [] },
		clock: { now: () => now },
		random: { bytes: (length) => new Uint8Array(length) },
		log: recordingLog().log,
		notifyMs,
		tokenSeconds: 300,
		retryMs,
	});
	const entries = async () => {
		const found: string[] = [];
		await stand.deferred.each(async (x) => void found.push(x));
		return found;
	};
	/** The notice of the 0.19 one, kept as 0.20 keeps it: its body, and the entry naming it. */
	const enter = async () => {
		const { added: _, ...told } = JSON.parse(notice) as Record<string, unknown>;
		await keep({ bodies, queue: stand.deferred }, told as never, now);
		kept.clear();
		return entryOf(idOf(bodyOf(told as never)));
	};
	/** The time each entry waits for. */
	const waits = async () =>
		(await entries()).map((e) => (JSON.parse(e) as { after?: number }).after);
	return {
		notices,
		notice,
		made,
		enter,
		waits,
		bodies,
		queue: stand.deferred,
		entries,
		answers,
		sent,
		kept: () => [...kept].map((k) => JSON.parse(k) as Record<string, unknown>),
		now: () => now,
		advance: (ms: number) => {
			now += ms;
		},
	};
}

it("waits a sweep's interval after a failed try before sending a notice again, whether the client answers it is unavailable or no answer comes [oidc-bcl-2.5-a]", async () => {
	for (const failing of [unavailable, noAnswer]) {
		const t = noticesFor([failing]);
		await t.notices.deliver([await t.enter()]);
		expect(t.sent).toEqual([uri]);
		// Its entry replaced with the time before which it is not tried; the body unchanged.
		expect(await t.waits()).toEqual([t.made + retryMs]);
		t.advance(retryMs - 1);
		await t.notices.sweep();
		expect(t.sent).toEqual([uri]);
		t.advance(1);
		await t.notices.sweep();
		expect([t.sent.length, await t.waits()]).toEqual([2, []]);
	}
});

it("waits again after each failed try, a sweep's interval after it was last due", async () => {
	const t = noticesFor([unavailable, async () => 429]);
	await t.notices.deliver([await t.enter()]);
	t.advance(retryMs);
	await t.notices.sweep();
	expect(t.sent).toHaveLength(2);
	expect(await t.waits()).toEqual([t.made + 2 * retryMs]);
	t.advance(retryMs - 1);
	await t.notices.sweep();
	expect(t.sent).toHaveLength(2);
	t.advance(1);
	await t.notices.sweep();
	expect([t.sent.length, await t.waits()]).toEqual([3, []]);
});

it("delivers one notice twice, with one jti, where two tries come at once, and keeps one entry for it [oidc-bcl-2.5-a]", async () => {
	const t = noticesFor();
	const entry = await t.enter();
	// Each try fails a few milliseconds after the other, as on two hosts.
	const later = async () => {
		t.advance(7);
		return 503;
	};
	t.answers.push(later, later);
	await Promise.all([t.notices.deliver([entry]), t.notices.deliver([entry])]);
	expect(t.sent).toEqual([uri, uri]);
	expect(await t.waits()).toEqual([t.made + retryMs]);
});

it("moves a 0.19 notice whose try failed to a body and an entry, writing nothing to the 0.19 notices", async () => {
	const t = noticesFor([unavailable, unavailable]);
	// A 0.19 notice without a time to wait for, found by a sweep ten intervals late.
	t.advance(10 * retryMs);
	await t.notices.sweep();
	expect([t.sent.length, t.kept()]).toEqual([1, []]);
	// Due a sweep's interval after it was made: already past, so the next sweep tries its entry.
	expect(await t.waits()).toEqual([t.made + retryMs]);
	await t.notices.sweep();
	expect([t.sent.length, await t.waits()]).toEqual([2, [t.made + 2 * retryMs]]);
	await t.notices.sweep();
	expect([t.sent.length, await t.waits(), t.kept()]).toEqual([3, [], []]);
});

it("delivers an entry's notice from its body, then removes the body, then the entry", async () => {
	const t = noticesFor();
	const one = {
		client: "app",
		session: "s-2",
		subject: "alice",
		until: t.now() + 60_000,
		jti: "j-2",
	};
	expect(await keep(t, one, t.now())).toBe("kept");
	await t.notices.sweep();
	expect(t.sent).toEqual([uri, uri]);
	expect([await t.bodies.read(idOf(bodyOf(one))), await t.entries()]).toEqual([undefined, []]);
});

it("does an entry whose body is gone, or does not hash to its id, sending nothing from it", async () => {
	const t = noticesFor();
	const one = { client: "app", session: "s-2", subject: "alice", until: t.now() + 60_000 };
	await t.queue.add(entryOf("no-such-body"));
	await t.bodies.create("not-its-id", bodyOf(one), 60_000, "alice");
	await t.queue.add(entryOf("not-its-id"));
	await t.notices.sweep();
	// The 0.19 notice alone is sent.
	expect(t.sent).toEqual([uri]);
	expect([await t.bodies.read("not-its-id"), await t.entries()]).toEqual([undefined, []]);
});

it("tries each notice kept nowhere once, naming no subject, and throws NoticeUnsent where one would be tried again", async () => {
	const t = noticesFor([unavailable]);
	const one = { client: "app", session: "s-2", subject: "alice", until: t.now() + 60_000 };
	await expect(t.notices.tellOnce([one])).rejects.toMatchObject({
		name: "NoticeUnsent",
		clients: ["app"],
		message: expect.not.stringContaining("alice"),
	});
	await t.notices.tellOnce([one]);
	expect([t.sent.length, await t.entries()]).toEqual([2, []]);
});
