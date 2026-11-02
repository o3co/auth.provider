import type { Client } from "@mod/clients";
import { recordingLog } from "@mod/kernel/testing";
import { OutboundUnavailable } from "@mod/outbound";
import { expect, it } from "vitest";
import type { PendingNotices } from "../../store.ts";
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
		sessionClients: { members: async () => [] },
		clock: { now: () => now },
		random: { bytes: (length) => new Uint8Array(length) },
		log: recordingLog().log,
		notifyMs,
		retryMs,
	});
	return {
		notices,
		notice,
		made,
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
		await t.notices.deliver([t.notice]);
		expect(t.sent).toEqual([uri]);
		// Kept with the time before which it is not tried, its other fields, those it does not know among them, as they were.
		expect(t.kept()).toEqual([{ ...JSON.parse(t.notice), after: t.made + retryMs }]);
		await t.notices.sweep();
		t.advance(retryMs - 1);
		await t.notices.sweep();
		expect(t.sent).toEqual([uri]);
		t.advance(1);
		await t.notices.sweep();
		expect([t.sent, t.kept()]).toEqual([[uri, uri], []]);
	}
});

it("waits again after each failed try, a sweep's interval after it was last due", async () => {
	const t = noticesFor([unavailable, async () => 429]);
	await t.notices.deliver([t.notice]);
	t.advance(retryMs);
	await t.notices.sweep();
	expect(t.sent).toHaveLength(2);
	expect(t.kept().map((k) => k.after)).toEqual([t.made + 2 * retryMs]);
	t.advance(retryMs - 1);
	await t.notices.sweep();
	expect(t.sent).toHaveLength(2);
	t.advance(1);
	await t.notices.sweep();
	expect([t.sent.length, t.kept()]).toEqual([3, []]);
});

it("keeps one notice where two hosts fail it at once, their clocks apart [oidc-bcl-2.5-a]", async () => {
	const t = noticesFor();
	// Each try fails a few milliseconds after the other, as on two hosts.
	const later = async () => {
		t.advance(7);
		return 503;
	};
	t.answers.push(later, later);
	await Promise.all([t.notices.sweep(), t.notices.sweep()]);
	expect(t.sent).toEqual([uri, uri]);
	expect(t.kept()).toEqual([{ ...JSON.parse(t.notice), after: t.made + retryMs }]);
});

it("tries at once a notice kept before notices waited, and one a late sweep finds past its time, once a sweep until it is due later", async () => {
	const t = noticesFor([unavailable, unavailable]);
	// A notice without a time to wait for, kept by an earlier host, is found by a sweep ten intervals late.
	t.advance(10 * retryMs);
	await t.notices.sweep();
	// The notice kept again is still past its time, and the sweep comes upon it: passed over until the next.
	expect(t.sent).toHaveLength(1);
	// Due a sweep's interval after it was made: already past, so the next sweep tries it.
	expect(t.kept().map((k) => k.after)).toEqual([t.made + retryMs]);
	await t.notices.sweep();
	expect(t.sent).toHaveLength(2);
	expect(t.kept().map((k) => k.after)).toEqual([t.made + 2 * retryMs]);
	await t.notices.sweep();
	expect([t.sent.length, t.kept()]).toEqual([3, []]);
});
