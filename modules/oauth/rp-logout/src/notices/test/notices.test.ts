import type { Client } from "@mod/clients";
import { recordingLog } from "@mod/kernel/testing";
import { OutboundUnavailable } from "@mod/outbound";
import { expect, it } from "vitest";
import type { PendingNotices } from "../../store.ts";
import { noticesOver } from "../notices.ts";

const retryMs = 60_000;
const uri = "https://app.example/bc";

/** The notices over a clock the test moves, a store kept in memory and a client answering in turn. */
function noticesFor(answers: (() => Promise<number>)[]) {
	let now = 1_800_000_000_000;
	const kept = new Set<string>();
	const pending: PendingNotices = {
		add: async (notice) => {
			kept.add(notice);
		},
		done: async (notice) => {
			kept.delete(notice);
		},
		each: async (handle) => {
			let failed = 0;
			for (const notice of [...kept]) await handle(notice).catch(() => failed++);
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
		notifyMs: 86_400_000,
		retryMs,
	});
	const notice = JSON.stringify({
		client: "app",
		session: "s-1",
		subject: "alice",
		until: now + 86_400_000,
		jti: "j-1",
		added: "x",
	});
	return {
		notices,
		notice,
		sent,
		kept: () => [...kept].map((k) => JSON.parse(k) as Record<string, unknown>),
		now: () => now,
		advance: (ms: number) => {
			now += ms;
		},
	};
}

it.each([
	["the client answers it is unavailable", async () => 503],
	[
		"no answer comes",
		async (): Promise<number> => {
			throw new OutboundUnavailable("timeout");
		},
	],
])(
	"waits a sweep's interval after a failed try before sending a notice again, where %s [oidc-bcl-2.5-a]",
	async (_name, failing) => {
		const t = noticesFor([failing]);
		await t.notices.deliver([t.notice]);
		const failedAt = t.now();
		expect(t.sent).toEqual([uri]);
		// Kept with the time before which it is not tried, its other fields, those it does not know among them, as they were.
		expect(t.kept()).toEqual([{ ...JSON.parse(t.notice), after: failedAt + retryMs }]);
		await t.notices.sweep();
		t.advance(retryMs - 1);
		await t.notices.sweep();
		expect(t.sent).toEqual([uri]);
		t.advance(1);
		await t.notices.sweep();
		expect([t.sent, t.kept()]).toEqual([[uri, uri], []]);
	},
);

it("waits again after each failed try, counting from that try", async () => {
	const t = noticesFor([async () => 503, async () => 429]);
	await t.notices.deliver([t.notice]);
	t.advance(retryMs);
	await t.notices.sweep();
	expect(t.sent).toHaveLength(2);
	expect(t.kept().map((k) => k.after)).toEqual([t.now() + retryMs]);
	t.advance(retryMs - 1);
	await t.notices.sweep();
	expect(t.sent).toHaveLength(2);
	t.advance(1);
	await t.notices.sweep();
	expect([t.sent.length, t.kept()]).toEqual([3, []]);
});
