import { Unavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import type { Seal } from "@mod/seal";
import type { Session } from "@mod/session";
import type { UpstreamLoginReceiver, UpstreamTokens } from "@mod/upstreams";
import { expect, it } from "vitest";
import type { StoredTransaction, TransactionStore } from "../../store.ts";
import { handoffWith } from "../handoff.ts";

const sessionOf = (subject: string): Session => ({
	id: "s1",
	context: { subject, amr: ["pwd"], authenticatedAt: 0 },
});
const session = sessionOf("alice");
const tokens = { accessToken: "up-1", tokenType: "Bearer", scope: [] };

/** How the test's store behaves: whether its removals and its changes go through. */
interface Store {
	readonly removes?: boolean;
	readonly changes?: boolean;
}

/** A handoff over one receiver, on a store whose removal of a held login's record fails unless `removes`. */
function holding({ removes = false, changes = true }: Store = {}) {
	let now = 0;
	let drawn = 0;
	const logged = recordingLog();
	const kept = new Map<string, StoredTransaction>();
	const transactions: TransactionStore = {
		save: async (key, value) => {
			if (kept.has(key)) return "exists";
			kept.set(key, value);
			return "created";
		},
		update: async (key, change) => {
			const before = kept.get(key);
			if (before === undefined) return undefined;
			const changed = change(before);
			if (!changed || !changes) return { before, after: before };
			kept.set(key, changed.value);
			return { before, after: changed.value };
		},
		remove: async (key) => {
			if (!removes) throw new Unavailable("store");
			kept.delete(key);
		},
	};
	const received: UpstreamTokens[] = [];
	const receiver: UpstreamLoginReceiver = {
		name: "one",
		received: async (at) => void received.push(at.tokens),
		withdrawn: async () => {},
	};
	const seal = {
		seal: (plain: string, context: string) => `${context}|${plain}`,
		open: (sealed: string, context: string) =>
			sealed.startsWith(`${context}|`)
				? { kind: "opened", plain: sealed.slice(context.length + 1) }
				: { kind: "refused" },
	} as unknown as Seal;
	const handoff = handoffWith({
		receivers: [receiver],
		seal,
		transactions,
		clock: { now: () => now },
		random: { bytes: (n) => new Uint8Array(n).fill(++drawn) },
		log: logged.log,
		lifetimeMs: 60_000,
	});
	/** Holds a login of alice's with `given`, and answers the carry its opening needs. */
	const hold = async (given: UpstreamTokens = tokens) => {
		const held = handoff.of("corp", "alice", given);
		if (!held) throw new Error("tokens someone receives are held");
		await held.after({ kind: "held" } as Parameters<typeof held.after>[0]);
		return held.from.carry;
	};
	const at = (ms: number) => {
		now = ms;
	};
	return { handoff, hold, at, received, logged: logged.lines };
}

it("hands a held login's tokens only once, even where its record cannot be removed after", async () => {
	const h = holding();
	const carry = await h.hold();
	// The removal fails, and the failure is told, never read as the record being gone.
	await expect(h.handoff.opened(session, carry)).rejects.toThrow();
	// The record it could not remove stays taken, so a second opening hands nothing.
	await h.handoff.opened(session, carry);
	expect(h.received).toEqual([tokens]);
});

it("hands nothing where the store did not take the record", async () => {
	const h = holding({ removes: true, changes: false });
	await h.handoff.opened(session, await h.hold());
	expect(h.received).toEqual([]);
});

it("hands nothing to a session of another subject, and warns", async () => {
	const h = holding({ removes: true });
	await h.handoff.opened(sessionOf("bob"), await h.hold());
	expect(h.received).toEqual([]);
	expect(h.logged()).toEqual([
		{ level: "warn", event: "federation.held_login_refused", fields: {} },
	]);
});

it("takes the whole seconds since the hold off the tokens' lifetime, to no less than none", async () => {
	const h = holding({ removes: true });
	const lifetimeAfter = async (heldAt: number, openedAt: number, expiresInSeconds = 100) => {
		h.at(heldAt);
		const carry = await h.hold({ ...tokens, expiresInSeconds });
		h.at(openedAt);
		await h.handoff.opened(session, carry);
		return h.received.at(-1)?.expiresInSeconds;
	};
	expect(await lifetimeAfter(0, 30_500)).toBe(69);
	expect(await lifetimeAfter(0, 59_000, 30)).toBe(0);
	expect(await lifetimeAfter(0, 0)).toBe(100);
	// A clock that went back spends nothing.
	expect(await lifetimeAfter(10_000, 0)).toBe(100);
});
