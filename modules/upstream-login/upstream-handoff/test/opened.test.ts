import { Unavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import type { Seal } from "@mod/seal";
import type { Session } from "@mod/session";
import type { UpstreamLoginReceiver, UpstreamTokens } from "@mod/upstreams";
import { expect, it } from "vitest";
import { handoffWith } from "../src/handoff.ts";
import type { HeldLoginStore, StoredHeldLogin } from "../src/store.ts";

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
	const kept = new Map<string, StoredHeldLogin>();
	const lifetimes: number[] = [];
	const held: HeldLoginStore = {
		save: async (key, value, lifetimeMs) => {
			if (kept.has(key)) return "exists";
			kept.set(key, value);
			lifetimes.push(lifetimeMs);
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
		held,
		clock: { now: () => now },
		random: { bytes: (n) => new Uint8Array(n).fill(++drawn) },
		log: logged.log,
	});
	/** Holds a login of alice's with `given`, and answers the carry its opening needs. */
	const hold = async (given: UpstreamTokens = tokens) => {
		const kept = handoff.of("corp", "alice", given, 60_000);
		if (!kept) throw new Error("tokens someone receives are held");
		await kept.after({ kind: "held" } as Parameters<typeof kept.after>[0]);
		return kept.carry;
	};
	const at = (ms: number) => {
		now = ms;
	};
	return { handoff, hold, at, received, lifetimes, logged: logged.lines };
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
		{ level: "warn", event: "upstream-handoff.held_login_refused", fields: {} },
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

it("keeps a held login for the lifetime its caller gives, its deadline that far on", async () => {
	const h = holding({ removes: true });
	h.at(5_000);
	const kept = h.handoff.of("corp", "alice", tokens, 90_000);
	if (!kept) throw new Error("tokens someone receives are held");
	expect(kept.deadline).toBe(95_000);
	await kept.after({ kind: "held" } as Parameters<typeof kept.after>[0]);
	expect(h.lifetimes).toEqual([90_000]);
	expect(h.handoff.of("corp", "alice", undefined, 90_000)).toBeUndefined();
});

it("hands nothing when told of a held login it does not keep", async () => {
	const h = holding({ removes: true });
	await h.handoff.opened(session, "unknown-carry");
	expect(h.received).toEqual([]);
});

it("keeps nothing of a login a gate refused, so no opening hands its tokens on", async () => {
	const h = holding();
	const kept = h.handoff.of("corp", "alice", tokens, 60_000);
	if (!kept) throw new Error("tokens someone receives are held");
	await kept.after({ kind: "refused", gate: "policy", cookies: [] });
	await h.handoff.opened(session, kept.carry);
	expect(h.received).toEqual([]);
});
