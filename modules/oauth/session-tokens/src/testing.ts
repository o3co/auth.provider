import { type Clock, defineModule, isUnavailable, Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import {
	type IssuedTokens,
	issuedTokens,
	type PendingSessions,
	pendingSessions,
	type TokenIndex,
	tokenIndex,
} from "./store.ts";

/** A place that keeps the references issued in each session, as one implementation of the store interface offers it. */
export interface IssuedPlace {
	readonly issued: IssuedTokens;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the place can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where memory can run short: it does, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
}

/**
 * What session-tokens needs from any implementation: each reference kept by session for exactly
 * its lifetime, any pushed out answered, through faults.
 */
export function issuedTokensContract(name: string, open: () => Promise<IssuedPlace>): void {
	let n = 0;
	const fresh = () => `s-${++n}-${Math.random().toString(36).slice(2)}`;
	/** The members in code point order, since `members` promises none. */
	const membersOf = async (issued: IssuedTokens, session: string) =>
		[...(await issued.members(session))].sort((a, b) => (a.member < b.member ? -1 : 1));
	const sorted = async (issued: IssuedTokens, session: string) =>
		(await membersOf(issued, session)).map(({ member }) => member);
	describe(`session-tokens' store interface: ${name}`, () => {
		it("keeps each reference for exactly its lifetime, apart by session", async () => {
			const place = await open();
			const [session, other] = [fresh(), fresh()];
			expect((await place.issued.add(session, "a", 1000)).pushedOut).toEqual([]);
			expect((await place.issued.add(session, "b", 3000)).pushedOut).toEqual([]);
			expect(await sorted(place.issued, session)).toEqual(["a", "b"]);
			expect(await place.issued.members(other)).toEqual([]);
			place.advance(400);
			expect(await membersOf(place.issued, session)).toEqual([
				{ member: "a", remainingMs: 600 },
				{ member: "b", remainingMs: 2600 },
			]);
			place.advance(599);
			expect(await sorted(place.issued, session)).toEqual(["a", "b"]);
			place.advance(1);
			expect(await sorted(place.issued, session)).toEqual(["b"]);
		});

		it("answers exactly the references it pushes out to keep within the size it states", async () => {
			const place = await open();
			const session = fresh();
			const { size } = place.issued;
			const added = Array.from({ length: size + 1 }, (_, i) => `r-${i}`);
			for (const reference of added.slice(0, -1)) {
				expect((await place.issued.add(session, reference, 60_000)).pushedOut).toEqual([]);
			}
			const { pushedOut } = await place.issued.add(session, `r-${size}`, 60_000);
			expect(pushedOut).toHaveLength(1);
			expect(pushedOut).not.toContain(`r-${size}`);
			expect([...(await sorted(place.issued, session)), ...pushedOut].sort()).toEqual(added.sort());
			// What it pushed out awaits until settled.
			expect(await place.issued.awaiting(session)).toEqual(pushedOut);
			await place.issued.settled(session, pushedOut[0] as string);
			expect(await place.issued.awaiting(session)).toEqual([]);
		}, 120_000);

		it("keeps references through restarts, memory pressure, lost answers and failovers", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover, restart, pressMemory } = place;
			if (!lose || !failover || !restart || !pressMemory) return context.skip();
			const session = fresh();
			await place.issued.add(session, "kept", 60_000);
			lose();
			expect((await place.issued.add(session, "settled", 60_000)).pushedOut).toEqual([]);
			await failover();
			await restart();
			await pressMemory();
			expect(await sorted(place.issued, session)).toEqual(["kept", "settled"]);
		});
	});
}

/** A place that keeps the token index, as one implementation of the store interface offers it. */
export type IndexPlace = Omit<IssuedPlace, "issued"> & { readonly index: TokenIndex };

/** What session-tokens needs from any implementation of the index: each token's session, once, for exactly its lifetime, through faults. */
export function tokenIndexContract(name: string, open: () => Promise<IndexPlace>): void {
	let n = 0;
	const fresh = () => `t-${++n}-${Math.random().toString(36).slice(2)}`;
	describe(`session-tokens' token index: ${name}`, () => {
		it("keeps the first session saved for a token for exactly its lifetime", async () => {
			const place = await open();
			const [token, other] = [fresh(), fresh()];
			expect(await place.index.save(token, "s-1", 1000)).toBe("created");
			expect(await place.index.save(token, "s-2", 5000)).toBe("exists");
			expect(await place.index.read(token)).toBe("s-1");
			expect(await place.index.read(other)).toBeUndefined();
			place.advance(999);
			expect(await place.index.read(token)).toBe("s-1");
			place.advance(1);
			expect(await place.index.read(token)).toBeUndefined();
		});

		it("keeps entries through restarts, memory pressure, lost answers and failovers", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover, restart, pressMemory } = place;
			if (!lose || !failover || !restart || !pressMemory) return context.skip();
			const [kept, settled] = [fresh(), fresh()];
			await place.index.save(kept, "s-1", 60_000);
			lose();
			expect(await place.index.save(settled, "s-2", 60_000)).toBe("created");
			await failover();
			await restart();
			await pressMemory();
			expect(await place.index.read(kept)).toBe("s-1");
			expect(await place.index.read(settled)).toBe("s-2");
		});
	});
}

/** A place that keeps the pending sessions, as one implementation of the store interface offers it. */
export type PendingPlace = Omit<IssuedPlace, "issued" | "advance"> & {
	readonly list: PendingSessions;
	/** Sessions the place keeps together, and how many it keeps before it refuses. */
	readonly crowd: { readonly limit: number; references(count: number): readonly string[] };
};

/** What session-tokens needs from any implementation of the pending sessions: each kept until done, never pushed out, through faults. */
export function pendingSessionsContract(name: string, open: () => Promise<PendingPlace>): void {
	let n = 0;
	const fresh = () => `p-${++n}-${Math.random().toString(36).slice(2)}`;
	const listed = async (list: PendingSessions) => {
		const found: string[] = [];
		await list.each(async (reference) => {
			found.push(reference);
		});
		return found.sort();
	};
	describe(`session-tokens' pending sessions: ${name}`, () => {
		it("keeps references until done, and one whose handling failed", async () => {
			const { list } = await open();
			const [failing, settled, handled] = [fresh(), fresh(), fresh()];
			for (const reference of [failing, settled, handled]) await list.add(reference);
			const swept = await list.each(async (reference) => {
				if (reference === failing) throw new Error("not yet");
				if (reference === settled) await list.done(reference);
			});
			expect(swept.failed).toBe(1);
			expect(await listed(list)).toEqual([failing, handled].sort());
		});

		it("refuses a reference past a full place without pushing out one it keeps", async () => {
			const { list, crowd } = await open();
			const [over, ...kept] = crowd.references(crowd.limit + 1);
			for (const reference of kept) await list.add(reference);
			expect(isUnavailable(await list.add(over as string).catch((error) => error))).toBe(true);
			expect(await listed(list)).toEqual([...kept].sort());
		}, 60_000);

		it("keeps references through restarts, memory pressure, lost answers and failovers", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover, restart, pressMemory } = place;
			if (!lose || !failover || !restart || !pressMemory) return context.skip();
			const [kept, settled] = [fresh(), fresh()];
			await place.list.add(kept);
			lose();
			await place.list.add(settled);
			lose();
			await place.list.done(settled);
			await failover();
			await restart();
			await pressMemory();
			expect(await listed(place.list)).toEqual([kept]);
		});
	});
}

/**
 * session-tokens' store interfaces in memory on the composition's clock, for a test that composes
 * the real module: it adds `module`. A session keeps `size` references, and the pushed-out list
 * refuses past `listed`.
 */
export function sessionTokensInMemory({ size = 1000, listed = 1000 } = {}) {
	let now = () => 0;
	const sets = new Map<string, Map<string, number>>();
	const waiting = new Map<string, Map<string, number>>();
	const live = (session: string) =>
		[...(sets.get(session) ?? [])].filter(([, ends]) => ends > now());
	const issued = {
		size,
		add: async (session: string, reference: string, lifetimeMs: number) => {
			const kept = new Map(live(session));
			kept.set(reference, Math.max(kept.get(reference) ?? 0, now() + lifetimeMs));
			const byEnd = [...kept].sort((a, b) => a[1] - b[1] || (a[0] < b[0] ? -1 : 1));
			// The reference added stays; the others that end first make room, as records does.
			const over = Math.max(0, byEnd.length - size);
			const out = new Set(
				byEnd
					.filter(([member]) => member !== reference)
					.slice(0, over)
					.map(([member]) => member),
			);
			sets.set(session, new Map(byEnd.filter(([member]) => !out.has(member))));
			const pushed = waiting.get(session) ?? new Map<string, number>();
			for (const member of out) pushed.set(member, kept.get(member) ?? now());
			waiting.set(session, pushed);
			return { pushedOut: [...out] };
		},
		members: async (session: string) =>
			live(session)
				.map(([member, ends]) => ({ member, remainingMs: ends - now() }))
				.sort((a, b) => (a.member < b.member ? -1 : 1)),
		awaiting: async (session: string) =>
			[...(waiting.get(session) ?? [])]
				.filter(([, ends]) => ends > now())
				.map(([member]) => member)
				.sort(),
		settled: async (session: string, reference: string) => {
			waiting.get(session)?.delete(reference);
		},
	} satisfies IssuedTokens;
	const entries = new Map<string, { readonly handle: string; readonly ends: number }>();
	const entry = (tokenId: string) => {
		const found = entries.get(tokenId);
		return found && found.ends > now() ? found : undefined;
	};
	const index: TokenIndex = {
		save: async (tokenId, handle, lifetimeMs) => {
			if (entry(tokenId)) return "exists";
			entries.set(tokenId, { handle, ends: now() + lifetimeMs });
			return "created";
		},
		read: async (tokenId) => entry(tokenId)?.handle,
	};
	const keptUntilDoneIn = () => {
		const jobs = new Set<string>();
		return {
			add: async (job: string) => {
				if (!jobs.has(job) && jobs.size >= listed) throw new Unavailable("session-tokens");
				jobs.add(job);
			},
			done: async (job: string) => {
				jobs.delete(job);
			},
			each: async (handle: (job: string) => Promise<void>) => {
				let failed = 0;
				for (const job of [...jobs]) {
					await handle(job).catch(() => {
						failed++;
					});
				}
				return { failed };
			},
		};
	};
	const pending: PendingSessions = keptUntilDoneIn();
	const on =
		<T>(value: T) =>
		(c: { readonly clock: Clock }) => {
			now = c.clock.now;
			return value;
		};
	const module = defineModule(
		{ name: "session-tokens-stores", replicaSafe: false, takes: [] },
		(m) => [
			m.provide(issuedTokens).by(on(issued)),
			m.provide(tokenIndex).by(on(index)),
			m.provide(pendingSessions).by(on(pending)),
		],
	);
	return { module, issued, index, pending };
}
