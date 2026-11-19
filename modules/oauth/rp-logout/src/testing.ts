import { describe, expect, it } from "vitest";
import type { z } from "zod";
import type { section } from "./section.ts";
import type { NoticeBodies, NoticeQueue, PendingNotices, SessionClients } from "./store.ts";

export type RpLogoutSettings = z.input<typeof section>;

export function rpLogoutConfig(settings: Partial<RpLogoutSettings> = {}) {
	return { "rp-logout": { ...settings } };
}

/** Faults a place may cause, where it has them. */
interface Faults {
	/** The next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** A replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** It restarts, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Memory runs short, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
}

/** A place that keeps each session's clients, as one implementation of the store interface offers it. */
export interface SessionClientsPlace extends Faults {
	readonly clients: SessionClients;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** How many clients the place keeps to a session. */
	readonly size: number;
}

/** What rp-logout needs from any implementation: each client kept by session for its lifetime, any pushed out answered, through faults. */
export function sessionClientsContract(
	name: string,
	open: () => Promise<SessionClientsPlace>,
): void {
	let n = 0;
	const fresh = () => `s-${++n}-${Math.random().toString(36).slice(2)}`;
	const sorted = async (clients: SessionClients, session: string) =>
		(await clients.members(session)).map(({ member }) => member).sort();
	describe(`rp-logout's session clients: ${name}`, () => {
		it("keeps each client for exactly its lifetime, apart by session", async () => {
			const place = await open();
			const [session, other] = [fresh(), fresh()];
			expect((await place.clients.add(session, "a", 1000)).pushedOut).toEqual([]);
			expect((await place.clients.add(session, "b", 3000)).pushedOut).toEqual([]);
			expect(await place.clients.members(other)).toEqual([]);
			place.advance(999);
			expect(await sorted(place.clients, session)).toEqual(["a", "b"]);
			place.advance(1);
			expect(await sorted(place.clients, session)).toEqual(["b"]);
		});

		it("answers exactly the clients it pushes out to keep within its size", async () => {
			const place = await open();
			const session = fresh();
			const added = Array.from({ length: place.size + 1 }, (_, i) => `c-${i}`);
			for (const client of added.slice(0, -1)) await place.clients.add(session, client, 60_000);
			const { pushedOut } = await place.clients.add(session, `c-${place.size}`, 60_000);
			expect(pushedOut).toHaveLength(1);
			expect([...(await sorted(place.clients, session)), ...pushedOut].sort()).toEqual(
				added.sort(),
			);
		});

		it("keeps clients through restarts, memory pressure, lost answers and failovers", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover, restart, pressMemory } = place;
			if (!lose || !failover || !restart || !pressMemory) return context.skip();
			const session = fresh();
			await place.clients.add(session, "kept", 60_000);
			lose();
			expect((await place.clients.add(session, "settled", 60_000)).pushedOut).toEqual([]);
			await failover();
			await restart();
			await pressMemory();
			expect(await sorted(place.clients, session)).toEqual(["kept", "settled"]);
		});
	});
}

/** A place that keeps the notices not yet delivered, as one implementation of the store interface offers it. */
export interface PendingNoticesPlace extends Faults {
	readonly notices: PendingNotices;
}

/** What rp-logout needs from any implementation of the 0.19 notices: each kept until done, a failed one kept, through faults. */
export function pendingNoticesContract(
	name: string,
	open: () => Promise<PendingNoticesPlace>,
): void {
	listContract("rp-logout's pending notices", name, open);
}

/** A place that keeps the queue of entries, as one implementation of the store interface offers it. */
export interface NoticeQueuePlace extends Faults {
	readonly queue: NoticeQueue;
}

/** What rp-logout needs from any implementation of the queue: each entry kept until done, a failed one kept, through faults. */
export function noticeQueueContract(name: string, open: () => Promise<NoticeQueuePlace>): void {
	listContract("rp-logout's notice queue", name, async () => {
		const { queue, ...faults } = await open();
		return { notices: queue, ...faults };
	});
}

/** The cases a list kept until done answers, the 0.19 notices' or the queue's. */
function listContract(label: string, name: string, open: () => Promise<PendingNoticesPlace>): void {
	let n = 0;
	const fresh = () => `n-${++n}-${Math.random().toString(36).slice(2)}`;
	const listed = async (notices: PendingNotices) => {
		const found: string[] = [];
		await notices.each(async (notice) => {
			found.push(notice);
		});
		return found.sort();
	};
	describe(`${label}: ${name}`, () => {
		it("keeps each notice until done, and one whose handling fails", async () => {
			const place = await open();
			const [kept, settled] = [fresh(), fresh()].sort() as [string, string];
			await place.notices.add(kept);
			await place.notices.add(settled);
			const result = await place.notices.each(async (notice) => {
				if (notice === kept) throw new Error("not now");
				await place.notices.done(notice);
			});
			expect(result).toEqual({ failed: 1 });
			expect(await listed(place.notices)).toEqual([kept]);
		});

		it("keeps notices through restarts, memory pressure, lost answers and failovers", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover, restart, pressMemory } = place;
			if (!lose || !failover || !restart || !pressMemory) return context.skip();
			const [kept, settled] = [fresh(), fresh()].sort() as [string, string];
			await place.notices.add(kept);
			lose();
			await place.notices.add(settled);
			await failover();
			await restart();
			await pressMemory();
			expect(await listed(place.notices)).toEqual([kept, settled]);
		});
	});
}

/** A place that keeps the notices' bodies, as one implementation of the store interface offers it. */
export interface NoticeBodiesPlace extends Faults {
	readonly bodies: NoticeBodies;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
}

/**
 * What rp-logout needs from any implementation of the bodies: each kept once by id for its subject
 * and exactly its lifetime, removed on asking, erased by subject handing each removed over, through
 * faults. Their queue is checked as the pending notices are (`pendingNoticesContract`).
 */
export function noticeBodiesContract(name: string, open: () => Promise<NoticeBodiesPlace>): void {
	let n = 0;
	const fresh = () => `b-${++n}-${Math.random().toString(36).slice(2)}`;
	describe(`rp-logout's notice bodies: ${name}`, () => {
		it("keeps a body once by id, for exactly its lifetime, removed on asking, and through faults", async () => {
			const {
				bodies,
				advance,
				loseNextAnswer: lose,
				failover,
				restart,
				pressMemory,
			} = await open();
			const [id, gone, settled] = [fresh(), fresh(), fresh()];
			expect(await bodies.create(id, "one", 1000, "alice")).toBe("created");
			expect(await bodies.create(id, "two", 1000, "alice")).toBe("exists");
			await bodies.create(gone, "three", 60_000, "alice");
			await bodies.remove(gone);
			advance(999);
			expect([await bodies.read(id), await bodies.read(gone)]).toEqual(["one", undefined]);
			advance(1);
			expect(await bodies.read(id)).toBeUndefined();
			// Where the place has them: a lost answer settles, and the body survives a failover, a
			// restart and memory pressure.
			if (!lose || !failover || !restart || !pressMemory) return;
			lose();
			expect(await bodies.create(settled, "settled", 60_000, "alice")).toBe("created");
			await failover();
			await restart();
			await pressMemory();
			expect(await bodies.read(settled)).toBe("settled");
		});

		it("erases, where the place erases, a subject's bodies, handing each over, and only that subject's", async (context) => {
			const { bodies } = await open();
			const { erase } = bodies;
			if (!erase) return context.skip();
			const [first, kept] = [fresh(), fresh()];
			await bodies.create(first, "erin's", 60_000, "erin");
			await bodies.create(kept, "finn's", 60_000, "finn");
			const removed: string[] = [];
			const report = await erase.call(bodies, "erin", new AbortController().signal, (b) => {
				removed.push(b);
			});
			// A Store that erases nothing now (its records not indexed yet) says so, and fences nothing.
			if (report.kind === "stopped") return context.skip();
			expect([report.kind, removed, await bodies.read(kept)]).toEqual([
				"erased",
				["erin's"],
				"finn's",
			]);
			expect(await bodies.create(fresh(), "again", 60_000, "erin")).toBe("erased");
		});
	});
}
