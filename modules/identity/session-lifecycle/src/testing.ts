import { isUnavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { z } from "zod";
import type { section } from "./section.ts";
import type {
	ClosingList,
	CookieIndex,
	SessionStore,
	StoredSession,
	SubjectSessions,
} from "./store.ts";

export type SessionLifecycleSettings = z.input<typeof section>;

export function sessionLifecycleConfig(settings: Partial<SessionLifecycleSettings> = {}) {
	return { "session-lifecycle": { ...settings } };
}

/** A place that keeps session-lifecycle's records, cookies and closings, as one implementation of its store interfaces offers it. */
export interface SessionStorePlace {
	readonly sessions: SessionStore;
	readonly cookies: CookieIndex;
	readonly closings: ClosingList;
	readonly subjects: SubjectSessions;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Before the next update of `handle` writes, another writer changes its record as given. */
	raceNextUpdate(handle: string, change: (record: StoredSession) => StoredSession): void;
	/** Handles the closings keep together, and how many it keeps before it refuses. */
	readonly crowd: { readonly limit: number; handles(count: number): readonly string[] };
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the place can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where memory can run short: it does, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
	/** Where what the place was given can be searched: whether any of it carried `text`. */
	readonly holds?: (text: string) => boolean;
}

/**
 * What session-lifecycle needs from any implementation of its store interfaces: records kept whole and
 * once, changed only from what they hold, ended at exactly their lifetime or never; cookies that
 * stay removed; closings kept until done, through lost answers and failovers, never pushed out.
 */
export function sessionStoreContract(name: string, open: () => Promise<SessionStorePlace>): void {
	let n = 0;
	const fresh = () => `s-${++n}-${Math.random().toString(36).slice(2)}`;
	const held = (value: object) => value as unknown as StoredSession;
	const counted = (record: StoredSession) => (record as unknown as { n: number }).n;
	const plus = (by: number) => (record: StoredSession) => ({
		value: held({ n: counted(record) + by }),
	});
	const closingsIn = async (closings: ClosingList) => {
		const found: string[] = [];
		await closings.each(async (handle) => {
			found.push(handle);
		});
		return found.sort();
	};

	describe(`session-lifecycle's store interfaces: ${name}`, () => {
		it("keeps a record whole and once per handle, whatever it holds", async () => {
			const { sessions } = await open();
			const handle = fresh();
			const odd = held({ state: "unheard-of", nested: { list: [1, "two"] } });
			expect(await sessions.save(handle, odd, 60_000)).toBe("created");
			expect(await sessions.save(handle, held({ n: 1 }), 60_000)).toBe("exists");
			expect(await sessions.read(handle)).toEqual(odd);
			expect(await sessions.update(handle, () => undefined)).toEqual({ before: odd, after: odd });
			expect(await sessions.update(fresh(), plus(1))).toBeUndefined();
			expect(await sessions.read(fresh())).toBeUndefined();
		});

		it("changes a record only from what it holds, again after a racing writer", async () => {
			const place = await open();
			const handle = fresh();
			await place.sessions.save(handle, held({ n: 1 }), 60_000);
			expect(await place.sessions.update(handle, plus(1))).toEqual({
				before: held({ n: 1 }),
				after: held({ n: 2 }),
			});
			place.raceNextUpdate(handle, (record) => held({ n: counted(record) * 10 }));
			expect((await place.sessions.update(handle, plus(1)))?.after).toEqual(held({ n: 21 }));
		});

		it("ends a record at exactly its lifetime, or never when it is left without one", async () => {
			const place = await open();
			const [ending, endless] = [fresh(), fresh()];
			await place.sessions.save(ending, held({ n: 1 }), 1000);
			await place.sessions.save(endless, held({ n: 1 }), 1000);
			place.advance(999);
			await place.sessions.update(ending, (record) => ({ value: record, lifetimeMs: 1000 }));
			await place.sessions.update(endless, (record) => ({ value: record, lifetimeMs: "endless" }));
			place.advance(999);
			expect(await place.sessions.read(ending)).toBeDefined();
			place.advance(1);
			expect(await place.sessions.read(ending)).toBeUndefined();
			place.advance(10 * 365 * 86_400_000);
			expect(await place.sessions.read(endless)).toEqual(held({ n: 1 }));
		});

		it("points a cookie's secret at a handle once, for its lifetime, until it is removed", async () => {
			const place = await open();
			const [secret, other, handle] = [fresh(), fresh(), fresh()];
			expect(await place.cookies.save(secret, handle, 60_000)).toBe("created");
			expect(await place.cookies.save(secret, fresh(), 60_000)).toBe("exists");
			expect(await place.cookies.read(secret)).toBe(handle);
			await place.cookies.remove(secret);
			await place.cookies.remove(fresh());
			expect(await place.cookies.read(secret)).toBeUndefined();
			await place.cookies.save(other, handle, 1000);
			place.advance(1000);
			expect(await place.cookies.read(other)).toBeUndefined();
		});

		it("never gives a cookie's secret to what the place holds, in clear", async (context) => {
			const place = await open();
			const { holds } = place;
			if (!holds) return context.skip();
			const [secret, handle] = [fresh(), fresh()];
			await place.cookies.save(secret, handle, 60_000);
			expect(await place.cookies.read(secret)).toBe(handle);
			await place.cookies.remove(secret);
			expect([holds(handle), holds(secret)]).toEqual([true, false]);
		});

		it("lists a subject's sessions each for its lifetime, until one is removed", async () => {
			const { subjects, advance } = await open();
			const [subject, other, ending, lasting] = [fresh(), fresh(), fresh(), fresh()];
			const members = async (of: string) =>
				(await subjects.members(of)).map(({ member }) => member).sort();
			expect((await subjects.add(subject, ending, 1000)).pushedOut).toEqual([]);
			await subjects.add(subject, lasting, 60_000);
			await subjects.add(other, ending, 60_000);
			expect(await members(subject)).toEqual([ending, lasting].sort());
			advance(1000);
			expect(await members(subject)).toEqual([lasting]);
			await subjects.remove(subject, lasting);
			await subjects.remove(fresh(), lasting);
			expect(await members(subject)).toEqual([]);
			expect(await members(other)).toEqual([ending]);
		});

		it("pushes out over its cap only others, never the handle being added", async () => {
			const { subjects } = await open();
			const subject = fresh();
			// Each handle ends before every one listed earlier, so the one ending first is the one being added.
			for (let n = 0; n < 10_000; n++) {
				const handle = fresh();
				const { pushedOut } = await subjects.add(subject, handle, 1_000_000 - n);
				if (pushedOut.length === 0) continue;
				expect(pushedOut).not.toContain(handle);
				expect((await subjects.members(subject)).map(({ member }) => member)).toContain(handle);
				return;
			}
			throw new Error("the listing pushed none out");
		});

		it("keeps closings until done, and a closing whose handling failed", async () => {
			const { closings } = await open();
			const [failing, settled, handled] = [fresh(), fresh(), fresh()];
			for (const handle of [failing, settled, handled]) await closings.add(handle);
			const swept = await closings.each(async (handle) => {
				if (handle === failing) throw new Error("not yet");
				if (handle === settled) await closings.done(handle);
			});
			expect(swept.failed).toBe(1);
			expect(await closingsIn(closings)).toEqual([failing, handled].sort());
		});

		it("refuses a closing past a full place without pushing out one it keeps", async () => {
			const { closings, crowd } = await open();
			const [over, ...kept] = crowd.handles(crowd.limit + 1);
			for (const handle of kept) await closings.add(handle);
			await expect(closings.add(over as string)).rejects.toSatisfy(isUnavailable);
			expect(await closingsIn(closings)).toEqual([...kept].sort());
		}, 60_000);

		it("keeps records, cookies, closings and listings through a restart and through memory pressure", async (context) => {
			const place = await open();
			const { restart, pressMemory } = place;
			if (!restart || !pressMemory) return context.skip();
			const [handle, secret, kept] = [fresh(), fresh(), fresh()];
			await place.sessions.save(handle, held({ n: 1 }), 60_000);
			await place.cookies.save(secret, handle, 60_000);
			await place.closings.add(kept);
			await place.subjects.add(secret, handle, 60_000);
			await restart();
			await pressMemory();
			expect(await place.sessions.read(handle)).toEqual(held({ n: 1 }));
			expect(await place.cookies.read(secret)).toBe(handle);
			expect(await closingsIn(place.closings)).toEqual([kept]);
			expect(await place.subjects.members(secret)).toMatchObject([{ member: handle }]);
		});

		// Each interface fails over after its own writes: a later write in another space would
		// confirm them, and hide a space that does not replicate.
		it("settles writes whose answers were lost, and keeps each interface's through a failover", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover } = place;
			if (!lose || !failover) return context.skip();
			const [handle, secret, retired, kept, settled] = [
				fresh(),
				fresh(),
				fresh(),
				fresh(),
				fresh(),
			];
			lose();
			expect(await place.sessions.save(handle, held({ n: 1 }), 60_000)).toBe("created");
			lose();
			expect((await place.sessions.update(handle, plus(1)))?.after).toEqual(held({ n: 2 }));
			await failover();
			expect(await place.sessions.read(handle)).toEqual(held({ n: 2 }));
			await place.cookies.save(retired, handle, 60_000);
			lose();
			expect(await place.cookies.save(secret, handle, 60_000)).toBe("created");
			lose();
			await place.cookies.remove(retired);
			await failover();
			expect(await place.cookies.read(secret)).toBe(handle);
			expect(await place.cookies.read(retired)).toBeUndefined();
			lose();
			await place.closings.add(kept);
			await place.closings.add(settled);
			lose();
			await place.closings.done(settled);
			await failover();
			expect(await closingsIn(place.closings)).toEqual([kept]);
			await place.subjects.add(kept, retired, 60_000);
			lose();
			await place.subjects.add(kept, handle, 60_000);
			lose();
			await place.subjects.remove(kept, retired);
			await failover();
			expect(await place.subjects.members(kept)).toMatchObject([{ member: handle }]);
		});
	});
}
