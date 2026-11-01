import { describe, expect, it } from "vitest";
import type { Job } from "../../resolver-process/contract.ts";
import {
	inProcessPool,
	LookupRefused,
	lookupShares,
	lookupsOver,
	type Pool,
	threadpoolHalf,
} from "../contract.ts";

/** A pool the test answers by hand, counting the interest each lookup is told of. */
function handPool(size = 4) {
	const jobs: {
		name: string;
		family?: 4;
		interest: number;
		wanted: boolean;
		settle: (addresses: readonly string[]) => void;
		fail: () => void;
	}[] = [];
	const pool: Pool = {
		run: (name, family) => {
			if (jobs.filter((j) => j.interest >= 0).length >= size) return undefined;
			let settle: (addresses: readonly string[]) => void = () => {};
			let fail: () => void = () => {};
			const answer = new Promise<readonly string[]>((resolve, reject) => {
				settle = resolve;
				fail = () => reject(new Error("lost"));
			});
			answer.catch(() => {});
			const job = { name, ...(family ? { family } : {}), interest: 1, wanted: true, settle, fail };
			jobs.push(job);
			const handle: Job = {
				answer,
				want: () => {
					if (!job.wanted) return false;
					job.interest += 1;
					return true;
				},
				unwant: () => {
					job.interest -= 1;
				},
			};
			return handle;
		},
	};
	return { pool, jobs };
}

const failureOf = (promise: Promise<unknown>) =>
	promise.then(
		() => "answered",
		(error) => (error instanceof LookupRefused ? error.failure : String(error)),
	);
const tick = () => new Promise((r) => setTimeout(r, 0));

describe("lookups shared among those asking at once", () => {
	it("resolves a name once for those asking it at once", async () => {
		const { pool, jobs } = handPool();
		const lookups = lookupsOver(pool);
		const live = new AbortController().signal;
		const both = [
			lookups.resolve("svc.test", undefined, live),
			lookups.resolve("svc.test", undefined, live),
		];
		expect(jobs).toHaveLength(1);
		expect(jobs[0]?.interest).toBe(2);
		jobs[0]?.settle(["10.0.0.1"]);
		expect(await Promise.all(both)).toEqual([["10.0.0.1"], ["10.0.0.1"]]);
	});

	it("lets each waiter go at its own deadline, the lookup told of each, the others still answered", async () => {
		const { pool, jobs } = handPool();
		const lookups = lookupsOver(pool);
		const short = new AbortController();
		const long = new AbortController();
		const first = lookups.resolve("svc.test", undefined, short.signal);
		const second = lookups.resolve("svc.test", undefined, long.signal);
		short.abort();
		expect(await failureOf(first)).toBe("timeout");
		expect(jobs[0]?.interest).toBe(1);
		jobs[0]?.settle(["10.0.0.1"]);
		expect(await second).toEqual(["10.0.0.1"]);
		const third = new AbortController();
		const late = lookups.resolve("other.test", undefined, third.signal);
		third.abort();
		await failureOf(late);
		expect(jobs[1]?.interest).toBe(0);
	});

	it("joins one no one waits on any more, while it may be waited on", async () => {
		const { pool, jobs } = handPool();
		const lookups = lookupsOver(pool);
		const gone = new AbortController();
		const left = lookups.resolve("svc.test", undefined, gone.signal);
		gone.abort();
		await failureOf(left);
		expect(jobs[0]?.interest).toBe(0);
		const back = lookups.resolve("svc.test", undefined, new AbortController().signal);
		expect(jobs).toHaveLength(1);
		expect(jobs[0]?.interest).toBe(1);
		jobs[0]?.settle(["10.0.0.1"]);
		expect(await back).toEqual(["10.0.0.1"]);
	});

	it("begins another where the one resolving may no longer be waited on, and the old one's end leaves it", async () => {
		const { pool, jobs } = handPool();
		const lookups = lookupsOver(pool);
		const live = new AbortController().signal;
		const old = lookups.resolve("svc.test", undefined, live);
		(jobs[0] as { wanted: boolean }).wanted = false;
		const fresh = lookups.resolve("svc.test", undefined, live);
		expect(jobs).toHaveLength(2);
		// The old one ends late: the key keeps the new one, which a third asker joins.
		jobs[0]?.fail();
		expect(await failureOf(old)).toBe("unreachable");
		await tick();
		const third = lookups.resolve("svc.test", undefined, live);
		expect(jobs).toHaveLength(2);
		expect(jobs[1]?.interest).toBe(2);
		jobs[1]?.settle(["10.0.0.2"]);
		expect(await Promise.all([fresh, third])).toEqual([["10.0.0.2"], ["10.0.0.2"]]);
	});

	it("shares no lookup between IPv4 alone and every family, nor between a name and the name with its dot", () => {
		const { pool, jobs } = handPool();
		const lookups = lookupsOver(pool);
		const live = new AbortController().signal;
		for (const [name, family] of [
			["short", undefined],
			["short", 4],
			["short.", undefined],
		] as const) {
			lookups.resolve(name, family, live).catch(() => {});
		}
		expect(jobs.map((j) => `${j.family ?? "any"} ${j.name}`)).toEqual([
			"any short",
			"4 short",
			"any short.",
		]);
	});

	it("is unavailable at once with no place, timed out at once past its deadline, unreachable where the lookup fails", async () => {
		const { pool, jobs } = handPool(1);
		const lookups = lookupsOver(pool);
		const live = new AbortController().signal;
		const holding = lookups.resolve("a.test", undefined, live);
		expect(await failureOf(lookups.resolve("b.test", undefined, live))).toBe("unavailable");
		expect(await failureOf(lookups.resolve("b.test", undefined, AbortSignal.abort()))).toBe(
			"timeout",
		);
		jobs[0]?.fail();
		expect(await failureOf(holding)).toBe("unreachable");
	});
});

describe("a lookup that never ends", () => {
	it("holds no more of each asker that left it: joining and timing out again and again keeps its subscriptions", async () => {
		let subscriptions = 0;
		const pending = new Promise<readonly string[]>(() => {});
		const plain = pending.then.bind(pending);
		const answer = Object.assign(pending, {
			// biome-ignore lint/suspicious/noThenProperty: counts each handler put on the answer
			then: ((...handlers: Parameters<typeof plain>) => {
				subscriptions += 1;
				return plain(...handlers);
			}) as typeof plain,
		});
		const job: Job = { answer, want: () => true, unwant: () => {} };
		const lookups = lookupsOver({ run: () => job });
		const askAndLeave = async () => {
			const deadline = new AbortController();
			const asked = lookups.resolve("stuck.test", undefined, deadline.signal).catch(() => "left");
			deadline.abort();
			expect(await asked).toBe("left");
		};
		await askAndLeave();
		const afterOne = subscriptions;
		for (let i = 0; i < 100; i++) await askAndLeave();
		expect(subscriptions).toBe(afterOne);
	});
});

describe("lookups in this process", () => {
	it("holds a place until the system's answer, one left by all its waiters still holding it and joined again", async () => {
		const settles = new Map<string, (addresses: readonly string[]) => void>();
		const calls: string[] = [];
		const pool = inProcessPool(1, (name) => {
			calls.push(name);
			return new Promise((done) => settles.set(name, done));
		});
		const lookups = lookupsOver(pool);
		const gone = new AbortController();
		const left = lookups.resolve("slow.test", undefined, gone.signal);
		gone.abort();
		expect(await failureOf(left)).toBe("timeout");
		await tick();
		// Its place is still held: no other name is looked up meanwhile.
		expect(
			await failureOf(lookups.resolve("other.test", undefined, new AbortController().signal)),
		).toBe("unavailable");
		const again = lookups.resolve("slow.test", undefined, new AbortController().signal);
		expect(calls).toEqual(["slow.test"]);
		settles.get("slow.test")?.(["10.0.0.1"]);
		expect(await again).toEqual(["10.0.0.1"]);
		await tick();
		expect(pool.run("other.test")).toBeDefined();
	});

	it("is unreachable where the resolver throws, at once or later", async () => {
		const lookups = lookupsOver(
			inProcessPool(2, (name) => {
				if (name === "now.test") throw new Error("at once");
				return Promise.reject(new Error("later"));
			}),
		);
		const live = new AbortController().signal;
		expect(await failureOf(lookups.resolve("now.test", undefined, live))).toBe("unreachable");
		expect(await failureOf(lookups.resolve("later.test", undefined, live))).toBe("unreachable");
	});

	it("never runs more than half the threadpool at once, both pools full together", async () => {
		const shares = lookupShares({ maxLookups: 4, inProcess: { threadpool: "4" } });
		expect(shares).toEqual({ total: 2, own: 1, outside: 1 });
		let running = 0;
		let most = 0;
		const slow = () => {
			running += 1;
			most = Math.max(most, running);
			return new Promise<readonly string[]>(() => {});
		};
		const own = lookupsOver(inProcessPool(shares.own, slow));
		const outside = lookupsOver(inProcessPool(shares.outside, slow));
		const live = new AbortController().signal;
		const asked = ["a", "b", "c"].flatMap((n) => [
			failureOf(own.resolve(`${n}.own`, undefined, live)),
			failureOf(outside.resolve(`${n}.outside`, undefined, live)),
		]);
		await tick();
		expect(most).toBe(2);
		expect(await Promise.race([Promise.all(asked.slice(2)), tick().then(() => "pending")])).toEqual(
			["unavailable", "unavailable", "unavailable", "unavailable"],
		);
	});
});

describe("the shares of lookups at once", () => {
	it("takes half the threadpool, at least one, four threads where unset or unreadable", () => {
		expect(
			[undefined, "", "4", "x", "0", "-2", "1", "2", "3", "8", "64", "1024"].map(threadpoolHalf),
		).toEqual([2, 2, 2, 2, 2, 2, 1, 1, 2, 4, 32, 512]);
	});

	it("gives the outside party half, rounded down, and the deployment's own the rest; in this process, of half the threadpool at most", () => {
		expect(lookupShares({ maxLookups: 4 })).toEqual({ total: 4, own: 2, outside: 2 });
		expect(lookupShares({ maxLookups: 1 })).toEqual({ total: 1, own: 1, outside: 0 });
		expect(lookupShares({ maxLookups: 16, inProcess: { threadpool: "4" } })).toEqual({
			total: 2,
			own: 1,
			outside: 1,
		});
		expect(lookupShares({ maxLookups: 16, inProcess: { threadpool: "2" } })).toEqual({
			total: 1,
			own: 1,
			outside: 0,
		});
		expect(lookupShares({ maxLookups: 1, inProcess: { threadpool: "8" } })).toEqual({
			total: 1,
			own: 1,
			outside: 0,
		});
	});
});
