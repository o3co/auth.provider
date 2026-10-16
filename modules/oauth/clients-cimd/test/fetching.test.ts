import { describe, expect, it } from "vitest";
import { type Fetched, fetchingOver, type Limits } from "../src/fetching/fetching.ts";

const limits: Limits = { cacheMs: 600_000, entries: 256, refusedMs: 60_000, concurrent: 8 };

/** A loader answering from a script per id, counting its calls; the clock moves by hand. */
function harness(script: (id: string) => Fetched<string> | Promise<Fetched<string>>, set = limits) {
	let now = 1_000_000;
	const calls: string[] = [];
	const fetching = fetchingOver(
		async (id) => {
			calls.push(id);
			return script(id);
		},
		set,
		{ now: () => now },
	);
	return {
		find: fetching.find,
		calls,
		pass: (ms: number) => {
			now += ms;
		},
	};
}

const found = (value: string, maxAgeMs?: number): Fetched<string> => ({
	kind: "found",
	value,
	maxAgeMs,
});

describe("fetching: keeping what was found", () => {
	it("keeps a found value until the cache time, then fetches again", async () => {
		const h = harness((id) => found(`v-${id}`));
		expect(await h.find("a")).toBe("v-a");
		h.pass(599_999);
		expect(await h.find("a")).toBe("v-a");
		expect(h.calls).toEqual(["a"]);
		h.pass(1);
		await h.find("a");
		expect(h.calls).toEqual(["a", "a"]);
	});

	it("keeps it for the answer's max age when that is shorter, and never longer than the cache time", async () => {
		const short = harness(() => found("v", 1_000));
		await short.find("a");
		short.pass(1_000);
		await short.find("a");
		expect(short.calls).toHaveLength(2);
		const long = harness(() => found("v", 10_000_000));
		await long.find("a");
		long.pass(600_000);
		await long.find("a");
		expect(long.calls).toHaveLength(2);
	});

	it("counts the keep time from the start of the fetch, however long the answer takes", async () => {
		const { promise, resolve } = Promise.withResolvers<Fetched<string>>();
		const h = harness(() => promise);
		const first = h.find("a");
		h.pass(5_000);
		resolve(found("v"));
		expect(await first).toBe("v");
		h.pass(594_999);
		await h.find("a");
		expect(h.calls).toHaveLength(1);
		h.pass(1);
		await h.find("a");
		expect(h.calls).toHaveLength(2);
	});

	it("gives an answer that outlived its max age while it came, but keeps nothing", async () => {
		const { promise, resolve } = Promise.withResolvers<Fetched<string>>();
		const h = harness(() => promise);
		const first = h.find("a");
		h.pass(2_000);
		resolve(found("v", 1_000));
		expect(await first).toBe("v");
		await h.find("a");
		expect(h.calls).toHaveLength(2);
	});

	it("keeps nothing for a max age of zero", async () => {
		const h = harness(() => found("v", 0));
		await h.find("a");
		await h.find("a");
		expect(h.calls).toHaveLength(2);
	});

	it("never uses an expired value when fetching again fails or is refused", async () => {
		let answer: Fetched<string> = found("v");
		const h = harness(() => answer);
		await h.find("a");
		h.pass(600_000);
		answer = { kind: "failed" };
		expect(await h.find("a")).toBeUndefined();
		answer = { kind: "refused" };
		expect(await h.find("a")).toBeUndefined();
	});

	it("lets nothing it does not keep push out what it keeps", async () => {
		const h = harness((id) => found(id, id === "b" ? 0 : undefined), { ...limits, entries: 1 });
		await h.find("a");
		await h.find("b");
		await h.find("a");
		expect(h.calls).toEqual(["a", "b"]);
	});

	it("drops an expired value at once, so it never pushes out a live one", async () => {
		let failing = false;
		const h = harness(
			(id) => (failing ? { kind: "failed" } : found(id, id === "a" ? 1_000 : undefined)),
			{
				...limits,
				entries: 2,
			},
		);
		await h.find("b");
		await h.find("a");
		h.pass(1_000);
		failing = true;
		await h.find("a");
		failing = false;
		await h.find("c");
		await h.find("b");
		expect(h.calls).toEqual(["b", "a", "a", "c"]);
	});

	it("holds at most the entries, dropping the one found longest ago", async () => {
		const h = harness((id) => found(id), { ...limits, entries: 2 });
		await h.find("a");
		await h.find("b");
		await h.find("c");
		await h.find("b");
		await h.find("c");
		expect(h.calls).toEqual(["a", "b", "c"]);
		await h.find("a");
		expect(h.calls).toEqual(["a", "b", "c", "a"]);
	});
});

describe("fetching: remembering refusals", () => {
	it("answers none without fetching while a refusal is remembered, then fetches again", async () => {
		const h = harness(() => ({ kind: "refused" }));
		expect(await h.find("a")).toBeUndefined();
		h.pass(59_999);
		expect(await h.find("a")).toBeUndefined();
		expect(h.calls).toEqual(["a"]);
		h.pass(1);
		await h.find("a");
		expect(h.calls).toEqual(["a", "a"]);
	});

	it("does not remember a failure, nor a loader that rejects", async () => {
		const failed = harness(() => ({ kind: "failed" }));
		await failed.find("a");
		await failed.find("a");
		expect(failed.calls).toHaveLength(2);
		const rejected = harness(() => Promise.reject(new Error("down")));
		expect(await rejected.find("a")).toBeUndefined();
		await rejected.find("a");
		expect(rejected.calls).toHaveLength(2);
	});

	it("counts the refusal time from the start of the fetch", async () => {
		const { promise, resolve } = Promise.withResolvers<Fetched<string>>();
		const h = harness(() => promise);
		const first = h.find("a");
		h.pass(5_000);
		resolve({ kind: "refused" });
		await first;
		h.pass(54_999);
		await h.find("a");
		expect(h.calls).toHaveLength(1);
		h.pass(1);
		await h.find("a");
		expect(h.calls).toHaveLength(2);
	});

	it("remembers nothing when the refusal time is zero", async () => {
		const h = harness(() => ({ kind: "refused" }), { ...limits, refusedMs: 0 });
		await h.find("a");
		await h.find("a");
		expect(h.calls).toHaveLength(2);
	});

	it("lets no refusal whose time ran out while it came push out a remembered one", async () => {
		const { promise, resolve } = Promise.withResolvers<Fetched<string>>();
		const h = harness((id) => (id === "b" ? promise : { kind: "refused" }), {
			...limits,
			entries: 1,
		});
		const slow = h.find("b");
		h.pass(1_000);
		await h.find("a");
		h.pass(59_000);
		resolve({ kind: "refused" });
		await slow;
		await h.find("a");
		expect(h.calls).toEqual(["b", "a"]);
	});

	it("drops an expired refusal at once, so it never pushes out a live one", async () => {
		const { promise, resolve } = Promise.withResolvers<Fetched<string>>();
		let failing = false;
		const h = harness(
			(id) => (failing ? { kind: "failed" } : id === "a" ? promise : { kind: "refused" }),
			{ ...limits, entries: 2 },
		);
		const slow = h.find("a");
		h.pass(1_000);
		await h.find("b");
		resolve({ kind: "refused" });
		await slow;
		h.pass(59_000);
		failing = true;
		await h.find("a");
		failing = false;
		await h.find("c");
		await h.find("b");
		expect(h.calls).toEqual(["a", "b", "a", "c"]);
	});

	it("bounds the refusals by the entries too", async () => {
		const h = harness(() => ({ kind: "refused" }), { ...limits, entries: 2 });
		for (const id of ["a", "b", "c", "a"]) await h.find(id);
		expect(h.calls).toEqual(["a", "b", "c", "a"]);
	});
});

describe("fetching: fetches at once", () => {
	it("joins fetches of the same id into one", async () => {
		const { promise, resolve } = Promise.withResolvers<Fetched<string>>();
		const h = harness(() => promise);
		const both = Promise.all([h.find("a"), h.find("a")]);
		resolve(found("v"));
		expect(await both).toEqual(["v", "v"]);
		expect(h.calls).toEqual(["a"]);
	});

	it("answers none at once past the running limit, remembering nothing, and frees the place", async () => {
		const waiting: ((answer: Fetched<string>) => void)[] = [];
		const h = harness(() => new Promise((done) => waiting.push(done)), {
			...limits,
			concurrent: 2,
		});
		const first = h.find("a");
		const second = h.find("b");
		expect(await h.find("c")).toBeUndefined();
		expect(h.calls).toEqual(["a", "b"]);
		for (const open of waiting) open(found("v"));
		await Promise.all([first, second]);
		const third = h.find("c");
		waiting[2]?.(found("v"));
		expect(await third).toBe("v");
	});
});
