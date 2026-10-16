import { expect, it } from "vitest";
import { memoryTransactions } from "../../../test/stores.ts";
import { permitsOver } from "../permits.ts";

let now = 1_800_000_000_000;
const clock = { now: () => now };
/** Permits on a store whose clock is the kernel's, lasting a minute, kept an hour at most. */
function permits() {
	const store = memoryTransactions(clock.now);
	return {
		store,
		permits: permitsOver({
			store: store.transactions,
			clock,
			recent: (at) => clock.now() - at <= 60_000,
			keepMs: 3_600_000,
		}),
	};
}

it("grants a session a release that one proof can use, keeping what it answered", async () => {
	const { permits: p } = permits();
	expect(await p.of("h1")).toEqual({ kind: "none" });
	await p.grant("h1");
	const ready = await p.of("h1");
	if (ready.kind !== "ready") throw new Error(ready.kind);
	expect(await p.of("h2")).toEqual({ kind: "none" });
	await p.use("h1", ready, { lock: "released" });
	expect(await p.of("h1")).toEqual({ kind: "used", result: { lock: "released" } });
	await p.use("h1", ready, { lock: "held", fixedAt: 1 });
	expect(await p.of("h1")).toEqual({ kind: "used", result: { lock: "released" } });
});

it("replaces a session's permit with a later proof's, used or not, under a new id", async () => {
	const { permits: p } = permits();
	await p.grant("h1");
	const first = await p.of("h1");
	if (first.kind !== "ready") throw new Error(first.kind);
	await p.use("h1", first, { lock: "released" });
	now += 1000;
	await p.grant("h1");
	const second = await p.of("h1");
	if (second.kind !== "ready") throw new Error(second.kind);
	expect(second.id).not.toBe(first.id);
	// The earlier proof's use leaves the later permit alone.
	await p.use("h1", first, { lock: "released" });
	expect((await p.of("h1")).kind).toBe("ready");
});

it("lets a permit lapse once its proof is no longer recent, and drops it an hour after the first", async () => {
	const { permits: p } = permits();
	await p.grant("h1");
	now += 60_001;
	expect(await p.of("h1")).toEqual({ kind: "none" });
	await p.grant("h1");
	expect((await p.of("h1")).kind).toBe("ready");
	now += 3_600_000 - 60_001;
	expect(await p.of("h1")).toEqual({ kind: "none" });
	await p.grant("h1");
	expect((await p.of("h1")).kind).toBe("ready");
});

it("keeps the session's handle out of the store's names", async () => {
	const { store, permits: p } = permits();
	await p.grant("handle-in-clear");
	expect(store.peek("handle-in-clear")).toBeUndefined();
});
