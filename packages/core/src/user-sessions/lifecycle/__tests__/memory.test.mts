/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * What the in-process `SessionLifecycleStore` adds to the port's contract
 * (which `@o3co/auth-provider-test-kit`'s `sessionLifecycleStoreContract`
 * holds it to): its retention's lengths on its clock, its bounds, its
 * refusal of a caller's input, and its own copies.
 */

import { describe, expect, it } from "vitest";
import {
	createInMemorySessionLifecycleStore,
	DEFAULT_CLOCK_SKEW_MS,
	DEFAULT_MEMORY_SESSION_LIFECYCLE_MAX_ENTRIES,
	DEFAULT_MEMORY_SESSION_LIFECYCLE_MAX_PARTICIPANTS,
	readConditionalReplaceAnswer,
	readSessionCloseAnswer,
	readVersionedSessionLifecycle,
	type SessionCloseRequest,
	type SessionLifecycleStore,
	type SessionParticipant,
} from "#/index.mjs";
import { MAX_MEMORY_STORE_ENTRIES } from "#/single-use/max-entries.mjs";

const START = Date.parse("2026-10-05T00:00:00.000Z");
const HOUR = 60 * 60 * 1000;

const clock = (start = START) => {
	let now = start;
	return {
		now: () => now,
		advance(ms: number) {
			now += ms;
		},
	};
};

const rp = (id: string): SessionParticipant => ({ kind: "rp", id, data: `{"id":"${id}"}` });

const CLOSE: SessionCloseRequest = {
	cause: "rp_logout",
	steps: ["user_session"],
	perParticipant: ["rp"],
	retainMs: 0,
};

const read = async (store: SessionLifecycleStore, sid: string) =>
	readVersionedSessionLifecycle(await store.read(sid));

describe("createInMemorySessionLifecycleStore", () => {
	it("is of kind memory", () => {
		expect(createInMemorySessionLifecycleStore().kind).toBe("memory");
	});

	describe("retention, on its clock", () => {
		it("keeps an active record until its expiresAt plus the clock skew, and no longer", async () => {
			const time = clock();
			const store = createInMemorySessionLifecycleStore({ now: time.now });
			const expiresAt = new Date(START + HOUR);
			expect((await store.open("s", "u", expiresAt)).outcome).toBe("opened");
			time.advance(HOUR + DEFAULT_CLOCK_SKEW_MS - 1);
			expect((await read(store, "s"))?.value.state).toBe("active");
			time.advance(1);
			expect(await read(store, "s")).toBeNull();
		});

		it("refuses a join from the session's expiresAt on, while the record is still kept", async () => {
			const time = clock();
			const store = createInMemorySessionLifecycleStore({ now: time.now });
			await store.open("s", "u", new Date(START + HOUR));
			time.advance(HOUR - 1);
			expect((await store.join("s", rp("a"))).outcome).toBe("joined");
			time.advance(1);
			expect((await store.join("s", rp("b"))).outcome).toBe("closed");
			expect((await read(store, "s"))?.value.participants).toEqual([rp("a")]);
		});

		it("refuses a repeated open from the session's expiresAt on, keeping the record as it was", async () => {
			const time = clock();
			const store = createInMemorySessionLifecycleStore({ now: time.now });
			const expiresAt = new Date(START + HOUR);
			await store.open("s", "u", expiresAt);
			const before = await read(store, "s");
			time.advance(HOUR);
			expect((await store.open("s", "u", expiresAt)).outcome).toBe("refused");
			expect(await read(store, "s")).toStrictEqual(before);
		});

		it("refuses an open whose expiresAt is not after its clock", async () => {
			const time = clock();
			const store = createInMemorySessionLifecycleStore({ now: time.now });
			expect((await store.open("s", "u", new Date(START))).outcome).toBe("refused");
			expect(await read(store, "s")).toBeNull();
			expect((await store.open("s", "u", new Date(START + 1))).outcome).toBe("opened");
		});

		it("keeps a closing record until the later of expiresAt plus the skew and the commit plus retainMs", async () => {
			for (const retainMs of [10 * HOUR, 1]) {
				const time = clock();
				const store = createInMemorySessionLifecycleStore({ now: time.now });
				await store.open("s", "u", new Date(START + HOUR));
				time.advance(HOUR / 2);
				const answer = readSessionCloseAnswer(await store.beginClose("s", { ...CLOSE, retainMs }));
				expect(answer.outcome).toBe("closing");
				const until = Math.max(START + HOUR + DEFAULT_CLOCK_SKEW_MS, START + HOUR / 2 + retainMs);
				time.advance(until - time.now() - 1);
				expect((await read(store, "s"))?.value.state).toBe("closing");
				time.advance(1);
				expect(await read(store, "s")).toBeNull();
			}
		});

		it("keeps a closed record as long as it kept it closing", async () => {
			const time = clock();
			const store = createInMemorySessionLifecycleStore({ now: time.now });
			await store.open("s", "u", new Date(START + HOUR));
			const answer = readSessionCloseAnswer(
				await store.beginClose("s", { ...CLOSE, retainMs: 5 * HOUR }),
			);
			if (answer.outcome !== "closing") throw new Error("not closing");
			const done = readConditionalReplaceAnswer(
				await store.completeIf("s", answer.generation, "user_session"),
			);
			expect(done.outcome).toBe("updated");
			time.advance(5 * HOUR - 1);
			expect((await read(store, "s"))?.value.state).toBe("closed");
			time.advance(1);
			expect(await read(store, "s")).toBeNull();
		});

		it("closes a session past its expiresAt while the record is kept", async () => {
			const time = clock();
			const store = createInMemorySessionLifecycleStore({ now: time.now });
			await store.open("s", "u", new Date(START + HOUR));
			time.advance(HOUR + 1);
			const answer = readSessionCloseAnswer(
				await store.beginClose("s", { ...CLOSE, cause: "expiry" }),
			);
			expect(answer.outcome).toBe("closing");
		});

		it("refuses a clock that answers no finite instant", async () => {
			const store = createInMemorySessionLifecycleStore({ now: () => Number.NaN });
			await expect(store.open("s", "u", new Date(START + HOUR))).rejects.toThrow(RangeError);
		});
	});

	describe("bounds", () => {
		it("names the option it refuses", () => {
			expect(() => createInMemorySessionLifecycleStore({ maxParticipants: 0 })).toThrow(
				/maxParticipants must be/,
			);
			expect(() => createInMemorySessionLifecycleStore({ maxEntries: 0 })).toThrow(
				/maxEntries must be/,
			);
		});

		it("refuses a maxEntries or a maxParticipants that is not a usable cap", () => {
			for (const bad of [0, -1, 1.5, Number.NaN, MAX_MEMORY_STORE_ENTRIES + 1]) {
				expect(() => createInMemorySessionLifecycleStore({ maxEntries: bad })).toThrow(RangeError);
				expect(() => createInMemorySessionLifecycleStore({ maxParticipants: bad })).toThrow(
					RangeError,
				);
			}
			expect(DEFAULT_MEMORY_SESSION_LIFECYCLE_MAX_ENTRIES).toBe(100_000);
			expect(DEFAULT_MEMORY_SESSION_LIFECYCLE_MAX_PARTICIPANTS).toBe(1_000);
		});

		it("full, drops lapsed records to open another, and otherwise rejects, evicting nothing", async () => {
			const time = clock();
			const store = createInMemorySessionLifecycleStore({ now: time.now, maxEntries: 2 });
			await store.open("short", "u", new Date(START + 1));
			await store.open("long", "u", new Date(START + HOUR));
			await expect(store.open("third", "u", new Date(START + HOUR))).rejects.toThrow(/full/);
			expect(await read(store, "third")).toBeNull();
			expect(await read(store, "short")).not.toBeNull();
			time.advance(1 + DEFAULT_CLOCK_SKEW_MS);
			expect((await store.open("third", "u", new Date(START + HOUR))).outcome).toBe("opened");
			expect(await read(store, "long")).not.toBeNull();
		});

		it("rejects a new participant past maxParticipants, and still answers a participant it holds", async () => {
			const store = createInMemorySessionLifecycleStore({ maxParticipants: 2 });
			await store.open("s", "u", new Date(Date.now() + HOUR));
			await store.join("s", rp("a"));
			await store.join("s", rp("b"));
			const before = await read(store, "s");
			await expect(store.join("s", rp("c"))).rejects.toThrow(/participants/);
			expect(await read(store, "s")).toStrictEqual(before);
			expect((await store.join("s", { ...rp("a"), data: "again" })).outcome).toBe("joined");
		});
	});

	describe("a caller's input", () => {
		const live = async () => {
			const store = createInMemorySessionLifecycleStore();
			await store.open("s", "u", new Date(Date.now() + HOUR));
			return store;
		};

		it("refuses a sid, a sub or an expiresAt the port does not admit, writing nothing", async () => {
			const store = createInMemorySessionLifecycleStore();
			const later = new Date(Date.now() + HOUR);
			await expect(store.open("", "u", later)).rejects.toThrow(RangeError);
			await expect(store.open("x".repeat(513), "u", later)).rejects.toThrow(RangeError);
			await expect(store.open("s", "", later)).rejects.toThrow(RangeError);
			await expect(store.open("\ud800", "u", later)).rejects.toThrow(RangeError);
			await expect(store.open("s", "u", new Date(Number.NaN))).rejects.toThrow(RangeError);
			await expect(store.open("s", "u", "later" as never)).rejects.toThrow(RangeError);
			const forged = Object.assign(new Date(Number.NaN), { getTime: () => Date.now() + HOUR });
			await expect(store.open("s", "u", forged)).rejects.toThrow(RangeError);
			expect(await read(store, "s")).toBeNull();
			await expect(store.read("")).rejects.toThrow(RangeError);
		});

		it("refuses a participant, a close request, an item or a limit the port does not admit", async () => {
			const store = await live();
			const before = await read(store, "s");
			await expect(store.join("s", { kind: "client", id: "a", data: "" } as never)).rejects.toThrow(
				RangeError,
			);
			await expect(store.beginClose("s", { ...CLOSE, cause: "logout" } as never)).rejects.toThrow(
				RangeError,
			);
			expect(await read(store, "s")).toStrictEqual(before);
			const answer = readSessionCloseAnswer(await store.beginClose("s", CLOSE));
			if (answer.outcome !== "closing") throw new Error("not closing");
			await expect(store.completeIf("s", answer.generation, "")).rejects.toThrow(RangeError);
			await expect(store.completeIf("s", answer.generation, "not_pending")).rejects.toThrow(
				RangeError,
			);
			expect((await read(store, "s"))?.generation).toBe(answer.generation);
			for (const limit of [0, -1, 1.5, 1001, Number.NaN]) {
				await expect(store.listClosing(limit)).rejects.toThrow(RangeError);
			}
		});

		it("checks the generation before the item: a stale generation answers conflict whatever the item", async () => {
			const store = await live();
			const first = readSessionCloseAnswer(
				await store.beginClose("s", { ...CLOSE, steps: ["a", "b"] }),
			);
			if (first.outcome !== "closing") throw new Error("not closing");
			const done = readConditionalReplaceAnswer(await store.completeIf("s", first.generation, "a"));
			expect(done.outcome).toBe("updated");
			expect(
				readConditionalReplaceAnswer(await store.completeIf("s", first.generation, "a")).outcome,
			).toBe("conflict");
		});

		it("refuses a malformed expected generation, writing nothing", async () => {
			const store = await live();
			const answer = readSessionCloseAnswer(await store.beginClose("s", CLOSE));
			if (answer.outcome !== "closing") throw new Error("not closing");
			for (const bad of ["", "has space", 'quote"d', 7]) {
				await expect(store.completeIf("s", bad as never, "user_session")).rejects.toThrow(
					RangeError,
				);
			}
			expect((await read(store, "s"))?.generation).toBe(answer.generation);
		});

		it("answers a repeated open for the same subject and end, and refuses another, writing nothing", async () => {
			const store = await live();
			const before = await read(store, "s");
			const expiresAt = before?.value.expiresAt as Date;
			expect((await store.open("s", "u", expiresAt)).outcome).toBe("opened");
			expect((await store.open("s", "other", expiresAt)).outcome).toBe("refused");
			expect(await read(store, "s")).toStrictEqual(before);
		});

		it("makes one work item per participant of a listed kind", async () => {
			const store = await live();
			await store.join("s", rp("a"));
			await store.join("s", { kind: "family", id: "f", data: "" });
			const answer = readSessionCloseAnswer(await store.beginClose("s", CLOSE));
			expect(
				answer.outcome !== "missing" && [...(answer.record.close?.pending ?? [])].sort(),
			).toEqual(["rp:a", "user_session"]);
		});

		it("refuses an item while the record is active, at its generation", async () => {
			const store = await live();
			const at = await read(store, "s");
			if (at === null) throw new Error("absent");
			await expect(store.completeIf("s", at.generation, "user_session")).rejects.toThrow(
				RangeError,
			);
		});
	});

	// Moves into the shared `sessionLifecycleStoreContract` with the Redis
	// store's join ordinal, so the suite and its Redis parity copy stay alike.
	describe("participant order", () => {
		it("answers participants in the order they first joined, a repeat join not moving one", async () => {
			const c = clock();
			const store = createInMemorySessionLifecycleStore({ now: c.now });
			const expiresAt = new Date(START + HOUR);
			expect((await store.open("s", "u", expiresAt)).outcome).toBe("opened");
			for (const [kind, id] of [
				["federation", "oidc"],
				["rp", "zeta"],
				["federation", "apple"],
				["family", "f1"],
				["federation", "oidc"],
			] as const) {
				expect((await store.join("s", { kind, id, data: "" })).outcome).toBe("joined");
			}
			const order = (await read(store, "s"))?.value.participants.map((p) => `${p.kind}:${p.id}`);
			expect(order).toEqual(["federation:oidc", "rp:zeta", "federation:apple", "family:f1"]);
			// The closing snapshot keeps the order.
			const closed = readSessionCloseAnswer(await store.beginClose("s", CLOSE));
			expect(
				closed.outcome === "missing" ? [] : closed.record.participants.map((p) => p.id),
			).toEqual(["oidc", "zeta", "apple", "f1"]);
		});
	});

	describe("its own copies", () => {
		it("keeps neither the participant nor the Date it was handed, and hands out copies", async () => {
			const store = createInMemorySessionLifecycleStore();
			const expiresAt = new Date(Date.now() + HOUR);
			await store.open("s", "u", expiresAt);
			const participant = { ...rp("a") };
			await store.join("s", participant);
			expiresAt.setTime(0);
			(participant as { id: string }).id = "changed";
			const first = await store.read("s");
			if (first === null) throw new Error("absent");
			(first.value.expiresAt as Date).setTime(0);
			(first.value.participants[0] as { data: string }).data = "mutated";
			(first.value.participants as SessionParticipant[]).push(rp("z"));
			const again = await read(store, "s");
			expect(again?.value.participants).toEqual([rp("a")]);
			expect(again?.value.expiresAt.getTime()).toBeGreaterThan(Date.now());
		});
	});

	it("lists the closing sids in ascending order after the cursor, at most the limit, and pages through them all", async () => {
		const store = createInMemorySessionLifecycleStore();
		for (const sid of ["c", "a", "b", "d"]) {
			await store.open(sid, "u", new Date(Date.now() + HOUR));
			if (sid !== "d") await store.beginClose(sid, CLOSE);
		}
		expect(await store.listClosing(2)).toEqual(["a", "b"]);
		expect(await store.listClosing(2, "b")).toEqual(["c"]);
		expect(await store.listClosing(2, "c")).toEqual([]);
		expect(await store.listClosing(5, "")).toEqual(["a", "b", "c"]);
		const a = readSessionCloseAnswer(await store.beginClose("a", CLOSE));
		if (a.outcome !== "closing") throw new Error("not closing");
		await store.completeIf("a", a.generation, "user_session");
		expect(await store.listClosing(1, "a")).toEqual(["b"]);
		await expect(store.listClosing(1, "x".repeat(513))).rejects.toThrow(RangeError);
		await expect(store.listClosing(1, 7 as never)).rejects.toThrow(RangeError);
		await expect(store.listClosing(1, "\ud800")).rejects.toThrow(RangeError);
	});
});
