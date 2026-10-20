import { createHash } from "node:crypto";
import { cookiesFor } from "@mod/cookies";
import { testRequest } from "@mod/http/testing";
import { isUnavailable } from "@mod/kernel";
import { memoryRecords } from "@mod/records/testing";
import { describe, expect, it } from "vitest";
import type { RoundTripStore, StoredRoundTrip } from "../src/contract.ts";
import { roundTripsOver } from "../src/round-trips.ts";

const now = 1_800_000_000_000;
const random = { bytes: (n: number) => crypto.getRandomValues(new Uint8Array(n)) };

function place(store?: RoundTripStore) {
	let at = now;
	const kept = memoryRecords<StoredRoundTrip>(() => at, { shards: 1, perShard: 1 });
	const records: RoundTripStore = store ?? {
		save: kept.records.create,
		update: kept.records.change,
	};
	const cookies = cookiesFor(true);
	const trips = roundTripsOver({ store: records, cookies, random, clock: { now: () => at } });
	/** A request back from the upstream over https, carrying these Set-Cookie values as its cookies. */
	const back = (...set: string[]) =>
		testRequest({
			headers: new Map([
				["cookie", set.map((c) => c.split(";")[0] ?? "").join("; ")],
				["x-forwarded-proto", "https"],
			]),
			source: { address: "198.51.100.1", scheme: "https", determined: true },
		});
	return {
		trips,
		back,
		advance: (ms: number) => {
			at += ms;
		},
	};
}

const bytesOf = (text: string) => Buffer.from(text, "base64url").length;

describe("an upstream round trip", () => {
	it("makes a 256-bit cookie, state, nonce and verifier, the challenge the verifier's S256", async () => {
		const { trips, back } = place();
		const begun = await trips.begin({ name: "fed.corp", carried: { at: 1 }, lifetimeMs: 60_000 });
		const id = /__Host-fed\.corp=([^;]+)/.exec(begun.cookie)?.[1] ?? "";
		expect([bytesOf(id), bytesOf(begun.state), bytesOf(begun.nonce)]).toEqual([32, 32, 32]);
		expect(begun.challengeMethod).toBe("S256");
		const taken = await trips.take(back(begun.cookie), "fed.corp", begun.state);
		if (taken.kind !== "taken") throw new Error("not taken");
		expect(bytesOf(taken.verifier)).toBe(32);
		expect(begun.challenge).toBe(createHash("sha256").update(taken.verifier).digest("base64url"));
		expect([taken.carried, taken.nonce, taken.startedAt]).toEqual([{ at: 1 }, begun.nonce, now]);
	});

	it("sets its cookie for the lifetime in whole seconds, rounded up and at least one", async () => {
		const { trips } = place();
		const ages = [];
		for (const lifetimeMs of [999, 1000, 1500]) {
			const { cookie } = await trips.begin({ name: "a", carried: null, lifetimeMs });
			ages.push(/Max-Age=(\d+)/.exec(cookie)?.[1]);
		}
		expect(ages).toEqual(["1", "1", "2"]);
	});

	it("is unavailable when a record already lives under its fresh cookie", async () => {
		const taken: RoundTripStore = { save: async () => "exists", update: async () => undefined };
		const { trips } = place(taken);
		const begun = trips.begin({ name: "a", carried: null, lifetimeMs: 1000 });
		await expect(begun).rejects.toSatisfy(isUnavailable);
	});

	it("is taken once, only by its own name with its own state, and spends nothing otherwise", async () => {
		const { trips, back } = place();
		const begun = await trips.begin({ name: "fed.corp", carried: null, lifetimeMs: 60_000 });
		const request = back(begun.cookie);
		expect(await trips.take(back(), "fed.corp", begun.state)).toEqual({ kind: "none" });
		expect(await trips.take(request, "fed.corp", undefined)).toEqual({ kind: "none" });
		expect(await trips.take(request, "fed.corp", "x".repeat(43))).toEqual({ kind: "none" });
		expect(
			await trips.take(
				back(begun.cookie.replace("fed.corp", "fed.other")),
				"fed.other",
				begun.state,
			),
		).toEqual({
			kind: "none",
		});
		expect((await trips.take(request, "fed.corp", begun.state)).kind).toBe("taken");
		expect(await trips.take(request, "fed.corp", begun.state)).toEqual({ kind: "none" });
	});

	it("is read while it lives, by its own name, without being taken, written or lengthened", async () => {
		const { trips, back, advance } = place();
		const begun = await trips.begin({ name: "fed.corp", carried: { at: 1 }, lifetimeMs: 60_000 });
		const request = back(begun.cookie);
		const live = {
			state: begun.state,
			nonce: begun.nonce,
			challenge: begun.challenge,
			challengeMethod: "S256",
			carried: { at: 1 },
		};
		expect(await trips.current(request, "fed.corp")).toEqual(live);
		expect(await trips.current(back(), "fed.corp")).toBeUndefined();
		const renamed = back(begun.cookie.replace("fed.corp", "fed.other"));
		expect(await trips.current(renamed, "fed.other")).toBeUndefined();
		advance(30_000);
		expect(await trips.current(request, "fed.corp")).toEqual(live);
		// Its end is where its start put it, however often it is read.
		advance(30_001);
		expect(await trips.current(request, "fed.corp")).toBeUndefined();
		expect(await trips.take(request, "fed.corp", begun.state)).toEqual({ kind: "none" });
	});

	it("is read as none once taken, or kept in a shape it does not know", async () => {
		const { trips, back } = place();
		const begun = await trips.begin({ name: "a", carried: null, lifetimeMs: 60_000 });
		expect((await trips.take(back(begun.cookie), "a", begun.state)).kind).toBe("taken");
		expect(await trips.current(back(begun.cookie), "a")).toBeUndefined();
		const unknown = { format: 2 } as unknown as StoredRoundTrip;
		const odd: RoundTripStore = {
			save: async () => "created",
			update: async (_cookie, change) => ({
				before: unknown,
				after: change(unknown)?.value ?? unknown,
			}),
		};
		const other = place(odd);
		const kept = await other.trips.begin({ name: "a", carried: null, lifetimeMs: 60_000 });
		expect(await other.trips.current(other.back(kept.cookie), "a")).toBeUndefined();
	});

	it("is taken by one of two callbacks at once, never both", async () => {
		const { trips, back } = place();
		const begun = await trips.begin({ name: "a", carried: null, lifetimeMs: 60_000 });
		const both = await Promise.all([
			trips.take(back(begun.cookie), "a", begun.state),
			trips.take(back(begun.cookie), "a", begun.state),
		]);
		expect(both.map((t) => t.kind).sort()).toEqual(["none", "taken"]);
	});

	it("ends the first of two round trips of one name begun in one browser", async () => {
		const { trips, back } = place();
		const first = await trips.begin({ name: "a", carried: 1, lifetimeMs: 60_000 });
		const second = await trips.begin({ name: "a", carried: 2, lifetimeMs: 60_000 });
		// The browser keeps the cookie set last.
		expect(await trips.take(back(second.cookie), "a", first.state)).toEqual({ kind: "none" });
		expect(await trips.take(back(second.cookie), "a", second.state)).toMatchObject({ carried: 2 });
	});

	it("reads no cookie sent twice or over plain http, so takes nothing", async () => {
		const { trips, back } = place();
		const begun = await trips.begin({ name: "a", carried: null, lifetimeMs: 60_000 });
		expect(await trips.take(back(begun.cookie, begun.cookie), "a", begun.state)).toEqual({
			kind: "none",
		});
		const plain = testRequest({
			headers: new Map([["cookie", begun.cookie.split(";")[0] ?? ""]]),
			source: { address: "198.51.100.1", scheme: "http", determined: true },
		});
		expect(await trips.take(plain, "a", begun.state)).toEqual({ kind: "none" });
		expect((await trips.take(back(begun.cookie), "a", begun.state)).kind).toBe("taken");
	});

	it("clears its cookie once taken, with the attributes it was set with", async () => {
		const { trips, back } = place();
		for (const crossSite of [false, true]) {
			const begun = await trips.begin({ name: "a", carried: null, lifetimeMs: 60_000, crossSite });
			const taken = await trips.take(back(begun.cookie), "a", begun.state);
			if (taken.kind !== "taken") throw new Error("not taken");
			const [cleared] = taken.cleared;
			expect(cleared).toMatch(/^__Host-a=;.*Max-Age=0/);
			expect(cleared?.includes("SameSite=None")).toBe(crossSite);
			expect(begun.cookie.includes("SameSite=None")).toBe(crossSite);
		}
	});
});
