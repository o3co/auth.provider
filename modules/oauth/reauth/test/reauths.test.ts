import { randomBytes } from "node:crypto";
import { assemble, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import { describe, expect, it } from "vitest";
import { reauthStore, reauths, type StoredReauth } from "../src/contract.ts";
import reauthModule from "../src/module.ts";
import { reauthsWith } from "../src/reauths.ts";

const setUp = () => {
	let now = 1_000_000;
	const stand = memoryRecords<StoredReauth>(() => now, { shards: 1, perShard: 1 });
	const store = { save: stand.records.create, update: stand.records.change };
	const reauths = reauthsWith({
		store,
		clock: { now: () => now },
		random: { bytes: (n) => randomBytes(n) },
	});
	return {
		reauths,
		store,
		advance: (ms: number) => {
			now += ms;
		},
	};
};
const params = (pairs: Record<string, string>) => new Map(Object.entries(pairs));

describe("re-authentication records", () => {
	it("names a record by 32 random bytes and takes it once, for the request it was made for", async () => {
		const { reauths } = setUp();
		const asked = params({ client_id: "app", prompt: "login" });
		const name = await reauths.remember(asked, 5);
		expect(name).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect((await reauths.take(name, asked))?.at).toBe(5);
		expect(await reauths.take(name, asked)).toBeUndefined();
	});

	it("hashes the request apart from its own name, in any order of parameters and of prompt words", async () => {
		const { reauths } = setUp();
		const name = await reauths.remember(params({ a: "1", prompt: "login consent" }), 5);
		const same = params({ reauth: name, prompt: "consent login login", a: "1" });
		expect(await reauths.take(name, same)).toBeDefined();
	});

	it("takes nothing for another request, and spends the record all the same", async () => {
		const { reauths } = setUp();
		const asked = params({ a: "1" });
		const name = await reauths.remember(asked, 5);
		expect(await reauths.take(name, params({ a: "2" }))).toBeUndefined();
		expect(await reauths.take(name, asked)).toBeUndefined();
	});

	it("looks up no name that is not 43 base64url characters, and none past ten minutes", async () => {
		const { reauths, advance } = setUp();
		expect(await reauths.take("short", params({}))).toBeUndefined();
		expect(await reauths.take(undefined, params({}))).toBeUndefined();
		const name = await reauths.remember(params({}), 5);
		advance(600_000);
		expect(await reauths.take(name, params({}))).toBeUndefined();
	});

	it("reads a record of another format or shape as none", async () => {
		const { reauths, store } = setUp();
		const name = "x".repeat(43);
		await store.save(name, { format: 2, at: 5, request: "r" } as unknown as StoredReauth, 60_000);
		expect(await reauths.take(name, params({}))).toBeUndefined();
	});

	it("is unavailable when the new name is held already", async () => {
		const { reauths, store } = setUp();
		const held = { save: async () => "exists" as const, update: store.update };
		const clashing = reauthsWith({
			store: held,
			clock: { now: () => 0 },
			random: { bytes: (n) => new Uint8Array(n) },
		});
		await expect(clashing.remember(params({}), 5)).rejects.toBeInstanceOf(Unavailable);
		expect(reauths).toBeDefined();
	});

	it("counts a login fresh at the record's moment or later, and an unknown time never", async () => {
		const { reauths, advance } = setUp();
		const taken = { format: 1, at: 2_000, request: "r" } as const;
		const login = { login: true, maxAgeMs: undefined, knownTime: false };
		expect(reauths.fresh(login, { authenticatedAt: 2_000 }, taken)).toBe(true);
		expect(reauths.fresh(login, { authenticatedAt: 1_999 }, taken)).toBe(false);
		expect(reauths.fresh(login, { authenticatedAt: 2_000 }, undefined)).toBe(false);
		const unknown = { authenticatedAt: 3_000, authenticatedAtUnknown: true } as const;
		expect(reauths.fresh(login, unknown, taken)).toBe(false);
		const knownTime = { login: false, maxAgeMs: undefined, knownTime: true };
		expect(reauths.fresh(knownTime, unknown, undefined)).toBe(false);
		expect(reauths.fresh(knownTime, { authenticatedAt: 0 }, undefined)).toBe(true);
		const maxAge = { login: false, maxAgeMs: 1_000, knownTime: false };
		expect(reauths.fresh(maxAge, { authenticatedAt: 999_000 }, undefined)).toBe(true);
		advance(1);
		expect(reauths.fresh(maxAge, { authenticatedAt: 999_000 }, undefined)).toBe(false);
	});
});

it("provides the records over the store the assembly wires, taking all it names", async () => {
	const stand = memoryRecords<StoredReauth>(() => 0, { shards: 1, perShard: 1 });
	const place = defineModule({ name: "reauth-place", takes: [] }, (m) => [
		m.provide(reauthStore).by(() => ({ save: stand.records.create, update: stand.records.change })),
	]);
	const input = { modules: [reauthModule, place], config: kernelConfig() };
	expect(await takesUnused(input)).toEqual({});
	const app = await assemble(input);
	const records = app.get(reauths);
	const name = await records.remember(params({ a: "1" }), 5);
	expect((await records.take(name, params({ a: "1" })))?.at).toBe(5);
});
