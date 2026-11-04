import type { Client } from "@mod/clients";
import { memoryRecords } from "@mod/records/testing";
import { describe, expect, it } from "vitest";
import { clientSection } from "../../client-section.ts";
import type { StoredGrant } from "../../store.ts";
import { grantsWith } from "../grants.ts";

const clientOf = (registered: boolean, under?: string): Client => ({
	id: "c",
	kind: "public",
	method: "none",
	registered,
	section: <T>(section: { name: string }) =>
		(section.name === clientSection.name ? { "first-party": false, under } : {}) as T,
});
const fromSource = (under?: string) => clientOf(false, under);
const registered = clientOf(true);
const key = JSON.stringify(["alice", "c"]);

function over() {
	const stand = memoryRecords<StoredGrant>(() => 0, { shards: 1, perShard: 1 });
	const store = {
		save: stand.records.create,
		read: stand.records.read,
		update: stand.records.change,
	};
	const held = (record: unknown) => store.save(key, record as StoredGrant, "endless");
	return { stand, store, held, grants: grantsWith({ store }) };
}

describe("grants: a client the operator registered", () => {
	it("counts a grant of any format it reads, and writes format 2 with no value, as a union", async () => {
		for (const record of [
			["read"],
			{ format: 2, range: ["read"] },
			{ format: 2, range: ["read"], under: "d1" },
		]) {
			const { grants, held, store } = over();
			await held(record);
			expect(await grants.rangeFor(registered, "alice"), JSON.stringify(record)).toEqual(["read"]);
			expect(await grants.covers(registered, "alice", ["read"])).toBe(true);
			await grants.grant(registered, "alice", ["write"]);
			expect(await store.read(key)).toEqual({ format: 2, range: ["read", "write"] });
		}
	});
});

describe("grants: a client from another source", () => {
	it("counts only a grant held under what its section says now", async () => {
		const { grants, held } = over();
		await held({ format: 2, range: ["read"], under: "d1" });
		expect(await grants.rangeFor(fromSource("d1"), "alice")).toEqual(["read"]);
		expect(await grants.covers(fromSource("d1"), "alice", ["read"])).toBe(true);
		expect(await grants.covers(fromSource("d1"), "alice", [])).toBe(true);
		expect(await grants.rangeFor(fromSource("d2"), "alice")).toEqual([]);
		expect(await grants.covers(fromSource("d2"), "alice", ["read"])).toBe(false);
		expect(await grants.covers(fromSource("d2"), "alice", [])).toBe(false);
	});

	it("counts no grant from format 1, nor one held under no value, which the next grant replaces", async () => {
		for (const record of [["read"], { format: 2, range: ["read"] }]) {
			const { grants, held, store } = over();
			await held(record);
			const client = fromSource("d1");
			expect(await grants.covers(client, "alice", ["read"]), JSON.stringify(record)).toBe(false);
			expect(await grants.rangeFor(client, "alice")).toEqual([]);
			await grants.grant(client, "alice", ["write"]);
			expect(await store.read(key)).toEqual({ format: 2, range: ["write"], under: "d1" });
			expect(await grants.covers(client, "alice", ["write"])).toBe(true);
			expect(await grants.covers(client, "alice", ["read"])).toBe(false);
		}
	});

	it("adds to a grant under the same value, and replaces one under another", async () => {
		const { grants, store } = over();
		await grants.grant(fromSource("d1"), "alice", ["read"]);
		await grants.grant(fromSource("d1"), "alice", ["write"]);
		expect(await store.read(key)).toEqual({
			format: 2,
			range: ["read", "write"],
			under: "d1",
		});
		await grants.grant(fromSource("d2"), "alice", ["admin"]);
		expect(await store.read(key)).toEqual({ format: 2, range: ["admin"], under: "d2" });
	});

	it("never covers a client whose section says no value, whatever was granted", async () => {
		const { grants, held } = over();
		await held({ format: 2, range: ["read"] });
		const client = fromSource(undefined);
		expect(await grants.covers(client, "alice", ["read"])).toBe(false);
		expect(await grants.rangeFor(client, "alice")).toEqual([]);
		await grants.grant(client, "alice", ["read"]);
		expect(await grants.covers(client, "alice", ["read"])).toBe(false);
	});

	it("writes under the value given, whatever the client says by then", async () => {
		const { grants, store } = over();
		await grants.keep("c", "alice", ["read"], "d1");
		expect(await grants.covers(fromSource("d1"), "alice", ["read"])).toBe(true);
		expect(await grants.covers(fromSource("d2"), "alice", ["read"])).toBe(false);
		expect(await store.read(key)).toEqual({ format: 2, range: ["read"], under: "d1" });
	});

	it("changes in turn what a racing request wrote, by its value", async () => {
		const same = over();
		same.stand.raceNextChange(() => ({ format: 2, range: ["other"], under: "d1" }) as never);
		await same.held({ format: 2, range: ["read"], under: "d1" });
		await same.grants.grant(fromSource("d1"), "alice", ["write"]);
		expect((await same.store.read(key)) as unknown).toMatchObject({
			range: ["other", "write"],
		});
	});
});

describe("grants: a record of a format this module does not read", () => {
	const unknown = [
		{ format: 3, range: ["read"], under: "d1" },
		{ format: 1, range: ["read"] },
		{ range: ["read"] },
		{ format: "2", range: ["read"] },
		{ format: 2, range: "read" },
		{ format: 2, range: [1] },
		[1],
		"read",
		7,
		null,
	];

	it("is no grant, for any client: the user is asked", async () => {
		for (const record of unknown) {
			const { grants, stand } = over();
			stand.records.create(key, record as unknown as StoredGrant, "endless");
			const name = JSON.stringify(record);
			for (const client of [registered, fromSource("d1")]) {
				expect(await grants.covers(client, "alice", ["read"]), name).toBe(false);
				expect(await grants.covers(client, "alice", []), name).toBe(false);
				expect(await grants.rangeFor(client, "alice"), name).toEqual([]);
			}
		}
	});

	it("is replaced by the next grant, nothing of it kept", async () => {
		const { grants, held, store } = over();
		await held({ format: 3, range: ["read"], under: "d1" });
		await grants.grant(registered, "alice", ["write"]);
		expect(await store.read(key)).toEqual({ format: 2, range: ["write"] });
	});
});
