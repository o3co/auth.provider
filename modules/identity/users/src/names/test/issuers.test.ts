import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import secretHashModule from "@mod/secret-hash/module";
import { describe, expect, it, vi } from "vitest";
import { type Ledger, type LinkStore, ledgers, upstreamNames, users } from "../../contract.ts";
import usersModule from "../../module.ts";
import { memoryUsersStores } from "../../testing.ts";

const issuerA = "https://a.example";
const issuerB = "https://b.example";
const issuerC = "https://c.example";

/** A module declaring the names, each with its issuer. */
const declaring = (declaredBy: string, names: Readonly<Record<string, string>>): Module =>
	defineModule({ name: `declares-${declaredBy}`, replicaSafe: true, takes: [] }, (m) => [
		m.contribute(upstreamNames).by(() => ({
			declaredBy,
			names: Object.entries(names).map(([name, issuer]) => ({ name, issuer })),
		})),
	]);

interface Boot {
	readonly names?: Readonly<Record<string, string>>;
	readonly moved?: readonly { idp: string; from: string; to: string }[];
	readonly more?: readonly Module[];
}

/** Boots users on the stores; answers its warnings, or the refusals it was refused with. */
async function boot(stores: ReturnType<typeof memoryUsersStores>, b: Boot = {}) {
	const recorded = recordingLog();
	const assembled = assemble({
		modules: [
			usersModule,
			secretHashModule,
			stores.module,
			declaring("federation", b.names ?? { corp: issuerA }),
			...(b.more ?? []),
		],
		config: { ...kernelConfig(), users: { "issuer-moved": b.moved ?? [] } },
		runtime: quietRuntime({ log: recorded.log }),
	});
	const warnings = () =>
		recorded
			.lines()
			.filter((line) => line.level === "warn")
			.map((line) => [line.event, line.fields]);
	return assembled.then(
		(assembly) => ({ refusals: undefined, warnings: warnings(), assembly }),
		(error: unknown) => {
			if (!BootRefused.is(error)) throw error;
			return { refusals: error.refusals, warnings: warnings(), assembly: undefined };
		},
	);
}

const refusedAs = (by: string) => [
	{
		where: "users",
		reason: `an IdP name stands for another issuer than the one kept for it, as ${by} it: use a new name, or state the move in users.issuer-moved`,
	},
];
const nameKey = (name: string) => JSON.stringify({ idp: name });
const issuerKept = (stores: ReturnType<typeof memoryUsersStores>, name: string) =>
	stores.links.store.read(nameKey(name));

describe("an IdP name's issuer, across boots", () => {
	it("is kept once at the first boot, and an unchanged one boots again with no warning and no write", async () => {
		const stores = memoryUsersStores();
		const save = vi.spyOn(stores.links.store, "save");
		const update = vi.spyOn(stores.links.store, "update");
		expect((await boot(stores)).warnings).toEqual([]);
		expect(await issuerKept(stores, "corp")).toEqual({ issuer: issuerA });
		expect(save).toHaveBeenCalledTimes(1);
		save.mockClear();
		update.mockClear();
		const again = await boot(stores);
		expect([again.refusals, again.warnings]).toEqual([undefined, []]);
		expect(save).not.toHaveBeenCalled();
		expect(update).not.toHaveBeenCalled();
	});

	it("is kept under a key no link's can be, whatever the name holds", async () => {
		const stores = memoryUsersStores();
		const { assembly } = await boot(stores, {
			names: { corp: issuerA, '{"idp":"corp"}': issuerB },
		});
		const people = assembly?.get(users);
		for (const subject of ["corp", '{"idp":"corp"}', "idp"]) {
			expect(await people?.byUpstream("corp", subject)).toEqual({ kind: "none" });
			expect(await stores.links.store.read(JSON.stringify(["corp", subject]))).toBeUndefined();
		}
		expect(await issuerKept(stores, "corp")).toEqual({ issuer: issuerA });
	});

	it("refuses another issuer under the name, naming the declaring module and no value, leaving what is kept", async () => {
		const stores = memoryUsersStores();
		await boot(stores);
		const refused = await boot(stores, { names: { corp: issuerB } });
		expect(refused.refusals).toEqual(refusedAs("federation declares"));
		for (const value of [issuerA, issuerB, "corp"]) {
			expect(JSON.stringify(refused.refusals)).not.toContain(value);
		}
		expect(await issuerKept(stores, "corp")).toEqual({ issuer: issuerA });
	});

	it("refuses it naming every module that declares the name", async () => {
		const stores = memoryUsersStores();
		await boot(stores);
		const refused = await boot(stores, {
			names: { corp: issuerB },
			more: [declaring("jwt-bearer-users", { corp: issuerB })],
		});
		expect(refused.refusals).toEqual(refusedAs("federation, jwt-bearer-users declare"));
	});

	it("writes nothing of a boot it refuses, a new name beside the refused one included", async () => {
		const stores = memoryUsersStores();
		await boot(stores);
		const refused = await boot(stores, { names: { corp: issuerB, other: issuerC } });
		expect(refused.refusals).toHaveLength(1);
		expect(await issuerKept(stores, "other")).toBeUndefined();
	});

	it("takes a new name for the new issuer, which the old name's links do not reach", async () => {
		const stores = memoryUsersStores();
		const first = await boot(stores);
		await first.assembly?.get(users).link("s-1", { idp: "corp", subject: "jdoe" });
		const { refusals, assembly } = await boot(stores, { names: { "corp-b": issuerB } });
		expect(refusals).toBeUndefined();
		expect(await assembly?.get(users).byUpstream("corp-b", "jdoe")).toEqual({ kind: "none" });
	});

	it("refuses another issuer for a ledger too, which is asked for no one", async () => {
		const byUpstream = vi.fn<NonNullable<Ledger["byUpstream"]>>(async () => ({ kind: "none" }));
		const ledger = defineModule({ name: "a-ledger", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(ledgers).by(() => ({
				verify: async () => ({ kind: "none" }),
				bySubject: async () => ({ kind: "none" }),
				byUpstream,
			})),
		]);
		const stores = memoryUsersStores();
		await boot(stores, { more: [ledger] });
		expect(await issuerKept(stores, "corp")).toEqual({ issuer: issuerA });
		const refused = await boot(stores, { names: { corp: issuerB }, more: [ledger] });
		expect(refused.refusals).toEqual(refusedAs("federation declares"));
		expect(byUpstream).not.toHaveBeenCalled();
	});

	it("refuses boot where the store cannot answer, never reading that as no record", async () => {
		for (const method of ["read", "save"] as const) {
			const stores = memoryUsersStores();
			vi.spyOn(stores.links.store, method).mockRejectedValue(new Unavailable("store"));
			const refused = await boot(stores);
			expect(refused.refusals).toEqual([
				{
					where: "users",
					reason: "the link store cannot answer for the issuers IdP names stand for",
				},
			]);
		}
	});

	it("takes the record of whichever instance saved first, refusing another issuer in it", async () => {
		const stores = memoryUsersStores();
		await boot(stores);
		const { read } = stores.links.store;
		// Reads none, as an instance does just before another saves.
		vi.spyOn(stores.links.store, "read").mockImplementationOnce(async () => undefined);
		const refused = await boot(stores, { names: { corp: issuerB } });
		expect(refused.refusals).toEqual(refusedAs("federation declares"));
		expect(await read(nameKey("corp"))).toEqual({ issuer: issuerA });
		// The same issuer is no difference.
		vi.spyOn(stores.links.store, "read").mockImplementationOnce(async () => undefined);
		expect((await boot(stores)).refusals).toBeUndefined();
	});

	it("reads a record of another shape as a difference, never as none", async () => {
		const stores = memoryUsersStores();
		const held = { issuer: 7 } as unknown as Parameters<LinkStore["save"]>[1];
		await stores.links.store.save(nameKey("corp"), held, "endless");
		expect((await boot(stores)).refusals).toEqual(refusedAs("federation declares"));
	});
});

describe("a boot another module refuses", () => {
	const refusing = defineModule({ name: "refusing", replicaSafe: true, takes: [] }, (m) => [
		m.provide(contract<void>("refused")).by((c) => c.refuse("refusing", "refused on purpose")),
	]);
	const refusedOnPurpose = [{ where: "refusing", reason: "refused on purpose" }];
	const stated = { idp: "corp", from: issuerA, to: issuerB };

	it("leaves the record and a stated move as they were, and a boot back on the old issuer succeeds", async () => {
		const stores = memoryUsersStores();
		await boot(stores);
		const refused = await boot(stores, {
			names: { corp: issuerB },
			moved: [stated],
			more: [refusing],
		});
		expect(refused.refusals).toEqual(refusedOnPurpose);
		expect(refused.warnings).toEqual([]);
		expect(await issuerKept(stores, "corp")).toEqual({ issuer: issuerA });
		expect((await boot(stores)).refusals).toBeUndefined();
		expect(await issuerKept(stores, "corp")).toEqual({ issuer: issuerA });
	});

	it("keeps no entry first seen, which is kept once a boot succeeds", async () => {
		const stores = memoryUsersStores();
		const refused = await boot(stores, { more: [refusing] });
		expect(refused.refusals).toEqual(refusedOnPurpose);
		expect(await issuerKept(stores, "corp")).toBeUndefined();
		expect((await boot(stores)).refusals).toBeUndefined();
		expect(await issuerKept(stores, "corp")).toEqual({ issuer: issuerA });
	});
});

describe("what a boot writes of a name's issuer, once no module refuses it", () => {
	it("refuses a difference another instance wrote since it judged, leaving that instance's", async () => {
		const stores = memoryUsersStores();
		await boot(stores);
		stores.links.raceNextUpdate(nameKey("corp"), () => ({ issuer: issuerC }) as never);
		const refused = await boot(stores, {
			names: { corp: issuerB },
			moved: [{ idp: "corp", from: issuerA, to: issuerB }],
		});
		expect(refused.refusals).toEqual(refusedAs("federation declares"));
		expect(refused.warnings).toEqual([]);
		expect(await issuerKept(stores, "corp")).toEqual({ issuer: issuerC });
	});

	it("refuses boot where the store cannot answer the write, never reading that as kept", async () => {
		const stores = memoryUsersStores();
		vi.spyOn(stores.links.store, "update").mockRejectedValueOnce(new Unavailable("store"));
		const refused = await boot(stores);
		expect(refused.refusals).toEqual([
			{
				where: "users",
				reason: "the link store cannot answer for the issuers IdP names stand for",
			},
		]);
	});
});

describe("a stated move of a name's issuer", () => {
	const move = { idp: "corp", from: issuerA, to: issuerB };

	it("rewrites what is kept and warns, naming the entry and no issuer", async () => {
		const stores = memoryUsersStores();
		await boot(stores);
		const moved = await boot(stores, { names: { corp: issuerB }, moved: [move] });
		expect(moved.refusals).toBeUndefined();
		expect(moved.warnings).toEqual([["users.issuer_moved", { idp: "corp" }]]);
		expect(await issuerKept(stores, "corp")).toEqual({ issuer: issuerB });
	});

	it("once applied boots again with the warning while it is listed, and with none once it is taken out", async () => {
		const stores = memoryUsersStores();
		await boot(stores);
		await boot(stores, { names: { corp: issuerB }, moved: [move] });
		const update = vi.spyOn(stores.links.store, "update");
		const applied = await boot(stores, { names: { corp: issuerB }, moved: [move] });
		expect(applied.refusals).toBeUndefined();
		expect(applied.warnings).toEqual([["users.issuer_moved", { idp: "corp" }]]);
		expect(update).not.toHaveBeenCalled();
		const after = await boot(stores, { names: { corp: issuerB } });
		expect([after.refusals, after.warnings]).toEqual([undefined, []]);
	});

	it("lets one instance's write stand where another moved it first", async () => {
		const stores = memoryUsersStores();
		await boot(stores);
		vi.spyOn(stores.links.store, "read").mockImplementationOnce(
			async () =>
				({
					issuer: issuerA,
				}) as never,
		);
		stores.links.raceNextUpdate(nameKey("corp"), () => ({ issuer: issuerB }) as never);
		const moved = await boot(stores, { names: { corp: issuerB }, moved: [move] });
		expect(moved.refusals).toBeUndefined();
		expect(await issuerKept(stores, "corp")).toEqual({ issuer: issuerB });
	});

	it("refuses an entry matching neither, at its key and with no value, leaving what is kept", async () => {
		const entries = [
			{ names: { corp: issuerB }, moved: [{ ...move, from: issuerC }] },
			{ names: { corp: issuerC }, moved: [move] },
			{ names: { corp: issuerA }, moved: [move] },
			{ names: { corp: issuerA }, moved: [{ ...move, idp: "nobody" }] },
		];
		for (const entry of entries) {
			const stores = memoryUsersStores();
			await boot(stores);
			const refused = await boot(stores, entry);
			expect(refused.refusals).toContainEqual({
				where: "users.issuer-moved.0",
				reason:
					"the issuer kept for this IdP and the one declared are neither its from and to, nor both its to",
			});
			for (const value of [issuerA, issuerB, issuerC, "corp", "nobody"]) {
				expect(JSON.stringify(refused.refusals)).not.toContain(value);
			}
			expect(await issuerKept(stores, "corp")).toEqual({ issuer: issuerA });
		}
	});

	it("refuses an entry where nothing is kept for its IdP, writing nothing", async () => {
		const stores = memoryUsersStores();
		const refused = await boot(stores, { names: { corp: issuerB }, moved: [move] });
		expect(refused.refusals?.map((r) => r.where)).toEqual(["users.issuer-moved.0"]);
		expect(await issuerKept(stores, "corp")).toBeUndefined();
	});
});
