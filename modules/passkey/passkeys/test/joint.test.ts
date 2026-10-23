import { randomBytes } from "node:crypto";
import { isUnavailable, Unavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { jointStores } from "./stores.ts";

const fresh = () => randomBytes(32).toString("base64url");

it("writes a registration's record and listing as one, deciding again on a race, its token made once", async () => {
	const t = jointStores();
	const [first, second] = [await t.credentialFor("sam"), await t.credentialFor("sam")];
	// Another of sam's registrations lands once this one has read and decided.
	t.stores.raceNextTogether(async () => {
		expect(await t.records.register("sam", second, 10)).toBe("registered");
	});
	expect(await t.records.register("sam", first, 10)).toBe("registered");
	// One token for each registration; the raced one decided twice, the other once.
	expect(t.counted).toMatchObject({ together: 2, decisions: 3, tokens: 2 });
	expect(await t.listOf("sam")).toEqual([second.id, first.id]);
	for (const c of [first, second]) expect((await t.records.passkey(c.id))?.subject).toBe("sam");
});

it("answers a clear by what its last decision took off, deciding again on a race", async () => {
	const t = jointStores();
	const [a, b, c] = [
		await t.credentialFor("sam"),
		await t.credentialFor("sam"),
		await t.credentialFor("sam"),
	];
	for (const kept of [a, b]) expect(await t.records.register("sam", kept, 10)).toBe("registered");
	// A third registration lands once the clear has read and decided: the clear takes it too.
	t.stores.raceNextTogether(async () => {
		expect(await t.records.register("sam", c, 10)).toBe("registered");
	});
	const before = t.counted.decisions;
	expect((await t.records.cleared("sam", fresh())).removed).toBe(3);
	// The clear decided twice, the registration between once.
	expect(t.counted.decisions - before).toBe(3);
	expect(await t.listOf("sam")).toEqual([]);
	for (const kept of [a, b, c]) expect(await t.records.passkey(kept.id)).toBeUndefined();
});

it("leaves no passkey off its list where an activation lands as a clear writes and the clear fails", async () => {
	const t = jointStores();
	const c = await t.credentialFor("sam");
	expect(await t.records.joined("sam", c, 10, undefined, "t-pending")).toBe("written");
	// Once the clear has read and decided, the registration's activation lands, then the clear's write fails.
	let landed = false;
	t.stores.raceNextTogether(async () => {
		landed = true;
		expect(await t.records.activated(c.id, "t-pending")).toBe("activated");
		throw new Unavailable("passkeys");
	});
	await expect(t.records.cleared("sam", fresh())).rejects.toSatisfy(isUnavailable);
	expect(landed).toBe(true);
	expect(await t.agreed("sam", c.id)).toBe(true);
});

it("ends nothing of a registration that replaced the ended one's, of the subject or of another", async () => {
	for (const replacing of ["sam", "kim"]) {
		const t = jointStores();
		const id = (await t.credentialFor("sam")).id;
		expect(
			await t.records.joined("sam", await t.credentialFor("sam", id), 10, undefined, "t-one"),
		).toBe("written");
		// A removal takes the pending one; another registration then keeps the id.
		expect(await t.records.removed("sam", id)).toMatchObject({ removed: true, empty: true });
		const theirs = await t.credentialFor(replacing, id);
		expect(await t.records.register(replacing, theirs, 10), replacing).toBe("registered");
		const before = { ...t.counted };
		expect(await t.records.ended("sam", id, "t-one"), replacing).toMatchObject({ removed: false });
		expect([t.counted.together - before.together, t.counted.single - before.single]).toEqual([
			1, 0,
		]);
		expect(await t.listOf(replacing), replacing).toEqual([id]);
		expect((await t.records.passkey(id))?.subject, replacing).toBe(replacing);
	}
});

it("removes in one change: a passkey or a pending one with its record, and an old entry freeing its slot alone", async () => {
	const t = jointStores();
	const live = await t.credentialFor("sam");
	expect(await t.records.register("sam", live, 10)).toBe("registered");
	const pending = await t.credentialFor("sam");
	expect(await t.records.joined("sam", pending, 10, undefined, "t-pending")).toBe("written");
	// Entries 0.18 left: for a removed record, for none, and for kim's listed passkey.
	const [stripped, absent] = [(await t.credentialFor("sam")).id, (await t.credentialFor("sam")).id];
	await t.keepAs(stripped, { v: 1, subject: "sam", removed: true });
	expect([await t.recordOf(stripped), await t.recordOf(absent)]).toEqual([
		{ v: 1, subject: "sam", removed: true },
		undefined,
	]);
	const kims = await t.credentialFor("kim");
	expect(await t.records.register("kim", kims, 10)).toBe("registered");
	await t.listAs18("sam", [live.id, pending.id, stripped, absent, kims.id]);
	for (const id of [live.id, pending.id, stripped, absent, kims.id]) {
		const before = { ...t.counted };
		expect((await t.records.removed("sam", id)).removed, id).toBe(true);
		expect([t.counted.together - before.together, t.counted.single - before.single]).toEqual([
			1, 0,
		]);
	}
	expect(await t.listOf("sam")).toEqual([]);
	for (const id of [live.id, pending.id]) {
		expect(await t.recordOf(id)).toEqual({ v: 1, subject: "sam", removed: true });
	}
	// The pending one's registration finds it gone; kim's passkey stays.
	expect(await t.records.activated(pending.id, "t-pending")).toBe("taken");
	expect((await t.records.passkey(kims.id))?.subject).toBe("kim");
});

it("clears a list of 100 and every record of the subject it names in one change, leaving another's", async () => {
	const t = jointStores();
	const ids: string[] = [];
	for (let n = 0; n < 100; n++) {
		const c = await t.credentialFor("sam");
		expect(await t.records.register("sam", c, 100)).toBe("registered");
		ids.push(c.id);
	}
	const kims = await t.credentialFor("kim");
	expect(await t.records.register("kim", kims, 10)).toBe("registered");
	await t.listAs18("sam", [...ids, kims.id]);
	const before = { ...t.counted };
	expect((await t.records.cleared("sam", fresh())).removed).toBe(101);
	expect([t.counted.together - before.together, t.counted.single - before.single]).toEqual([1, 0]);
	expect(await t.listOf("sam")).toEqual([]);
	for (const id of ids)
		expect(await t.recordOf(id)).toEqual({ v: 1, subject: "sam", removed: true });
	expect((await t.records.passkey(kims.id))?.subject).toBe("kim");
});

it("leaves everything as it was where a clear fails", async () => {
	const t = jointStores();
	const [a, b] = [await t.credentialFor("sam"), await t.credentialFor("sam")];
	for (const c of [a, b]) expect(await t.records.register("sam", c, 10)).toBe("registered");
	t.stores.down.together.failNext("updateTogether");
	await expect(t.records.cleared("sam", fresh())).rejects.toSatisfy(isUnavailable);
	expect(await t.listOf("sam")).toEqual([a.id, b.id]);
	for (const c of [a, b]) expect((await t.records.passkey(c.id))?.subject).toBe("sam");
});

it("judges a full list and an id its holder lists in the one change, writing nothing", async () => {
	const t = jointStores();
	const [first, other] = [await t.credentialFor("sam"), await t.credentialFor("sam")];
	expect(await t.records.register("sam", first, 1)).toBe("registered");
	const kims = await t.credentialFor("kim", first.id);
	const before = { ...t.counted };
	expect(await t.records.register("sam", other, 1)).toBe("full");
	expect(await t.records.register("kim", kims, 10)).toBe("conflict");
	expect([t.counted.together - before.together, t.counted.single - before.single]).toEqual([2, 0]);
	expect(await t.recordOf(other.id)).toBeUndefined();
	expect((await t.records.passkey(first.id))?.subject).toBe("sam");
});

it("takes over a record 0.18 left on no list, and mends an old entry once the record's holder lists it no longer", async () => {
	const t = jointStores();
	// A 0.18 registration failed between its writes: kim's live record, on no list.
	const orphan = (await t.credentialFor("kim")).id;
	await t.orphanAs18(orphan, "kim");
	expect(await t.records.register("sam", await t.credentialFor("sam", orphan), 10)).toBe(
		"registered",
	);
	expect((await t.records.passkey(orphan))?.subject).toBe("sam");
	// 0.18 left sam's list naming kim's listed id: it counts toward sam's limit.
	const kims = await t.credentialFor("kim");
	expect(await t.records.register("kim", kims, 10)).toBe("registered");
	await t.listAs18("sam", [kims.id]);
	expect(await t.records.register("sam", await t.credentialFor("sam"), 1)).toBe("full");
	// While kim lists it, neither sam nor another subject takes it.
	for (const subject of ["sam", "lee"]) {
		const asked = await t.credentialFor(subject, kims.id);
		expect(await t.records.register(subject, asked, 10), subject).toBe("conflict");
	}
	// Once kim lists it no longer, sam registering it again uses the old entry, listed once.
	expect(await t.records.removed("kim", kims.id)).toMatchObject({ removed: true, empty: true });
	expect(await t.records.register("sam", await t.credentialFor("sam", kims.id), 10)).toBe(
		"registered",
	);
	expect(await t.listOf("sam")).toEqual([kims.id]);
	expect((await t.records.passkey(kims.id))?.subject).toBe("sam");
});
