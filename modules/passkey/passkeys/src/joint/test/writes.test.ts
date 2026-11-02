import { randomBytes } from "node:crypto";
import { isUnavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { heldState, memoryStores, writeToken } from "../../../test/stores.ts";
import { keptPasskeys } from "../../records.ts";

const fresh = () => randomBytes(32).toString("base64url");

/** Passkey records over memory stores, and a credential for `subject` under its handle. */
function kept(now: () => number = () => 1_000) {
	const stores = memoryStores();
	const records = keptPasskeys(stores.passkeys, writeToken, now);
	const credentialFor = async (subject: string, id: string) => ({
		id,
		publicKey: "pQ",
		signCount: 0,
		userHandle: await records.handleFor(subject, fresh()),
		backupEligible: false,
		backedUp: false,
	});
	return { stores, records, credentialFor };
}

it("leaves no id taken for good when the store fails as a registration writes", async () => {
	const { stores, records, credentialFor } = await kept();
	const id = fresh();
	const sams = await credentialFor("sam", id);
	stores.down.together.failNext("updateTogether");
	await expect(records.register("sam", sams, 10)).rejects.toSatisfy(isUnavailable);
	// Nothing of it, read raw before any later registration writes.
	expect(await heldState(stores.passkeys, ["sam", "kim"], [id])).toEqual({
		lists: { sam: [], kim: [] },
		records: { [id]: undefined },
	});
	expect(await records.register("kim", await credentialFor("kim", id), 10)).toBe("registered");
	expect((await records.passkey(id))?.subject).toBe("kim");
	expect((await records.holder("sam"))?.credentials).toEqual([]);
});

it("leaves no id taken for good when another registration takes the subject's last place first", async () => {
	const { stores, records, credentialFor } = await kept();
	const [id, other] = [fresh(), fresh()];
	const sams = await credentialFor("sam", id);
	// Another of sam's registrations takes the last place once this one has read and decided.
	stores.raceNextTogether(async () => {
		expect(await records.register("sam", await credentialFor("sam", other), 1)).toBe("registered");
	});
	expect(await records.register("sam", sams, 1)).toBe("full");
	// Only the registration that took the place, read raw before any later registration writes.
	expect(await heldState(stores.passkeys, ["sam", "kim"], [id, other])).toEqual({
		lists: { sam: [other], kim: [] },
		records: { [id]: undefined, [other]: { subject: "sam", as: "passkey" } },
	});
	expect(await records.register("kim", await credentialFor("kim", id), 1)).toBe("registered");
	expect((await records.passkey(id))?.subject).toBe("kim");
});

it("keeps a listed credential its holder's", async () => {
	const { records, credentialFor } = await kept();
	const id = fresh();
	expect(await records.register("sam", await credentialFor("sam", id), 10)).toBe("registered");
	expect(await records.register("kim", await credentialFor("kim", id), 10)).toBe("conflict");
	expect((await records.passkey(id))?.subject).toBe("sam");
});

it("refuses a credential it could not read back, writing nothing", async () => {
	const { records, credentialFor } = await kept();
	const cases: Record<string, object> = {
		"a public key over 4096 bytes": { publicKey: Buffer.alloc(4097).toString("base64url") },
		"transports not all strings": { transports: [1] },
	};
	for (const [name, over] of Object.entries(cases)) {
		const id = fresh();
		const credential = { ...(await credentialFor("sam", id)), ...over } as never;
		expect(await records.register("sam", credential, 10), name).toBe("malformed");
		expect(await records.passkey(id), name).toBeUndefined();
	}
});

it("removes a passkey from its holder, telling when none is left, and strips its record so nothing reads it as a key", async () => {
	const { records, credentialFor } = kept();
	const [a, b] = [fresh(), fresh()];
	await records.register("sam", await credentialFor("sam", a), 10);
	await records.register("sam", await credentialFor("sam", b), 10);
	const judged = { ...(await credentialFor("sam", a)) };
	expect(await records.removed("sam", a)).toEqual({ removed: true, empty: false });
	expect(await records.passkey(a)).toBeUndefined();
	expect(
		await records.count({ subject: "sam", credential: judged }, { ...judged, signCount: 1 }),
	).toBe("raced");
	expect(await records.removed("sam", b)).toMatchObject({ removed: true, empty: true });
	expect(await records.removed("sam", b)).toEqual({ removed: false, empty: true });
	expect(await records.listed("sam")).toEqual([]);
	// The handle stays; a removed id is taken over by a new registration, as one no holder lists.
	expect((await records.holder("sam"))?.credentials).toEqual([]);
	expect(await records.register("kim", await credentialFor("kim", a), 10)).toBe("registered");
	expect((await records.passkey(a))?.subject).toBe("kim");
});

it("never strips a record another subject holds, though the call names its id", async () => {
	const { records, credentialFor } = kept();
	const id = fresh();
	await records.register("kim", await credentialFor("kim", id), 10);
	expect(await records.removed("sam", id)).toEqual({ removed: false, empty: true });
	expect((await records.passkey(id))?.subject).toBe("kim");
});
