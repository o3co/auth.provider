import { randomBytes } from "node:crypto";
import { isUnavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { keptPasskeys } from "../src/records.ts";
import { memoryStores } from "./stores.ts";

const fresh = () => randomBytes(32).toString("base64url");

/** Passkey records over memory stores, and a credential for `subject` under its handle. */
function kept() {
	const stores = memoryStores();
	const records = keptPasskeys(stores.passkeys);
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

it("leaves no id taken for good when the store fails between keeping a credential and listing it", async () => {
	const { stores, records, credentialFor } = await kept();
	const id = fresh();
	const sams = await credentialFor("sam", id);
	stores.down.subjects.failNext("update");
	await expect(records.register("sam", sams, 10)).rejects.toSatisfy(isUnavailable);
	expect(await records.register("kim", await credentialFor("kim", id), 10)).toBe("registered");
	expect((await records.passkey(id))?.subject).toBe("kim");
	expect((await records.holder("sam"))?.credentials).toEqual([]);
});

it("leaves no id taken for good when another registration takes the subject's last place first", async () => {
	const { stores, records, credentialFor } = await kept();
	const [id, other] = [fresh(), fresh()];
	const sams = await credentialFor("sam", id);
	stores.raceSubjects((record) => {
		const holder = record as unknown as { credentials: string[] };
		return { ...holder, credentials: [...holder.credentials, other] } as unknown as typeof record;
	});
	expect(await records.register("sam", sams, 1)).toBe("full");
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
