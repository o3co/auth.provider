import { createHash, randomBytes } from "node:crypto";
import { expect, it } from "vitest";
import { memoryStores, writeToken } from "../../../test/stores.ts";
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

it("lists a subject's passkeys with their names and when they were registered, a record from before with no time", async () => {
	const { stores, records, credentialFor } = kept(() => 5_000);
	const [a, b] = [fresh(), fresh()];
	expect(await records.register("sam", await credentialFor("sam", a), 10, "laptop")).toBe(
		"registered",
	);
	expect(await records.register("sam", await credentialFor("sam", b), 10)).toBe("registered");
	// A record written before registration times were kept.
	const { v, subject, publicKey, signCount, backupEligible, backedUp } = {
		v: 1,
		subject: "sam",
		...(await credentialFor("sam", b)),
	};
	await stores.passkeys.credentials.update(
		`c-${createHash("sha256").update(b).digest("base64url")}`,
		() => ({ value: { v, subject, publicKey, signCount, backupEligible, backedUp } as never }),
	);
	expect(await records.listed("sam")).toEqual([
		{ id: a, nickname: "laptop", backupEligible: false, backedUp: false, at: 5_000 },
		{ id: b, backupEligible: false, backedUp: false },
	]);
	expect(await records.listed("kim")).toEqual([]);
});

it("renames only a passkey the subject holds", async () => {
	const { records, credentialFor } = kept();
	const id = fresh();
	await records.register("sam", await credentialFor("sam", id), 10);
	expect(await records.renamed("sam", id, "phone")).toBe("renamed");
	expect((await records.listed("sam"))[0]?.nickname).toBe("phone");
	expect(await records.renamed("kim", id, "mine")).toBe("unknown");
	expect(await records.renamed("sam", fresh(), "none")).toBe("unknown");
	expect((await records.listed("sam"))[0]?.nickname).toBe("phone");
});

it("reads a holder 0.18 kept, with no fence, at fence 0", async () => {
	const { stores, records } = kept();
	const handle = fresh();
	await stores.backTo("sam", { v: 1, handle, credentials: [] });
	expect(await records.holder("sam")).toEqual({ handle, credentials: [], fence: 0 });
});
