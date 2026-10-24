import { randomBytes } from "node:crypto";
import { expect, it } from "vitest";
import { memoryStores, writeToken } from "../../../test/stores.ts";
import { keptPasskeys } from "../../records.ts";
import { holdersOver } from "../holders.ts";

const fresh = () => randomBytes(32).toString("base64url");

/** Holdings over memory stores with no witnessing contributed. */
function held() {
	const stores = memoryStores();
	const records = keptPasskeys(stores.passkeys, writeToken, () => 1_000);
	const { holders, settle } = holdersOver({ records, witnessing: undefined, handle: fresh });
	const register = async (subject: string, id = fresh()) => {
		const credential = {
			id,
			publicKey: "pQ",
			signCount: 0,
			userHandle: await records.handleFor(subject, fresh()),
			backupEligible: false,
			backedUp: false,
		};
		expect(await records.register(subject, credential, 10)).toBe("registered");
		await settle(subject, "registration");
		return id;
	};
	const remove = async (subject: string, id: string) => {
		await settle(subject, "removal", (await records.removed(subject, id)).emptied);
	};
	return { stores, records, holders, register, remove };
}

it("tells holding from the passkeys alone without a witnessing, settling nothing", async () => {
	const { holders, register, remove } = held();
	expect(holders.witnessed).toBe(false);
	expect(await holders.held("sam")).toBe(false);
	const id = await register("sam");
	expect(await holders.held("sam")).toBe(true);
	await remove("sam", id);
	expect(await holders.held("sam")).toBe(false);
});

it("ends every passkey on a reset, counting them, and makes the holder anew for a subject that has none", async () => {
	const { stores, records, holders, register } = held();
	await register("sam");
	await register("sam");
	expect(await holders.cleared("sam")).toEqual({ removed: 2 });
	expect(await holders.held("sam")).toBe(false);
	// A store that lost the subject's holder: the reset makes it anew, as a repair needs.
	const lost = (await records.holder("sam"))?.handle;
	await stores.lose.holder("sam");
	expect(await holders.cleared("sam")).toEqual({ removed: 0 });
	const holder = await records.holder("sam");
	expect(holder?.credentials).toEqual([]);
	expect(holder?.handle).not.toBe(lost);
});
