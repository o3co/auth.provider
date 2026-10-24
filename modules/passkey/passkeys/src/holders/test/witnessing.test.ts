import { randomBytes } from "node:crypto";
import { recordingLog } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { memoryStores, writeToken } from "../../../test/stores.ts";
import type { AfterRemoval, Asked, PasskeyWitnessing } from "../../contract.ts";
import { keptPasskeys } from "../../records.ts";
import { holdersOver } from "../holders.ts";

const fresh = () => randomBytes(32).toString("base64url");

/** Holdings over memory stores and a witnessing that records what it is asked, answering `answer`. */
function asked(answer = true) {
	const stores = memoryStores();
	const records = keptPasskeys(stores.passkeys, writeToken, () => 1_000);
	const calls: { kind: string; at: Asked; reads: (boolean | AfterRemoval)[] }[] = [];
	let read: { holds?: () => Promise<boolean>; after?: () => Promise<AfterRemoval> } = {};
	const witnessing: PasskeyWitnessing = {
		settle: async (_, at, holds) => {
			read = { holds };
			calls.push({ kind: "settle", at, reads: [await holds()] });
			return answer;
		},
		emptied: async (_, at, after, holds) => {
			read = { holds, after };
			calls.push({ kind: "emptied", at, reads: [await after(), await holds()] });
		},
	};
	const { holders, settle } = holdersOver({
		records,
		witness: undefined,
		witnessing,
		audit: { record: () => {} },
		log: recordingLog().log,
		token: fresh,
		handle: fresh,
	});
	const register = async (subject: string) => {
		const id = fresh();
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
	return { stores, records, holders, calls, register, remove, read: () => read };
}

it("asks the witnessing contributed where it settles, answering what it answers, a witness or none", async () => {
	const h = asked(false);
	expect(h.holders.witnessed).toBe(true);
	expect(await h.holders.held("sam")).toBe(false);
	const [a, b] = [await h.register("sam"), await h.register("sam")];
	await h.remove("sam", a);
	await h.holders.settle("sam");
	expect(h.calls).toEqual([
		{ kind: "settle", at: "held", reads: [false] },
		{ kind: "settle", at: "registration", reads: [true] },
		{ kind: "settle", at: "registration", reads: [true] },
		{ kind: "settle", at: "removal", reads: [true] },
		{ kind: "settle", at: "settle", reads: [true] },
	]);
	// The last removal and a reset empty the list: the witnessing is told what that left.
	h.calls.length = 0;
	await h.remove("sam", b);
	await h.register("dee");
	expect(await h.holders.cleared("dee")).toEqual({ removed: 1 });
	expect(h.calls).toEqual([
		{ kind: "emptied", at: "removal", reads: ["none", false] },
		{ kind: "settle", at: "registration", reads: [true] },
		{ kind: "emptied", at: "reset", reads: ["none", false] },
	]);
});

it("hands reads that read anew each time and write nothing", async () => {
	const h = asked();
	const id = await h.register("sam");
	await h.remove("sam", id);
	const { holds, after } = h.read();
	expect([await holds?.(), await after?.()]).toEqual([false, "none"]);
	// A passkey registered since reads as held, and the emptied write's holder as holding one.
	await h.register("sam");
	expect([await holds?.(), await after?.()]).toEqual([true, "passkey"]);
	const before = await h.records.holder("sam");
	await after?.();
	await holds?.();
	expect(await h.records.holder("sam")).toEqual(before);
	// The holder lost: unsure, never none.
	await h.stores.lose.holder("sam");
	expect(await after?.()).toBe("unsure");
});
