import { randomBytes } from "node:crypto";
import { expect, it } from "vitest";
import { heldState, jointOver, memoryStores, writeToken } from "../../../test/stores.ts";
import { keptPasskeys } from "../../records.ts";
import type { PasskeyStore } from "../../store.ts";

const fresh = () => randomBytes(32).toString("base64url");

/** Passkey records over memory stores, `reading` run after each read of a holder, with ways to register and keep pending. */
function kept({ reading }: { reading?: (read: number) => Promise<void> } = {}) {
	const stores = memoryStores();
	let reads = 0;
	const subjects = stores.passkeys.subjects;
	const store: PasskeyStore = {
		...stores.passkeys,
		subjects: {
			...subjects,
			read: async (key) => {
				const record = await subjects.read(key);
				await reading?.(++reads);
				return record;
			},
		},
	};
	const joint = jointOver(store);
	const { records, credentialFor } = joint;
	const pending = async (subject: string, id = fresh()) => {
		const written = writeToken();
		const credential = await credentialFor(subject, id);
		expect(await records.joined(subject, credential, 10, undefined, written)).toBe("written");
		return { id, written };
	};
	const register = async (subject: string, id = fresh()) => {
		expect(await records.register(subject, await credentialFor(subject, id), 10)).toBe(
			"registered",
		);
		return id;
	};
	const fence = async (subject: string) => (await records.holder(subject))?.fence;
	return { ...joint, stores, pending, register, fence };
}

it("moves the holder's fence on only with a write that empties its list, answering the holder it left", async () => {
	const { records, register, pending, fence } = kept();
	const [a, b] = [await register("sam"), await register("sam")];
	const handle = (await records.holder("sam"))?.handle;
	expect(await fence("sam")).toBe(0);
	await records.renamed("sam", a, "laptop");
	expect(await records.removed("sam", a)).toEqual({ removed: true, empty: false });
	expect(await fence("sam")).toBe(0);
	expect(await records.removed("sam", b)).toEqual({
		removed: true,
		empty: true,
		emptied: { handle, fence: 1 },
	});
	const c = await register("sam");
	const d = await pending("sam");
	expect((await records.ended("sam", d.id, d.written)).emptied).toBeUndefined();
	expect(await fence("sam")).toBe(1);
	expect(await records.cleared("sam", fresh())).toEqual({
		removed: 1,
		emptied: { handle, fence: 2 },
	});
	const e = await pending("sam");
	expect((await records.ended("sam", e.id, e.written)).emptied).toEqual({ handle, fence: 3 });
	// A removal that takes nothing off moves nothing on.
	expect((await records.removed("sam", c)).emptied).toBeUndefined();
	expect(await fence("sam")).toBe(3);
});

it("tells what the subject holds after its list was emptied: a passkey, a pending one, none, or unsure", async () => {
	const { stores, records, register, pending, keepAs, listAs18 } = kept();
	const id = await register("sam");
	const emptied = (await records.removed("sam", id)).emptied;
	if (!emptied) throw new Error("the last removal empties the list");
	expect(await records.afterRemoval("sam", emptied)).toBe("none");
	// A later fence is this call's write and more; one behind it, or another handle, is unsure.
	expect(await records.afterRemoval("sam", { ...emptied, fence: 0 })).toBe("none");
	expect(await records.afterRemoval("sam", { ...emptied, fence: 9 })).toBe("unsure");
	expect(await records.afterRemoval("sam", { ...emptied, handle: fresh() })).toBe("unsure");
	const p = await pending("sam");
	expect(await records.afterRemoval("sam", emptied)).toBe("pending");
	await register("sam");
	expect(await records.afterRemoval("sam", emptied)).toBe("passkey");
	expect(await records.activated(p.id, p.written)).toBe("activated");
	expect(await records.afterRemoval("sam", emptied)).toBe("passkey");
	// Another subject's record on the list, as 0.18 left it, is none of the subject's.
	const theirs = fresh();
	await keepAs(theirs, { v: 1, subject: "kim", removed: true });
	await listAs18("dee", [theirs]);
	const dees = await records.holder("dee");
	if (!dees) throw new Error("listed");
	expect(await records.afterRemoval("dee", { handle: dees.handle, fence: 0 })).toBe("none");
	// Unsure: a record on the list is missing, or no holder.
	const lost = fresh();
	await listAs18("lee", [lost]);
	const lees = await records.holder("lee");
	if (!lees) throw new Error("listed");
	expect(await records.afterRemoval("lee", { handle: lees.handle, fence: 0 })).toBe("unsure");
	await stores.lose.holder("sam");
	expect(await records.afterRemoval("sam", emptied)).toBe("unsure");
});

it("reads from the start once where the holder changes between its two reads, then is unsure", async () => {
	let changes = 0;
	let reading: ((read: number) => Promise<void>) | undefined;
	const h = kept({ reading: (read) => reading?.(read) ?? Promise.resolve() });
	const id = await h.register("sam");
	const emptied = (await h.records.removed("sam", id)).emptied;
	if (!emptied) throw new Error("the last removal empties the list");
	/** A reset lands right after the first read of each try, `times` tries in a row. */
	const resetAfterFirstRead = (times: number) => {
		let tries = 0;
		let first = true;
		reading = async () => {
			const now = first;
			first = !first;
			if (!now || tries === times) return;
			tries += 1;
			changes += 1;
			await h.records.cleared("sam", fresh());
		};
	};
	resetAfterFirstRead(1);
	expect(await h.records.afterRemoval("sam", emptied)).toBe("none");
	resetAfterFirstRead(2);
	expect(await h.records.afterRemoval("sam", emptied)).toBe("unsure");
	expect(changes).toBe(3);
});

it("makes the holder anew in a reset of a subject that has none, under the handle given, at fence 1", async () => {
	const { records } = kept();
	const handle = fresh();
	expect(await records.cleared("dee", handle)).toEqual({
		removed: 0,
		emptied: { handle, fence: 1 },
	});
	expect(await records.holder("dee")).toEqual({ handle, credentials: [], fence: 1 });
	// A holder there keeps its handle.
	expect((await records.cleared("dee", fresh())).emptied).toEqual({ handle, fence: 2 });
});

it("writes nothing for a registration whose holder is made anew under another handle after it was checked", async () => {
	const stores = memoryStores();
	const records = keptPasskeys(stores.passkeys, writeToken, () => 1_000);
	const id = fresh();
	const credential = {
		id,
		publicKey: "pQ",
		signCount: 0,
		userHandle: await records.handleFor("sam", fresh()),
		backupEligible: false,
		backedUp: false,
	};
	stores.raceNextTogether(async () => {
		await stores.lose.holder("sam");
		await records.cleared("sam", fresh());
	});
	expect(await records.joined("sam", credential, 10, undefined, writeToken())).toBe("malformed");
	expect(await heldState(stores.passkeys, ["sam"], [id])).toEqual({
		lists: { sam: [] },
		records: { [id]: undefined },
	});
});
