import { createHash, randomBytes } from "node:crypto";
import { isUnavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { memoryStores, writeToken } from "../../../test/stores.ts";
import { type KeptPasskeys, keptPasskeys } from "../../records.ts";
import {
	passkeyWitnessContract,
	passkeyWitnessProblems,
	passkeyWitnessStandIn,
} from "../../testing.ts";
import { holdersOver } from "../holders.ts";

const fresh = () => randomBytes(32).toString("base64url");

/** Holdings over memory stores and a witness in memory, recording what is audited. */
function held({ witnessed = true, around = (r: KeptPasskeys) => r } = {}) {
	const stores = memoryStores();
	const kept = keptPasskeys(stores.passkeys, writeToken, () => 1_000);
	const records = around(kept);
	const stand = passkeyWitnessStandIn();
	const events: { kind: string; subject?: string; attributes?: unknown }[] = [];
	let n = 0;
	const { holders, settle } = holdersOver({
		records,
		witness: witnessed ? stand.witness : undefined,
		audit: { record: (event) => void events.push(event) },
		log: recordingLog().log,
		token: () => `t${++n}`,
		handle: fresh,
	});
	/** Registers a passkey for `subject` as a registration does: the write, then the settle. */
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
	/** Removes a passkey as a removal does: the update, then the settle, handed the holder it left where it emptied the list. */
	const remove = async (subject: string, id: string) => {
		const removed = await records.removed(subject, id);
		await settle(subject, "removal", removed.emptied);
		return { removed: removed.removed, empty: removed.empty };
	};
	return { stores, records, stand, events, holders, settle, register, remove };
}

it("tells holding from the passkeys alone without a witness, settling nothing", async () => {
	const { holders, register, remove } = held({ witnessed: false });
	expect(holders.witnessed).toBe(false);
	expect(await holders.held("sam")).toBe(false);
	const id = await register("sam");
	expect(await holders.held("sam")).toBe(true);
	await remove("sam", id);
	expect(await holders.held("sam")).toBe(false);
});

it("marks a subject once it holds a passkey, and clears the mark only with the removal that leaves none", async () => {
	const { holders, stand, register, remove } = held();
	expect(holders.witnessed).toBe(true);
	const [a, b] = [await register("sam"), await register("sam")];
	expect(stand.marks.get("sam")).toBe("t1");
	expect(await remove("sam", a)).toEqual({ removed: true, empty: false });
	expect(stand.marks.has("sam")).toBe(true);
	expect(await remove("sam", b)).toEqual({ removed: true, empty: true });
	expect(stand.marks.has("sam")).toBe(false);
	expect(await holders.held("sam")).toBe(false);
});

it("records a mark beside no passkey as inconsistent and unavailable, never clearing it, as the store may have lost them", async () => {
	const { holders, stand, events } = held();
	stand.marks.set("dee", "lost");
	await expect(holders.held("dee")).rejects.toSatisfy(isUnavailable);
	expect(stand.marks.get("dee")).toBe("lost");
	expect(events).toEqual([
		expect.objectContaining({
			kind: "passkey.enrollment_inconsistent",
			subject: "dee",
			attributes: { at: "held" },
		}),
	]);
	expect(JSON.stringify(events)).not.toMatch(/lost/);
});

it("reads once more before telling a mark inconsistent, as a last removal's clear may land meanwhile", async () => {
	const { holders, stand, records, events, register } = held();
	const id = await register("sam");
	// The last removal emptied the list; its clear lands between this call's two reads.
	await records.removed("sam", id);
	let reads = 0;
	stand.next.beforeRead = () => {
		reads += 1;
	};
	const witnessRead = stand.witness.read;
	stand.witness.read = async (subject) => {
		const marked = await witnessRead(subject);
		if (reads === 1) stand.marks.delete("sam");
		return marked;
	};
	expect(await holders.held("sam")).toBe(false);
	expect(events).toEqual([]);
});

it("withdraws only its own mark where the passkey went meanwhile, never another's", async () => {
	const { stand, records, register } = held();
	// The passkeys go, as a reset's list update would, right after this registration's settle marks.
	const enroll = stand.witness.enroll;
	stand.witness.enroll = async (subject, token) => {
		const owned = await enroll(subject, token);
		if (subject === "sam") await records.cleared("sam", fresh());
		return owned;
	};
	await register("sam");
	expect(stand.marks.has("sam")).toBe(false);
	// Another's mark beside a passkey stays as it is.
	stand.marks.set("kim", "theirs");
	await register("kim");
	expect(stand.marks.get("kim")).toBe("theirs");
});

it("marks twice at most, then is unavailable while the mark and the passkeys still differ", async () => {
	const { stand, register } = held();
	// Each mark is taken right after it is set, so the mark and the passkeys keep differing.
	const enroll = stand.witness.enroll;
	stand.witness.enroll = async (subject, token) => {
		const owned = await enroll(subject, token);
		stand.marks.delete(subject);
		return owned;
	};
	let enrolls = 0;
	const counted = stand.witness.enroll;
	stand.witness.enroll = async (subject, token) => {
		enrolls += 1;
		return counted(subject, token);
	};
	await expect(register("sam")).rejects.toSatisfy(isUnavailable);
	expect(enrolls).toBe(2);
	expect(stand.marks.has("sam")).toBe(false);
});

it("clears the mark on a reset, however few passkeys the subject held, counting the passkeys it ended", async () => {
	const { holders, stand, register } = held();
	await register("sam");
	await register("sam");
	expect(await holders.cleared("sam")).toEqual({ removed: 2 });
	expect(stand.marks.has("sam")).toBe(false);
	expect(await holders.held("sam")).toBe(false);
	// A mark beside none, a store that lost its passkeys, is what a reset mends.
	stand.marks.set("dee", "lost");
	expect(await holders.cleared("dee")).toEqual({ removed: 0 });
	expect(stand.marks.has("dee")).toBe(false);
});

it("is unavailable while the witness cannot be read or written, the passkey written staying", async () => {
	const { holders, stand, records, register } = held();
	stand.failing.read = 1;
	await expect(holders.held("sam")).rejects.toSatisfy(isUnavailable);
	stand.failing.enroll = 4;
	await expect(register("sam")).rejects.toSatisfy(isUnavailable);
	expect(await records.listed("sam")).toHaveLength(1);
	// The next settle marks it.
	expect(await holders.held("sam")).toBe(true);
	expect(stand.marks.has("sam")).toBe(true);
});

passkeyWitnessContract("the witness in memory", async () => passkeyWitnessStandIn().witness);
passkeyWitnessContract(
	"the witness in memory, without clear",
	async () => passkeyWitnessStandIn("passkey-witness", { clear: false }).witness,
);

it("offers clear from the witness in memory, and leaves it out when asked to", () => {
	expect(typeof passkeyWitnessStandIn().witness.clear).toBe("function");
	expect(passkeyWitnessStandIn("w", { clear: false }).witness.clear).toBeUndefined();
});

it("names each way a witness's markedWith breaks its promise", async () => {
	/** The witness in memory, its markedWith answering as `lie` says from what it holds. */
	const lying = (lie: (subject: string, marks: Map<string, string>) => string | undefined) => {
		const stand = passkeyWitnessStandIn();
		return { ...stand.witness, markedWith: async (subject: string) => lie(subject, stand.marks) };
	};
	const cases: Record<string, ReturnType<typeof lying>> = {
		"a token for a subject never marked": lying(() => "made-up"),
		"another token than the one its enroll owned": lying((s, m) =>
			m.has(s) ? "other" : undefined,
		),
		"none for a marked subject": lying(() => undefined),
	};
	const { markedWith: _, ...untold } = passkeyWitnessStandIn().witness;
	expect(await passkeyWitnessProblems(untold as never)).toContain(
		"the witness does not tell its mark's token",
	);
	for (const [what, witness] of Object.entries(cases)) {
		expect(await passkeyWitnessProblems(witness), what).not.toEqual([]);
	}
	// One that answers a withdrawn mark's token still.
	const stand = passkeyWitnessStandIn();
	const remembered = new Map<string, string>();
	const sticky = {
		...stand.witness,
		enroll: async (subject: string, token: string) => {
			const owned = await stand.witness.enroll(subject, token);
			if (owned) remembered.set(subject, token);
			return owned;
		},
		markedWith: async (subject: string) => stand.marks.get(subject) ?? remembered.get(subject),
	};
	expect(await passkeyWitnessProblems(sticky)).toContain(
		"markedWith answers the token of a mark withdrawn",
	);
	// One that answers a cleared mark's token still.
	const kept = passkeyWitnessStandIn();
	const before = new Map<string, string>();
	const unforgetting = {
		...kept.witness,
		clear: async (subject: string) => {
			const token = kept.marks.get(subject);
			if (token !== undefined) before.set(subject, token);
			await kept.witness.clear?.(subject);
		},
		markedWith: async (subject: string) => kept.marks.get(subject) ?? before.get(subject),
	};
	expect(await passkeyWitnessProblems(unforgetting)).toContain(
		"markedWith answers the token of a mark cleared",
	);
});

it("answers held as the settle saw it with the mark agreeing, so a store lost right after is caught on the next ask", async () => {
	let lose: (() => Promise<void>) | undefined;
	const { holders, stores, events, register } = held({
		around: (records) => ({
			...records,
			listed: async (subject) => {
				const listed = await records.listed(subject);
				const run = lose;
				lose = undefined;
				await run?.();
				return listed;
			},
		}),
	});
	await register("sam");
	// The store loses the subject's passkeys right after the settle reads them.
	lose = async () => {
		await stores.passkeys.subjects.update(
			`s-${createHash("sha256").update("sam").digest("base64url")}`,
			(record) => ({ value: { ...(record as object), credentials: [] } as never }),
		);
	};
	expect(await holders.held("sam")).toBe(true);
	await expect(holders.held("sam")).rejects.toSatisfy(isUnavailable);
	expect(events.map((e) => e.kind)).toEqual(["passkey.enrollment_inconsistent"]);
});

it("reads both again after withdrawing its mark, and records another's mark left beside no passkey", async () => {
	const { stand, records, events, register } = held();
	const enroll = stand.witness.enroll;
	stand.witness.enroll = async (subject, token) => {
		const owned = await enroll(subject, token);
		if (subject === "sam") {
			// The passkeys go, and another binding's mark replaces this call's before it withdraws.
			await records.cleared("sam", fresh());
			stand.next.beforeWithdraw = () => stand.marks.set("sam", "theirs");
		}
		return owned;
	};
	await expect(register("sam")).rejects.toSatisfy(isUnavailable);
	expect(stand.marks.get("sam")).toBe("theirs");
	expect(events).toEqual([
		expect.objectContaining({
			kind: "passkey.enrollment_inconsistent",
			attributes: { at: "registration" },
		}),
	]);
});

it("asks a witness whose answer was lost again with the same token, which owns the mark", async () => {
	const { stand, register } = held();
	const tokens: string[] = [];
	const enroll = stand.witness.enroll;
	stand.witness.enroll = async (subject, token) => {
		tokens.push(token);
		return enroll(subject, token);
	};
	stand.lost.enroll = 1;
	await register("sam");
	expect(tokens).toEqual(["t1", "t1"]);
	expect(stand.marks.get("sam")).toBe("t1");
});
