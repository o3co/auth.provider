import { isUnavailable, Unavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import { passkeyWitnessStandIn } from "@mod/passkey-witness/testing";
import type { AfterRemoval } from "@mod/passkeys";
import { expect, it } from "vitest";
import { witnessingOver } from "../src/witnessing.ts";

/** The witnessing over a witness in memory, what passkeys reads scripted: `holding`, and `after`'s answers in turn. */
function over() {
	const stand = passkeyWitnessStandIn();
	const events: { kind: string; subject?: string; attributes?: unknown }[] = [];
	const order: string[] = [];
	const state = { holding: false, after: [] as AfterRemoval[] };
	let n = 0;
	const markedWith = stand.witness.markedWith;
	stand.witness.markedWith = async (subject) => {
		order.push("markedWith");
		return markedWith(subject);
	};
	const witnessing = witnessingOver({
		witness: stand.witness,
		audit: { record: (event) => void events.push(event) },
		log: recordingLog().log,
		token: () => `t${++n}`,
	});
	const holds = async () => state.holding;
	const after = async () => {
		order.push("after");
		return state.after.shift() ?? "none";
	};
	return { stand, events, order, state, witnessing, holds, after };
}

const inconsistent = (at: string) => [
	expect.objectContaining({ kind: "passkey.enrollment_inconsistent", attributes: { at } }),
];

it("marks a subject holding a passkey under a new token, and answers what the mark agreed with", async () => {
	const w = over();
	w.state.holding = true;
	expect(await w.witnessing.settle("sam", "registration", w.holds)).toBe(true);
	expect(w.stand.marks.get("sam")).toBe("t1");
	expect(await w.witnessing.settle("sam", "held", w.holds)).toBe(true);
	expect(w.stand.marks.get("sam")).toBe("t1");
	w.state.holding = false;
	expect(await w.witnessing.settle("kim", "held", w.holds)).toBe(false);
	expect(w.events).toEqual([]);
});

it("records a mark beside no passkey as inconsistent and unavailable, keeping it and naming no token", async () => {
	const w = over();
	w.stand.marks.set("dee", "lost");
	await expect(w.witnessing.settle("dee", "held", w.holds)).rejects.toSatisfy(isUnavailable);
	expect(w.stand.marks.get("dee")).toBe("lost");
	expect(w.events).toEqual([
		expect.objectContaining({ subject: "dee", attributes: { at: "held" } }),
	]);
	expect(JSON.stringify(w.events)).not.toMatch(/lost/);
});

it("reads once more before telling a mark inconsistent, as a last removal's withdraw may land meanwhile", async () => {
	const w = over();
	w.stand.marks.set("sam", "theirs");
	w.stand.next.beforeRead = () => {
		w.stand.next.beforeRead = () => w.stand.marks.delete("sam");
	};
	expect(await w.witnessing.settle("sam", "held", w.holds)).toBe(false);
	expect(w.events).toEqual([]);
});

it("withdraws only its own mark where the passkey went meanwhile, never another's", async () => {
	const w = over();
	w.state.holding = true;
	w.stand.next.afterEnroll = () => {
		w.state.holding = false;
	};
	expect(await w.witnessing.settle("sam", "registration", w.holds)).toBe(false);
	expect(w.stand.marks.has("sam")).toBe(false);
	w.state.holding = true;
	w.stand.marks.set("kim", "theirs");
	expect(await w.witnessing.settle("kim", "registration", w.holds)).toBe(true);
	expect(w.stand.marks.get("kim")).toBe("theirs");
});

it("reads both again after withdrawing its mark, and records another's mark left beside no passkey", async () => {
	const w = over();
	w.state.holding = true;
	w.stand.next.afterEnroll = () => {
		w.state.holding = false;
		w.stand.next.beforeWithdraw = () => w.stand.marks.set("sam", "theirs");
	};
	await expect(w.witnessing.settle("sam", "registration", w.holds)).rejects.toSatisfy(
		isUnavailable,
	);
	expect(w.stand.marks.get("sam")).toBe("theirs");
	expect(w.events).toEqual(inconsistent("registration"));
});

it("marks twice at most, then is unavailable while the mark and the passkeys still differ", async () => {
	const w = over();
	w.state.holding = true;
	let enrolls = 0;
	const enroll = w.stand.witness.enroll;
	w.stand.witness.enroll = async (subject, token) => {
		enrolls += 1;
		const owned = await enroll(subject, token);
		w.stand.marks.delete(subject);
		return owned;
	};
	await expect(w.witnessing.settle("sam", "registration", w.holds)).rejects.toSatisfy(
		isUnavailable,
	);
	expect(enrolls).toBe(2);
});

it("asks a witness whose answer was lost again with the same token, which owns the mark", async () => {
	const w = over();
	w.state.holding = true;
	const tokens: string[] = [];
	const enroll = w.stand.witness.enroll;
	w.stand.witness.enroll = async (subject, token) => {
		tokens.push(token);
		return enroll(subject, token);
	};
	w.stand.lost.enroll = 1;
	expect(await w.witnessing.settle("sam", "registration", w.holds)).toBe(true);
	expect(tokens).toEqual(["t1", "t1"]);
	expect(w.stand.marks.get("sam")).toBe("t1");
});

it("is unavailable while the witness cannot be read or written", async () => {
	const w = over();
	w.state.holding = true;
	w.stand.failing.read = 1;
	await expect(w.witnessing.settle("sam", "held", w.holds)).rejects.toSatisfy(isUnavailable);
	w.stand.failing.enroll = 4;
	await expect(w.witnessing.settle("sam", "registration", w.holds)).rejects.toSatisfy(
		isUnavailable,
	);
	expect(await w.witnessing.settle("sam", "held", w.holds)).toBe(true);
});

it("after an emptying write, reads the mark's token before what passkeys holds, and asks nothing more where no mark is set", async () => {
	const w = over();
	await w.witnessing.emptied("sam", "removal", w.after, w.holds);
	expect(w.order).toEqual(["markedWith"]);
	w.stand.marks.set("sam", "old");
	await w.witnessing.emptied("sam", "removal", w.after, w.holds);
	expect(w.order).toEqual(["markedWith", "markedWith", "after", "after"]);
	expect(w.stand.marks.has("sam")).toBe(false);
});

it("withdraws the token it read where after says none, leaving a mark set since under another token", async () => {
	const w = over();
	w.stand.marks.set("sam", "old");
	w.stand.next.beforeWithdraw = () => w.stand.marks.set("sam", "t2");
	await w.witnessing.emptied("sam", "removal", w.after, w.holds);
	expect(w.stand.marks.get("sam")).toBe("t2");
});

it("keeps the mark where after says a passkey or a pending one is held", async () => {
	for (const held of ["passkey", "pending"] as const) {
		const w = over();
		w.stand.marks.set("sam", "old");
		w.state.after = [held];
		await w.witnessing.emptied("sam", "removal", w.after, w.holds);
		expect(w.stand.marks.get("sam"), held).toBe("old");
		expect(w.order, held).toEqual(["markedWith", "after"]);
	}
});

it("fails closed where after is unsure: the mark kept, recorded where asked, unavailable", async () => {
	const w = over();
	w.stand.marks.set("sam", "old");
	w.state.after = ["unsure"];
	await expect(w.witnessing.emptied("sam", "reset", w.after, w.holds)).rejects.toSatisfy(
		isUnavailable,
	);
	expect(w.stand.marks.get("sam")).toBe("old");
	expect(w.events).toEqual(inconsistent("reset"));
});

it("asks a withdraw unavailable again with the same token, reading nothing again, then is unavailable past its retries", async () => {
	const w = over();
	w.stand.marks.set("sam", "old");
	const tokens: string[] = [];
	const withdraw = w.stand.witness.withdraw;
	w.stand.witness.withdraw = async (subject, token) => {
		tokens.push(token);
		return withdraw(subject, token);
	};
	w.stand.failing.withdraw = 4;
	await expect(w.witnessing.emptied("sam", "removal", w.after, w.holds)).rejects.toSatisfy(
		isUnavailable,
	);
	expect(tokens).toEqual(["old", "old", "old", "old"]);
	expect(w.order).toEqual(["markedWith", "after"]);
	expect(w.stand.marks.get("sam")).toBe("old");
	expect(w.events).toEqual([]);
});

it("reads after again once it withdrew: marks again for a passkey come meanwhile, leaves a pending one, fails closed on unsure", async () => {
	const passkey = over();
	passkey.stand.marks.set("sam", "old");
	passkey.state.after = ["none", "passkey"];
	passkey.state.holding = true;
	await passkey.witnessing.emptied("sam", "removal", passkey.after, passkey.holds);
	expect(passkey.stand.marks.get("sam")).toBe("t1");
	const pending = over();
	pending.stand.marks.set("sam", "old");
	pending.state.after = ["none", "pending"];
	await pending.witnessing.emptied("sam", "removal", pending.after, pending.holds);
	expect(pending.stand.marks.has("sam")).toBe(false);
	const unsure = over();
	unsure.stand.marks.set("sam", "old");
	unsure.state.after = ["none", "unsure"];
	await expect(
		unsure.witnessing.emptied("sam", "reset", unsure.after, unsure.holds),
	).rejects.toSatisfy(isUnavailable);
	expect(unsure.events).toEqual(inconsistent("reset"));
});

it("passes on a failure that is not unavailable, as is", async () => {
	const w = over();
	w.stand.marks.set("sam", "old");
	w.stand.witness.withdraw = async () => {
		throw new TypeError("broken");
	};
	await expect(w.witnessing.emptied("sam", "removal", w.after, w.holds)).rejects.toThrow(TypeError);
	expect(new Unavailable("x")).toSatisfy(isUnavailable);
});
