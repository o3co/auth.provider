import { BootRefused, defineModule, isUnavailable } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import { factorKinds } from "@mod/mfa-extensions";
import { witnessStandIn } from "@mod/mfa-witness/testing";
import { expect, it } from "vitest";
import { witnessBackfill } from "../src/contract.ts";
import { witnessed } from "./harness.ts";

/** A counting kind whose first proof names a credential no two factors may hold. */
const card = defineModule({ name: "kind-card", takes: [] }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "card",
		amr: ["hwk"],
		addsSecondFactor: true,
		guessable: false,
		counts: true,
		uniqueSecret: (factor) => (typeof factor.state === "string" ? factor.state : undefined),
		enroll: async () => ({ secret: "c", show: {} }),
		verify: async (_secret, state, proof) => ({ kind: "valid" as const, state: state ?? proof }),
	})),
]);

/** A witnessed mfa with the card kind, and a binding of a card under a proof. */
async function withCards() {
	const served = await witnessed({}, [card]);
	const bindCard = async (subject: string, proof: string) => {
		const begun = await served.decided.begin(subject, "card");
		if (begun.kind !== "begun") throw new Error(begun.kind);
		const proved = await served.decided.provePending(subject, begun.pending, proof);
		if (proved.kind !== "valid") throw new Error(proved.kind);
		return served.decided.bind(subject, begun.pending, proved.state);
	};
	return { ...served, bindCard };
}

it("refuses to start with two witnesses", async () => {
	await expect(witnessed({}, [witnessStandIn("witness-two").module])).rejects.toBeInstanceOf(
		BootRefused,
	);
});

it("marks no subject whose first binding another subject's factor already holds the value of, so it stays usable", async () => {
	const { decided, witness } = await witnessed({}, [card]);
	const bindCard = async (subject: string, proof: string) => {
		const begun = await decided.begin(subject, "card");
		if (begun.kind !== "begun") throw new Error(begun.kind);
		const proved = await decided.provePending(subject, begun.pending, proof);
		if (proved.kind !== "valid") throw new Error(proved.kind);
		return decided.bind(subject, begun.pending, proved.state);
	};
	expect(await bindCard("ann", "c1")).toMatchObject({ kind: "bound" });
	expect(await bindCard("bob", "c1")).toEqual({ kind: "duplicate" });
	expect(witness.marks.has("bob")).toBe(false);
	expect(await decided.asks("bob")).not.toBe(undefined);
	expect(await bindCard("bob", "c2")).toMatchObject({ kind: "bound" });
});

it("fills no mark for a factor whose claim is missing, as 0.18 left one", async () => {
	const { app, bindCard, place, witness } = await withCards();
	expect(await bindCard("bob", "c1")).toMatchObject({ kind: "bound" });
	await place.loseClaims();
	witness.marks.clear();
	// Written, none claimed: it may yet be another's.
	expect(await app.get(witnessBackfill).settle("bob")).toBe("unclaimed");
	expect(witness.marks.has("bob")).toBe(false);
});

it("fills no mark for a factor whose claim is missing, whose value another then binds", async () => {
	const { app, bindCard, place, witness } = await withCards();
	expect(await bindCard("bob", "c1")).toMatchObject({ kind: "bound" });
	await place.loseClaims();
	witness.marks.clear();
	expect(await bindCard("ann", "c1")).toMatchObject({ kind: "bound" });
	expect(await app.get(witnessBackfill).settle("bob")).toBe("unclaimed");
	expect(witness.marks.has("bob")).toBe(false);
	expect(witness.marks.has("ann")).toBe(true);
});

it("marks the subject once a counting factor is written, a binding filling a mark that is missing", async () => {
	const { bindCode, witness } = await witnessed();
	await bindCode("ana");
	expect(witness.marks.has("ana")).toBe(true);
	witness.marks.clear();
	await bindCode("ana");
	expect(witness.marks.has("ana")).toBe(true);
});

it("leaves no mark when a first binding's write fails, so the subject can bind again", async () => {
	const { decided, provedCode, witness, place, counted } = await witnessed();
	const begun = await provedCode("abe");
	place.down.failNext("update");
	await expect(decided.bind("abe", begun.pending, begun.state)).rejects.toSatisfy(isUnavailable);
	expect([await counted("abe"), witness.marks.has("abe")]).toEqual([0, false]);
	expect(await decided.asks("abe")).not.toBe(undefined);
	const again = await provedCode("abe");
	expect((await decided.bind("abe", again.pending, again.state)).kind).toBe("bound");
	expect(witness.marks.has("abe")).toBe(true);
});

it("answers unavailable where a wiped store would read as never enrolled: login, a first binding, and credentials", async () => {
	const { decided, bindCode, wipe, events } = await witnessed();
	await bindCode("bea");
	wipe();
	events.length = 0;
	await expect(decided.asks("bea")).rejects.toSatisfy(isUnavailable);
	await expect(decided.begin("bea", "code")).rejects.toSatisfy(isUnavailable);
	await expect(decided.countingHeld("bea", "credentials")).rejects.toSatisfy(isUnavailable);
	expect(events.map((e) => [e.kind, e.attributes])).toEqual([
		["mfa.enrollment_inconsistent", { at: "login" }],
		["mfa.enrollment_inconsistent", { at: "binding" }],
		["mfa.enrollment_inconsistent", { at: "credentials" }],
	]);
	expect(await decided.countingHeld("eli", "login")).toBe(false);
});

it("refuses a first binding begun before the owner's, once the store is wiped, writing nothing", async () => {
	const { decided, provedCode, bindCode, wipe, counted, events } = await witnessed();
	const stale = await provedCode("cid");
	await bindCode("cid");
	wipe();
	events.length = 0;
	// The mark with nothing counting is a store that lost its factors: unavailable, as `begin` answers.
	await expect(decided.bind("cid", stale.pending, stale.state)).rejects.toSatisfy(isUnavailable);
	expect(await counted("cid")).toBe(0);
	expect(events.map((e) => [e.kind, e.attributes])).toEqual([
		["mfa.enrollment_inconsistent", { at: "binding" }],
	]);
});

it("asks the witness again with the same token, three times at most; past that the factor stands unmarked until a later binding marks it", async () => {
	const { decided, provedCode, witness, counted, bindCode } = await witnessed();
	const begun = await provedCode("dan");
	witness.failing.enroll = 2;
	expect((await decided.bind("dan", begun.pending, begun.state)).kind).toBe("bound");
	const other = await provedCode("eli");
	witness.failing.enroll = 8;
	await expect(decided.bind("eli", other.pending, other.state)).rejects.toSatisfy(isUnavailable);
	expect([await counted("eli"), witness.marks.has("eli")]).toEqual([1, false]);
	witness.failing.enroll = 0;
	await bindCode("eli");
	expect(witness.marks.has("eli")).toBe(true);
});

it("binds over a mark its own token set when its answer was lost", async () => {
	const { decided, provedCode, witness, counted } = await witnessed();
	const begun = await provedCode("fay");
	witness.lost.enroll = 1;
	expect((await decided.bind("fay", begun.pending, begun.state)).kind).toBe("bound");
	expect(await counted("fay")).toBe(1);
});

it("writes nothing and leaves the mark when a reset lands while it binds a first factor", async () => {
	const { decided, provedCode, witness, counted, place, bindCode } = await witnessed();
	// A list of the subject's to change: a way back alone, which counts for nothing.
	await bindCode("gil").catch(() => undefined);
	await decided.clear("gil");
	const begun = await provedCode("gil");
	// While this binding writes, a reset clears the factors and moves the fence, and a newer binding marks.
	place.raceNextChange((record) => {
		witness.marks.set("gil", "newer");
		return { ...record, factors: [], fences: 2 } as typeof record;
	});
	expect(await decided.bind("gil", begun.pending, begun.state)).toEqual({ kind: "fenced" });
	expect(await counted("gil")).toBe(0);
	expect(witness.marks.get("gil")).toBe("newer");
});

it("never removes the last counting factor under optional mode, as only a reset clears the mark", async () => {
	const { decided, bindCode, idOf } = await witnessed({ mode: "optional" });
	await bindCode("ivy");
	expect(await decided.remove("ivy", await idOf("ivy", "code"), await decided.fenceOf("ivy"))).toBe(
		"last",
	);
});

it("clears the mark after a reset's removal, and answers unavailable while it cannot, the factors gone", async () => {
	const { decided, bindCode, witness, counted } = await witnessed();
	await bindCode("jo");
	expect((await decided.clear("jo")).count).toBe(2);
	expect(witness.marks.has("jo")).toBe(false);
	await bindCode("jo");
	witness.failing.markedWith = 1;
	await expect(decided.clear("jo")).rejects.toSatisfy(isUnavailable);
	expect([await counted("jo"), witness.marks.has("jo")]).toEqual([0, true]);
	await expect(decided.asks("jo")).rejects.toSatisfy(isUnavailable);
});

it("answers unavailable, writing nothing, wherever the witness cannot be read", async () => {
	const { decided, provedCode, witness, counted } = await witnessed();
	witness.failing.read = 3;
	await expect(decided.asks("kim")).rejects.toSatisfy(isUnavailable);
	await expect(decided.begin("kim", "code")).rejects.toSatisfy(isUnavailable);
	await expect(decided.countingHeld("kim", "credentials")).rejects.toSatisfy(isUnavailable);
	const begun = await provedCode("kim");
	witness.failing.read = 1;
	await expect(decided.bind("kim", begun.pending, begun.state)).rejects.toSatisfy(isUnavailable);
	expect(await counted("kim")).toBe(0);
});

it("judges whether a counting factor is held against the witness, recording where it was asked", async () => {
	const { decided, bindCode, wipe, events } = await witnessed();
	await bindCode("dee");
	expect(await decided.countingHeld("dee", "credentials")).toBe(true);
	wipe();
	events.length = 0;
	await expect(decided.countingHeld("dee", "credentials")).rejects.toSatisfy(isUnavailable);
	await expect(decided.countingHeld("dee", "binding")).rejects.toSatisfy(isUnavailable);
	expect(events.map((e) => [e.kind, e.attributes])).toEqual([
		["mfa.enrollment_inconsistent", { at: "credentials" }],
		["mfa.enrollment_inconsistent", { at: "binding" }],
	]);
});

it("takes all it names, with mfa and a witness in memory", async () => {
	const h = await witnessed();
	expect(await takesUnused(h.input)).toEqual({});
});
