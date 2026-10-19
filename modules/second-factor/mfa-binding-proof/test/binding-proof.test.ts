import { randomBytes } from "node:crypto";
import { auditStandIn } from "@mod/audit/testing";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { assemble, BootRefused, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import gatesModule from "@mod/login-gates/module";
import { factorStore, factors, proofSteps, type StoredFactors } from "@mod/mfa";
import mfaModule from "@mod/mfa/module";
import { mfaConfig } from "@mod/mfa/testing";
import mfaEntry from "@mod/mfa-entry/module";
import { factorKinds } from "@mod/mfa-extensions";
import { memoryRecords } from "@mod/records/testing";
import sealModule from "@mod/seal/module";
import { sealConfig } from "@mod/seal/testing";
import { sessionStandIn } from "@mod/session/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { afterEach, expect, it } from "vitest";
import { bindingProof, bindingProofs } from "../src/contract.ts";
import bindingProofModule from "../src/module.ts";

let shift = 0;
const runtime = quietRuntime({ clock: { now: () => Date.now() + shift } });
let stop = async () => {};
afterEach(async () => {
	await stop();
	shift = 0;
	contact.limited = false;
	contact.refused = false;
	contact.from.length = 0;
});

/** Counting kinds whose proof is their secret: two, so a pass is seen to begin only its own kind. */
const counting = (kind: string) =>
	defineModule({ name: `kind-${kind}` }, (m) => [
		m.contribute(factorKinds).by(() => ({
			kind,
			amr: ["otp"],
			addsSecondFactor: true,
			guessable: true,
			counts: true,
			enroll: async () => ({ secret: "c", show: {} }),
			verify: async (secret, _state, proof) =>
				proof === secret ? { kind: "valid" as const, state: null } : { kind: "invalid" as const },
		})),
	]);
const step = defineModule({ name: "step" }, (m) => [
	m.contribute(proofSteps).by(() => ({ name: "step" })),
]);

/** What the proof last kept, and how it answers: not available to `nobody`. */
const contact = { kept: "", limited: false, refused: false, from: [] as unknown[] };
const owning = defineModule({ name: "proof-contact" }, (m) => [
	m.contribute(bindingProofs).by(() => ({
		name: "contact",
		available: async (subject, from) => {
			contact.from.push(from);
			return subject !== "nobody";
		},
		send: async (_subject, _until, from) => {
			contact.from.push(from);
			if (contact.limited) return { kind: "limited" as const };
			if (contact.refused) return { kind: "refused" as const };
			contact.kept = randomBytes(6).toString("hex");
			return { kind: "sent" as const, show: { masked: "k***" }, kept: contact.kept };
		},
		check: async (_subject, kept, answer) => answer === kept,
	})),
]);

async function serve(mode?: "never" | "when-available" | "always", proofs = [owning]) {
	const stand = memoryRecords<StoredFactors>(() => runtime.clock.now(), { shards: 1, perShard: 1 });
	const store = defineModule({ name: "factor-store" }, (m) => [
		m.provide(factorStore).by(() => ({
			save: (key, record) => stand.records.create(key, record, "endless"),
			read: stand.records.read,
			update: stand.records.change,
			scan: stand.records.scan,
		})),
	]);
	const app = await assemble({
		modules: [
			http,
			auditStandIn().module,
			sessionStandIn,
			subjectRevocationStandIn,
			store,
			sealModule,
			gatesModule,
			mfaModule,
			mfaEntry,
			step,
			counting("code"),
			counting("key"),
			...proofs,
			bindingProofModule,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			...sealConfig(),
			...mfaConfig(),
			...(mode ? { "mfa-binding-proof": { mode } } : {}),
		},
		runtime,
	});
	stop = () => app.stop(1000);
	const asking = app.get(bindingProof);
	const decided = app.get(factors);
	const inAMinute = () => runtime.clock.now() + 60_000;
	/** A pass for the subject, bound to a transaction and kind; a proof that gives none fails the test. */
	const passOf = async (subject: string, bound = { transaction: "t", kind: "code" }) => {
		const sent = await asking.challenge(subject, inAMinute());
		if (sent.kind !== "sent") throw new Error(sent.kind);
		const pass = await asking.prove(subject, contact.kept, sent.sealed, bound);
		if (pass === undefined) throw new Error("no pass");
		return pass;
	};
	/** Binds a code factor for the subject through mfa, the pass given. */
	const bindCode = async (subject: string, passed?: string) => {
		const begun = await decided.begin(subject, "code", passed, "t");
		if (begun.kind !== "begun") throw new Error(begun.kind);
		const proved = await decided.provePending(subject, begun.pending, "c");
		if (proved.kind !== "valid") throw new Error(proved.kind);
		return decided.bind(subject, begun.pending, proved.state);
	};
	return { asking, decided, passOf, bindCode, inAMinute };
}

it("asks the available proof of a subject holding no counting factor, and nothing of one it is not available to or one holding a factor", async () => {
	const { asking, passOf, bindCode } = await serve();
	expect(await asking.asks("ann")).toBe("proof");
	expect(await asking.asks("nobody")).toBe("nothing");
	expect((await bindCode("ann", await passOf("ann"))).kind).toBe("bound");
	expect(await asking.asks("ann")).toBe("nothing");
});

it("sends the proof's challenge sealed, and answers none, limited, or refused with the proof's name", async () => {
	const { asking, inAMinute } = await serve();
	const sent = await asking.challenge("ann", inAMinute());
	if (sent.kind !== "sent") throw new Error(sent.kind);
	expect([sent.proof, sent.show, sent.sealed.includes(contact.kept)]).toEqual([
		"contact",
		{ masked: "k***" },
		false,
	]);
	expect(await asking.challenge("nobody", inAMinute())).toEqual({ kind: "none" });
	contact.limited = true;
	expect(await asking.challenge("cid", inAMinute())).toEqual({ kind: "limited" });
	contact.limited = false;
	contact.refused = true;
	expect(await asking.challenge("cid", inAMinute())).toEqual({ kind: "refused", proof: "contact" });
});

it("gives a pass for the right answer to the sealed challenge, in time, and is unavailable on a challenge that will not open", async () => {
	const { asking, inAMinute } = await serve();
	const sent = await asking.challenge("ann", inAMinute());
	if (sent.kind !== "sent") throw new Error(sent.kind);
	const bound = { transaction: "t", kind: "code" };
	expect(await asking.prove("ann", "wrong", sent.sealed, bound)).toBeUndefined();
	// The challenge is kept by mfa-flows for its own subject: one that will not open is a fault.
	for (const [subject, sealed] of [
		["bob", sent.sealed],
		["ann", "forged"],
	] as const) {
		await expect(asking.prove(subject, contact.kept, sealed, bound)).rejects.toSatisfy(
			isUnavailable,
		);
	}
	const passed = await asking.prove("ann", contact.kept, sent.sealed, bound);
	expect([typeof passed, passed?.includes(contact.kept)]).toEqual(["string", false]);
	shift += 61_000;
	expect(await asking.prove("ann", contact.kept, sent.sealed, bound)).toBeUndefined();
});

it("lets mfa begin a first binding only with the subject's pass, for the transaction and kind it names, in time", async () => {
	const { decided, passOf } = await serve();
	const required = { kind: "binding-proof-required" };
	const [ann, bob] = [await passOf("ann"), await passOf("bob")];
	expect(await decided.begin("ann", "code", undefined, "t")).toEqual(required);
	expect(await decided.begin("ann", "code", ann, "other"), "another transaction").toEqual(required);
	expect(await decided.begin("ann", "key", ann, "t"), "another kind").toEqual(required);
	for (const passed of [bob, "forged"]) {
		await expect(decided.begin("ann", "code", passed, "t")).rejects.toSatisfy(isUnavailable);
	}
	expect((await decided.begin("ann", "code", ann, "t")).kind).toBe("begun");
	expect((await decided.begin("nobody", "code")).kind).toBe("begun");
	expect((await decided.begin("bob", "code", bob, "t")).kind, "in time").toBe("begun");
	shift += 61_000;
	expect(await decided.begin("bob", "code", bob, "t"), "past its end").toEqual(required);
});

it("asks nothing under never, and the first contributed under always", async () => {
	const never = await serve("never");
	expect(await never.asking.asks("ann")).toBe("nothing");
	expect((await never.decided.begin("ann", "code")).kind).toBe("begun");
	await stop();
	const always = await serve("always");
	expect(await always.asking.asks("nobody")).toBe("proof");
});

it("refuses to boot under always with no proof composed, naming the proofs", async () => {
	const refused = await serve("always", []).then(
		() => undefined,
		(error: unknown) => error,
	);
	expect(refused).toBeInstanceOf(BootRefused);
	expect((refused as BootRefused).refusals.map((r) => r.where)).toEqual([
		"mfa-binding-proof.proofs",
	]);
});

it("passes where an ask came from to the proof unread", async () => {
	const { asking, decided, inAMinute } = await serve();
	const login = { kind: "login", email: "ann@example.invalid" } as const;
	const session = { kind: "session", handle: "h1" } as const;
	await asking.asks("ann", session); // available
	await asking.challenge("ann", inAMinute(), login); // available, then send
	await decided.begin("ann", "code", undefined, "t", login); // the gate's available
	expect(contact.from).toEqual([session, login, login, login]);
});

it("asks for a proof when one is available, when the operator sets no mode", () => {
	expect(bindingProofModule.section?.parse({})).toEqual({ mode: "when-available" });
});
