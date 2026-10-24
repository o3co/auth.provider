import { randomBytes } from "node:crypto";
import { auditStandIn } from "@mod/audit/testing";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import {
	assemble,
	BootRefused,
	defineModule,
	isUnavailable,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { isLabel } from "@mod/labels";
import { logins } from "@mod/login-gates";
import gatesModule from "@mod/login-gates/module";
import { factorBinding } from "@mod/mfa-binding";
import * as extensions from "@mod/mfa-extensions";
import {
	type Enrolled,
	factorKinds,
	firstBindingGates,
	type Opened,
	type Sending,
	type Witnessing,
	witnessing,
} from "@mod/mfa-extensions";
import { factorManaging } from "@mod/mfa-managing";
import { type FactorReading, factorReading } from "@mod/mfa-reading";
import { witnessStandIn } from "@mod/mfa-witness/testing";
import { seal } from "@mod/seal";
import sealModule from "@mod/seal/module";
import { sealConfig } from "@mod/seal/testing";
import { sessionStandIn } from "@mod/session/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { afterEach, describe, expect, it } from "vitest";
import * as offered from "../src/contract.ts";
import { enforcers, proofSteps } from "../src/contract.ts";
import type { Decisions, UnclaimedReading } from "../src/factors.ts";
import mfaModule from "../src/module.ts";
import { claimKeyOf, listKeyOf, storedList } from "../src/records/records.ts";
import { section } from "../src/section.ts";
import { type FactorStore, factorStore, type StoredFactors } from "../src/store.ts";
import { type MfaSettings, mfaConfig } from "../src/testing.ts";
import { memoryFactors } from "./stores.ts";

let shift = 0;
/** Where set, the clock stands at this time (before the shift), so a test can judge a window's very edge. */
let stopped: number | undefined;
const runtime = quietRuntime({ clock: { now: () => (stopped ?? Date.now()) + shift } });
let stop = async () => {};
afterEach(async () => {
	shift = 0;
	stopped = undefined;
	await stop();
});

/** A guessable, counting kind: the proof is the secret and a counter that must go up. */
const code = defineModule({ name: "kind-code" }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "code",
		amr: ["otp"],
		addsSecondFactor: true,
		guessable: true,
		counts: true,
		enroll: async () => {
			const secret = randomBytes(6).toString("hex");
			return { secret, show: { secret } };
		},
		verify: async (secret, state, proof) => {
			const [given, n] = proof.split(":");
			const last = typeof state === "number" ? state : -1;
			if (given !== secret) return { kind: "invalid" as const };
			return Number(n) > last
				? { kind: "valid" as const, state: Number(n) }
				: { kind: "replayed" as const };
		},
	})),
]);
/** A way back that does not count and cannot be guessed: single-use codes. */
const backup = defineModule({ name: "kind-backup" }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "backup",
		amr: [],
		addsSecondFactor: true,
		guessable: false,
		counts: false,
		enroll: async () => ({ secret: JSON.stringify(["b1", "b2"]), show: ["b1", "b2"] }),
		verify: async (secret, state, proof) => {
			const used = Array.isArray(state) ? (state as string[]) : [];
			const codes = JSON.parse(secret) as string[];
			if (!codes.includes(proof)) return { kind: "invalid" as const };
			return used.includes(proof)
				? { kind: "replayed" as const }
				: {
						kind: "valid" as const,
						state: [...used, proof],
						remaining: codes.length - used.length - 1,
					};
		},
	})),
]);

/** A step that proves factors, as a login flow contributes one. */
const step = defineModule({ name: "step" }, (m) => [
	m.contribute(proofSteps).by(() => ({ name: "step" })),
]);

/** A counting kind whose proof names its amr: the secret, then the amr it claims. */
const key = defineModule({ name: "kind-key" }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "key",
		amr: ["hwk", "swk"],
		addsSecondFactor: true,
		guessable: false,
		counts: true,
		enroll: async () => ({ secret: "k", show: { secret: "k" } }),
		verify: async (secret, _state, proof) => {
			const [given, amr = ""] = proof.split(":");
			return given === secret
				? { kind: "valid" as const, state: proof, amr: [amr] }
				: { kind: "invalid" as const };
		},
	})),
]);
/** A counting kind that does not add a second factor. */
const mail = defineModule({ name: "kind-mail" }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "mail",
		amr: ["otp"],
		addsSecondFactor: false,
		guessable: true,
		counts: true,
		enroll: async () => ({ secret: "m", show: { secret: "m" } }),
		verify: async (secret, _state, proof) =>
			proof === secret ? { kind: "valid" as const, state: null } : { kind: "invalid" as const },
	})),
]);

/** What the challenge kind last saw, and how it answers the next challenge. */
const ping = {
	answer: "sent" as Sending["kind"],
	/** Why a refusal is given, when it says. */
	reason: undefined as "contact-changed" | undefined,
	until: 0,
	kept: "",
	held: [] as readonly Opened[],
	/** Where each ask came from, as the kind was given it. */
	from: [] as unknown[],
};
/** A counting kind that sends a challenge: its proof is the code the challenge kept. */
const pinged = defineModule({ name: "kind-ping" }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "ping",
		amr: ["otp"],
		addsSecondFactor: true,
		guessable: true,
		counts: true,
		enroll: async (_subject, held, from) => {
			ping.from.push(from);
			ping.held = held;
			return { secret: `p${held.length}`, show: {} };
		},
		challenge: async (_subject, factor, until, from) => {
			ping.from.push(from);
			ping.until = until;
			if (ping.answer === "refused" && ping.reason) return { kind: "refused", reason: ping.reason };
			if (ping.answer !== "sent") return { kind: ping.answer };
			ping.kept = randomBytes(6).toString("hex");
			return { kind: "sent" as const, show: { to: factor.secret }, kept: ping.kept };
		},
		// A binding's first proof is its secret; every later one is the code its challenge kept.
		verify: async (secret, _state, proof, kept) =>
			proof === (kept ?? secret)
				? { kind: "valid" as const, state: proof }
				: { kind: "invalid" as const },
	})),
]);

/** A counting kind whose first proof names a credential no two factors may hold. */
const card = defineModule({ name: "kind-card" }, (m) => [
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

/** How the told kind answers its next enrolment; its secret is the value no two factors may hold. */
const told = { answer: undefined as Enrolled | undefined };
const toldKind = defineModule({ name: "kind-told" }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "told",
		amr: ["otp"],
		addsSecondFactor: true,
		guessable: true,
		counts: true,
		uniqueSecret: (factor) => factor.secret,
		enroll: async () => told.answer ?? { secret: "t1", show: {} },
		verify: async (secret, _state, proof) =>
			proof === secret ? { kind: "valid" as const, state: null } : { kind: "invalid" as const },
	})),
]);
/** A way back that will not enrol now. */
const stuck = defineModule({ name: "kind-stuck" }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "stuck",
		amr: [],
		addsSecondFactor: true,
		guessable: false,
		counts: false,
		enroll: async () => ({ kind: "limited" as const }),
		verify: async () => ({ kind: "invalid" as const }),
	})),
]);

/** A module holding sessions to the factors, as `mfa-entry` does in an app. */
const enforcer = defineModule({ name: "enforcer" }, (m) => [
	m.contribute(enforcers).by(() => ({ name: "enforcer" })),
]);

async function serve(
	settings: Partial<MfaSettings> = {},
	{
		steps = [step],
		kinds = [code, backup],
		extra = [] as Module[],
		enforced = true,
		store = undefined as Module | undefined,
	} = {},
) {
	const audit = auditStandIn();
	const place = memoryFactors();
	const app = await assemble({
		modules: [
			http,
			audit.module,
			subjectRevocationStandIn,
			store ?? place.module,
			sealModule,
			sessionStandIn,
			gatesModule,
			mfaModule,
			...kinds,
			...steps,
			...(enforced ? [enforcer] : []),
			...extra,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			...sealConfig(),
			...mfaConfig(settings),
		},
		runtime,
	});
	stop = () => app.stop(1000);
	// mfa's three faces, as one for these tests.
	const decided: Decisions = {
		...(app.get(factorReading) as FactorReading & UnclaimedReading),
		...app.get(factorBinding),
		...app.get(factorManaging),
	};
	/** A code binding begun and proved for the subject, not yet bound. */
	const provedCode = async (subject: string, passed?: string) => {
		const begun = await decided.begin(subject, "code", passed, "t");
		if (begun.kind !== "begun") throw new Error(begun.kind);
		const secret = String((begun.show as { secret: string }).secret);
		const proved = await decided.provePending(subject, begun.pending, `${secret}:0`);
		if (proved.kind !== "valid") throw new Error(proved.kind);
		return { pending: begun.pending, state: proved.state, secret };
	};
	/** Binds a code factor for the subject, and answers it with its secret. */
	const bindCode = async (subject: string, label?: string, passed?: string) => {
		const { pending, state, secret } = await provedCode(subject, passed);
		const bound = await decided.bind(subject, pending, state, label);
		if (bound.kind !== "bound") throw new Error(bound.kind);
		// The codes are the reissue's to write, as an enrollment asks it.
		if (bound.codesDue) await decided.reissue(subject, bound.fence);
		return { ...bound, secret };
	};
	/** Binds a factor of the kind, its first proof being `proof`. */
	const bindKind = async (subject: string, kind: string, proof: string) => {
		const begun = await decided.begin(subject, kind);
		if (begun.kind !== "begun") throw new Error(begun.kind);
		const proved = await decided.provePending(subject, begun.pending, proof);
		if (proved.kind !== "valid") throw new Error(proved.kind);
		const bound = await decided.bind(subject, begun.pending, proved.state);
		if (bound.kind === "bound" && bound.codesDue) await decided.reissue(subject, bound.fence);
		return bound;
	};
	/** The identifier of the subject's first factor of the kind. */
	const idOf = async (subject: string, kind: string) =>
		(await decided.held(subject)).find((f) => f.kind === kind)?.id ?? "";
	return {
		app,
		decided,
		provedCode,
		bindCode,
		bindKind,
		idOf,
		events: audit.events,
		place,
	};
}

describe("decisions on the subject's factors", () => {
	it("binds in three steps, refusing a kind that does not count, and unavailable on another subject's pending", async () => {
		const { decided } = await serve({ mode: "required" });
		expect(await decided.asks("zed")).toBe("binding");
		expect((await decided.begin("zed", "backup")).kind).toBe("unknown-kind");
		const begun = await decided.begin("zed", "code");
		if (begun.kind !== "begun") throw new Error(begun.kind);
		const secret = String((begun.show as { secret: string }).secret);
		expect((await decided.provePending("zed", begun.pending, "x:0")).kind).toBe("invalid");
		// The pending is kept by mfa-flows for its own subject: one that will not open is a fault, not a guess.
		await expect(decided.provePending("amy", begun.pending, `${secret}:0`)).rejects.toSatisfy(
			isUnavailable,
		);
		await expect(decided.bind("amy", begun.pending, null)).rejects.toSatisfy(isUnavailable);
		const proved = await decided.provePending("zed", begun.pending, `${secret}:0`);
		if (proved.kind !== "valid") throw new Error(proved.kind);
		const bound = await decided.bind("zed", begun.pending, proved.state, "phone");
		if (bound.kind !== "bound") throw new Error(bound.kind);
		// What the binding adds is its first proof's amr, answered by `provePending`.
		expect("amr" in bound).toBe(false);
		// The binding writes no codes: they are due, for the reissue to write.
		expect([bound.codesDue, "recoveryCodes" in bound]).toEqual([true, false]);
		expect((await decided.held("zed")).map((f) => f.kind)).toEqual(["code"]);
		expect((await decided.reissue("zed", bound.fence)).kind).toBe("reissued");
		expect(await decided.asks("zed")).toBe("proof");
	});

	it("refuses a proof used before, and a binding past the limit", async () => {
		const { decided, bindCode } = await serve({ "max-factors": 2 });
		const bound = await bindCode("zed");
		expect((await decided.begin("zed", "code")).kind).toBe("full");
		const proof = `${bound.secret}:1`;
		expect(await decided.prove("zed", bound.factor.id, proof)).toEqual({
			kind: "valid",
			amr: ["otp", "mfa"],
		});
		expect((await decided.prove("zed", bound.factor.id, proof)).kind).toBe("replayed");
	});

	it("passes only one of two racing uses of a proof", async () => {
		const { decided, bindCode, place } = await serve();
		const bound = await bindCode("kim");
		// Another request uses the next proof between this one's read and its write.
		place.raceNextChange((record) => {
			const { factors: all } = record as unknown as { factors: { id: string }[] };
			const used = all.map((f) => (f.id === bound.factor.id ? { ...f, state: 1 } : f));
			return { ...record, factors: used };
		});
		expect((await decided.prove("kim", bound.factor.id, `${bound.secret}:1`)).kind).toBe("raced");
	});

	it("binds nothing begun before the subject's factors were cleared, nor while a clear lands", async () => {
		const { decided, bindCode, provedCode, place } = await serve();
		await bindCode("ivy");
		const before = await provedCode("ivy");
		await decided.clear("ivy");
		expect(await decided.bind("ivy", before.pending, before.state)).toEqual({ kind: "fenced" });
		expect(await decided.held("ivy")).toEqual([]);
		// Even a subject that held nothing: the clear is counted all the same.
		const none = await provedCode("una");
		await decided.clear("una");
		expect(await decided.bind("una", none.pending, none.state)).toEqual({ kind: "fenced" });
		expect(await decided.held("una")).toEqual([]);
		// A clear that lands between the check and the write: the write sees it.
		await bindCode("eve");
		const racing = await provedCode("eve");
		place.raceNextChange((record) => ({ ...record, factors: [], fences: 1 }));
		expect(await decided.bind("eve", racing.pending, racing.state)).toEqual({ kind: "fenced" });
		expect(await decided.held("eve")).toEqual([]);
	});

	it("binds nothing begun before the subject's fence moved, as a revocation moves it", async () => {
		const { decided, bindCode, provedCode } = await serve();
		await bindCode("lia");
		const before = await provedCode("lia");
		await decided.fence("lia");
		expect(await decided.bind("lia", before.pending, before.state)).toEqual({ kind: "fenced" });
		expect((await decided.held("lia")).filter((f) => f.kind === "code")).toHaveLength(1);
		// A subject holding nothing is fenced as well.
		const none = await provedCode("ned");
		await decided.fence("ned");
		expect(await decided.bind("ned", none.pending, none.state)).toEqual({ kind: "fenced" });
		expect(await decided.held("ned")).toEqual([]);
	});

	it("removes or reissues nothing for a fence read before it moved", async () => {
		const { decided, bindCode, idOf } = await serve();
		await bindCode("rio");
		const read = await decided.fenceOf("rio");
		await decided.fence("rio");
		const code = await idOf("rio", "code");
		expect(await decided.remove("rio", code, read)).toBe("fenced");
		expect(await decided.reissue("rio", read)).toEqual({ kind: "fenced" });
		expect((await decided.held("rio")).map((f) => f.kind).sort()).toEqual(["backup", "code"]);
		const now = await decided.fenceOf("rio");
		expect((await decided.reissue("rio", now)).kind).toBe("reissued");
		await bindCode("rio");
		expect(await decided.remove("rio", code, now)).toBe("removed");
	});

	it("answers unavailable when it cannot move the fence", async () => {
		const { decided, place } = await serve();
		place.down.unavailable("update", "save");
		await expect(decided.fence("ola")).rejects.toSatisfy(isUnavailable);
	});

	it("counts a reset and a fence landing together, each once", async () => {
		const { decided, bindCode, place } = await serve();
		await bindCode("pia");
		// A reset's clear lands while the fence is written; the fence reads again.
		place.raceNextChange((record) => {
			const fences = (record as unknown as { fences?: number }).fences ?? 0;
			return { ...record, factors: [], fences: fences + 1 };
		});
		await decided.fence("pia");
		const stored = (await place.factors.read(listKeyOf("pia"))) as unknown as { fences?: number };
		expect(stored.fences).toBe(2);
		expect(await decided.held("pia")).toEqual([]);
	});

	it("answers whether a factor can be guessed", async () => {
		const { decided, bindCode, idOf } = await serve();
		const bound = await bindCode("zed");
		expect(await decided.guessable("zed", bound.factor.id)).toBe(true);
		expect(await decided.guessable("zed", await idOf("zed", "backup"))).toBe(false);
		expect(await decided.guessable("zed", "none")).toBeUndefined();
	});

	it("tells whether every guessable factor was bound after a time, taking an unknown kind or a record with no time as bound before", async () => {
		const { decided, bindCode, bindKind, idOf, place } = await serve(
			{},
			{ kinds: [code, backup, key] },
		);
		expect(await decided.guessableBoundAfter("ivy", runtime.clock.now())).toBe(true);
		await bindKind("kai", "key", "k:hwk");
		expect(await decided.guessableBoundAfter("kai", runtime.clock.now() + 60_000)).toBe(true);
		const before = runtime.clock.now();
		await bindCode("ivy");
		const after = runtime.clock.now();
		expect(await decided.guessableBoundAfter("ivy", before - 1)).toBe(true);
		expect(await decided.guessableBoundAfter("ivy", after)).toBe(false);
		/** Rewrites the subject's factors as another request would, while one of them is renamed. */
		const rewritten = async (subject: string, each: (f: Record<string, unknown>) => object) => {
			place.raceNextChange((record) => {
				const { factors: all } = record as unknown as { factors: Record<string, unknown>[] };
				return { ...record, factors: all.map(each) };
			});
			await decided.rename(subject, await idOf(subject, "backup"), "spare");
		};
		await rewritten("ivy", (f) => (f.kind === "code" ? { ...f, kind: "gone" } : f));
		expect(await decided.guessableBoundAfter("ivy", before - 1)).toBe(false);
		await bindCode("jo");
		await rewritten("jo", ({ boundAt: _, ...f }) => f);
		expect(await decided.guessableBoundAfter("jo", 0)).toBe(false);
	});

	it("takes a kind that does not say whether guessing beats it as one guessing does, as 0.17 did", async () => {
		/** A kind written without the declaration, as untyped code could contribute one. */
		const silent = defineModule({ name: "kind-silent" }, (m) => [
			m.contribute(factorKinds).by(
				() =>
					({
						kind: "silent",
						amr: ["hwk"],
						addsSecondFactor: true,
						counts: true,
						enroll: async () => ({ secret: "s", show: {} }),
						verify: async () => ({ kind: "valid" as const, state: null }),
					}) as never,
			),
		]);
		const { decided, bindKind, idOf } = await serve({}, { kinds: [code, backup, silent] });
		const before = runtime.clock.now();
		await bindKind("ola", "silent", "x");
		expect(await decided.guessable("ola", await idOf("ola", "silent"))).toBe(true);
		shift += 1000;
		expect(await decided.guessableBoundAfter("ola", before + 500)).toBe(false);
	});

	it("requires a second factor where the section leaves the mode unset, as 0.17 did", async () => {
		const { decided } = await serve({ mode: undefined });
		expect(await decided.asks("zed")).toBe("binding");
	});

	it("keeps the last counting factor under required mode, and renames", async () => {
		const { decided, bindCode } = await serve({ mode: "required" });
		const bound = await bindCode("zed");
		expect(await decided.remove("zed", bound.factor.id, await decided.fenceOf("zed"))).toBe("last");
		expect(await decided.rename("zed", bound.factor.id, "work")).toBe("renamed");
		expect(await decided.rename("zed", "none", "work")).toBe("unknown");
		expect((await decided.held("zed")).find((f) => f.id === bound.factor.id)?.label).toBe("work");
	});

	it("asks nothing of a subject without factors under optional mode, and replaces the recovery codes", async () => {
		const { decided, bindCode, idOf } = await serve();
		expect(await decided.asks("ann")).toBe("nothing");
		expect((await decided.reissue("ann", await decided.fenceOf("ann"))).kind).toBe(
			"no-qualifying-factor",
		);
		const bound = await bindCode("ann");
		expect(await decided.asks("ann")).toBe("proof");
		expect(await decided.asks("amy")).toBe("nothing");
		const reissued = await decided.reissue("ann", await decided.fenceOf("ann"));
		if (reissued.kind !== "reissued") throw new Error(reissued.kind);
		expect((await decided.held("ann")).filter((f) => f.kind === "backup")).toHaveLength(1);
		expect((await decided.prove("ann", await idOf("ann", "backup"), "b1")).kind).toBe("valid");
		expect(await decided.remove("ann", bound.factor.id, await decided.fenceOf("ann"))).toBe(
			"removed",
		);
		expect(await decided.remove("ann", bound.factor.id, await decided.fenceOf("ann"))).toBe(
			"unknown",
		);
	});

	it("answers no proof valid while its state cannot be written, records nothing, and takes it once it can", async () => {
		const { decided, bindCode, idOf, place, events } = await serve();
		const bound = await bindCode("una");
		const backupId = await idOf("una", "backup");
		const before = events.length;
		place.down.unavailable("update");
		for (const [factor, proof] of [
			[bound.factor.id, `${bound.secret}:1`],
			[backupId, "b1"],
		] as const) {
			await expect(decided.prove("una", factor, proof), factor).rejects.toThrow(Unavailable);
		}
		place.down.restore();
		expect(events.slice(before)).toEqual([]);
		expect((await decided.prove("una", bound.factor.id, `${bound.secret}:1`)).kind).toBe("valid");
		expect((await decided.prove("una", backupId, "b1")).kind).toBe("valid");
	});

	it("records a binding, the recovery codes issued, a recovery code used and a removal, never a secret", async () => {
		const { decided, bindCode, idOf, events } = await serve();
		const bound = await bindCode("ida");
		const backupId = await idOf("ida", "backup");
		expect((await decided.prove("ida", backupId, "b1")).kind).toBe("valid");
		expect((await decided.prove("ida", backupId, "b1")).kind).toBe("replayed");
		expect((await decided.prove("ida", bound.factor.id, `${bound.secret}:1`)).kind).toBe("valid");
		expect((await decided.reissue("ida", await decided.fenceOf("ida"))).kind).toBe("reissued");
		expect(await decided.remove("ida", bound.factor.id, await decided.fenceOf("ida"))).toBe(
			"removed",
		);
		expect(await decided.remove("ida", bound.factor.id, await decided.fenceOf("ida"))).toBe(
			"unknown",
		);
		const of = (kind: string, attributes: Record<string, string>) => ({
			kind,
			subject: "ida",
			attributes,
			at: expect.any(Number),
		});
		expect(events).toEqual([
			of("mfa.factor.enrolled", { kind: "code", factor: bound.factor.id }),
			of("mfa.recovery_codes.generated", { kind: "backup", regenerated: "false" }),
			of("mfa.recovery_code.used", { kind: "backup", factor: backupId, remaining: "1" }),
			of("mfa.recovery_codes.generated", { kind: "backup", regenerated: "true" }),
			of("mfa.factor.removed", { kind: "code", factor: bound.factor.id }),
		]);
		const written = JSON.stringify(events);
		expect([written.includes(bound.secret), /"b[12]"/.test(written)]).toEqual([false, false]);
	});

	it("records nothing for a refused binding, removal or reissue", async () => {
		const { decided, provedCode, bindCode, idOf, events } = await serve({
			mode: "required",
			"max-factors": 3,
		});
		expect((await decided.reissue("jon", await decided.fenceOf("jon"))).kind).toBe(
			"no-qualifying-factor",
		);
		expect(events).toEqual([]);
		const bound = await bindCode("jon");
		const [one, two] = [await provedCode("jon"), await provedCode("jon")];
		expect((await decided.bind("jon", one.pending, one.state)).kind).toBe("bound");
		events.length = 0;
		expect((await decided.bind("jon", two.pending, two.state)).kind).toBe("full");
		expect(await decided.remove("jon", "none", await decided.fenceOf("jon"))).toBe("unknown");
		expect(events).toEqual([]);
		expect(await decided.remove("jon", bound.factor.id, await decided.fenceOf("jon"))).toBe(
			"removed",
		);
		events.length = 0;
		expect(
			await decided.remove("jon", await idOf("jon", "code"), await decided.fenceOf("jon")),
		).toBe("last");
		expect(events).toEqual([]);
	});

	it("drops the recovery codes with the last counting factor, so a login no longer asks for them", async () => {
		const { decided, bindCode } = await serve();
		const one = await bindCode("liv");
		const two = await bindCode("liv");
		expect(await decided.remove("liv", one.factor.id, await decided.fenceOf("liv"))).toBe(
			"removed",
		);
		expect((await decided.held("liv")).map((f) => f.kind).sort()).toEqual(["backup", "code"]);
		expect(await decided.remove("liv", two.factor.id, await decided.fenceOf("liv"))).toBe(
			"removed",
		);
		expect(await decided.held("liv")).toEqual([]);
		expect(await decided.asks("liv")).toBe("nothing");
	});

	it("decides a reissue on the factors as written, so a racing removal of the last one leaves no codes alone", async () => {
		const { decided, bindCode, place, events } = await serve();
		await bindCode("max");
		events.length = 0;
		// Another request removes every factor before the reissue writes.
		place.raceNextChange((record) => ({ ...record, factors: [] }));
		expect(await decided.reissue("max", await decided.fenceOf("max"))).toEqual({
			kind: "no-qualifying-factor",
		});
		expect(await decided.held("max")).toEqual([]);
		expect(await decided.asks("max")).toBe("nothing");
		expect(events).toEqual([]);
	});

	it("counts the recovery codes a binding brings against the limit", async () => {
		const { decided, provedCode, bindCode, idOf } = await serve({ "max-factors": 2 });
		const first = await bindCode("kai");
		expect(
			await decided.remove("kai", await idOf("kai", "backup"), await decided.fenceOf("kai")),
		).toBe("removed");
		const { pending, state } = await provedCode("kai");
		expect(await decided.bind("kai", pending, state)).toEqual({ kind: "full" });
		expect(await decided.held("kai")).toEqual([first.factor]);
	});

	it("clears every factor of the subject, of any kind and written meanwhile, naming the kinds, and records nothing", async () => {
		const { decided, bindCode, place, events } = await serve({ mode: "required" });
		await bindCode("ray");
		await bindCode("ray");
		await bindCode("uma");
		events.length = 0;
		// Another request adds a factor of a kind this deployment does not know before the reset writes.
		place.raceNextChange((record) => {
			const { factors: all } = record as unknown as { factors: object[] };
			const foreign = { id: "x", kind: "gone", secret: "s", state: null };
			return { ...record, factors: [...all, foreign] };
		});
		expect(await decided.clear("ray")).toEqual({ count: 4, kinds: ["backup", "code", "gone"] });
		expect(await decided.held("ray")).toEqual([]);
		expect(await decided.asks("ray")).toBe("binding");
		expect((await decided.held("uma")).length).toBe(2);
		expect(await decided.clear("ray")).toEqual({ count: 0, kinds: [] });
		expect(await decided.clear("new")).toEqual({ count: 0, kinds: [] });
		expect(events).toEqual([]);
	});

	it("frees a cleared factor's unique value for another subject", async () => {
		const { decided, bindKind } = await serve({}, { kinds: [card] });
		expect((await bindKind("ada", "card", "c-1")).kind).toBe("bound");
		expect((await bindKind("bob", "card", "c-1")).kind).toBe("duplicate");
		expect(await decided.clear("ada")).toEqual({ count: 1, kinds: ["card"] });
		expect((await bindKind("bob", "card", "c-1")).kind).toBe("bound");
	});

	it("keeps no label that is not of the label's shape, judging it before the binding or the factor", async () => {
		const { decided, provedCode, bindCode } = await serve();
		const { factor } = await bindCode("eve");
		const proved = await provedCode("eve");
		const before = await decided.held("eve");
		for (const label of ["", "ph\none", "\u202ephone", "p".repeat(65)]) {
			const bound = await decided.bind("eve", proved.pending, proved.state, label);
			const renamed = await decided.rename("eve", factor.id, label);
			expect([label, bound, renamed]).toEqual([
				label,
				{ kind: "malformed-label" },
				"malformed-label",
			]);
		}
		expect(await decided.bind("eve", "gone", proved.state, "")).toEqual({
			kind: "malformed-label",
		});
		expect(await decided.rename("eve", "gone", "")).toBe("malformed-label");
		expect(await decided.held("eve")).toEqual(before);
		const named = await decided.bind("eve", proved.pending, proved.state, "desk");
		expect(named.kind === "bound" && named.factor.label).toBe("desk");
	});
});

it("declares mfa and the amr of every kind contributed as what it can prove", async () => {
	const { app } = await serve();
	expect(app.get(logins).achievable(["otp", "mfa"])).toBe(true);
	expect(app.get(logins).achievable(["hwk"])).toBe(false);
});

it("adds mfa only for a kind that adds a second factor, and keeps a proof's own amr to its kind's", async () => {
	const { decided, bindKind, idOf } = await serve({}, { kinds: [key, mail] });
	expect(await bindKind("ray", "mail", "m")).toMatchObject({ kind: "bound" });
	expect(await bindKind("ray", "key", "k:hwk")).toMatchObject({ kind: "bound" });
	expect(await decided.prove("ray", await idOf("ray", "mail"), "m")).toEqual({
		kind: "valid",
		amr: ["otp"],
	});
	const keyId = await idOf("ray", "key");
	expect(await decided.prove("ray", keyId, "k:swk")).toEqual({
		kind: "valid",
		amr: ["swk", "mfa"],
	});
	expect(await decided.prove("ray", keyId, "k:pwd")).toEqual({ kind: "valid", amr: ["mfa"] });
});

it("answers a binding's first proof with its own amr, kept to its kind's", async () => {
	const { decided } = await serve({}, { kinds: [key, mail] });
	for (const [kind, proof, amr] of [
		["key", "k:hwk", ["hwk", "mfa"]],
		["key", "k:pwd", ["mfa"]],
		["mail", "m", ["otp"]],
	] as const) {
		const begun = await decided.begin("ray", kind);
		if (begun.kind !== "begun") throw new Error(begun.kind);
		expect(await decided.provePending("ray", begun.pending, proof), proof).toMatchObject({
			kind: "valid",
			amr,
		});
	}
});

it("declares mfa only where a kind adds a second factor", async () => {
	const { app } = await serve({}, { kinds: [mail] });
	expect(app.get(logins).achievable(["otp"])).toBe(true);
	expect(app.get(logins).achievable(["mfa"])).toBe(false);
});

describe("recovery codes written by the reissue", () => {
	/** Binds a code factor for the subject, which writes no recovery codes. */
	const bindLater = async (h: Awaited<ReturnType<typeof serve>>, subject: string) => {
		const { pending, state } = await h.provedCode(subject);
		return h.decided.bind(subject, pending, state);
	};

	it("binds with no codes, answering the fence it began under and that codes are due; the reissue makes the first set", async () => {
		const h = await serve();
		const { decided, events } = h;
		const began = await decided.fenceOf("ana");
		const bound = await bindLater(h, "ana");
		if (bound.kind !== "bound") throw new Error(bound.kind);
		expect([bound.fence, bound.codesDue, "recoveryCodes" in bound]).toEqual([began, true, false]);
		expect((await decided.held("ana")).map((f) => f.kind)).toEqual(["code"]);
		const first = await decided.reissue("ana", bound.fence);
		if (first.kind !== "reissued") throw new Error(first.kind);
		expect((await decided.held("ana")).map((f) => f.kind)).toEqual(["code", "backup"]);
		// A subject holding codes owes none: a further binding answers nothing due.
		const again = await bindLater(h, "ana");
		expect(again.kind === "bound" && again.codesDue).toBe(false);
		expect((await decided.reissue("ana", await decided.fenceOf("ana"))).kind).toBe("reissued");
		expect(events.map((e) => [e.kind, e.attributes?.regenerated])).toEqual([
			["mfa.factor.enrolled", undefined],
			["mfa.recovery_codes.generated", "false"],
			["mfa.factor.enrolled", undefined],
			["mfa.recovery_codes.generated", "true"],
		]);
	});

	it("writes no codes for a fence that moved after the binding began", async () => {
		const h = await serve();
		const bound = await bindLater(h, "bea");
		if (bound.kind !== "bound") throw new Error(bound.kind);
		await h.decided.fence("bea");
		expect(await h.decided.reissue("bea", bound.fence)).toEqual({ kind: "fenced" });
		expect((await h.decided.held("bea")).map((f) => f.kind)).toEqual(["code"]);
	});

	it("keeps the codes a place: a binding of a subject holding none counts them against the limit", async () => {
		const h = await serve({ "max-factors": 2 });
		const bound = await bindLater(h, "cal");
		expect(bound.kind === "bound" && bound.codesDue).toBe(true);
		expect(await bindLater(h, "cal")).toEqual({ kind: "full" });
		expect((await h.decided.reissue("cal", await h.decided.fenceOf("cal"))).kind).toBe("reissued");
	});

	it("adds no first set past the limit, decided on the factors as written", async () => {
		const h = await serve({ "max-factors": 2 });
		await bindLater(h, "dax");
		h.events.length = 0;
		// Another binding takes the place kept for the codes before the reissue writes.
		h.place.raceNextChange((record) => {
			const { factors: all } = record as unknown as { factors: { id: string }[] };
			return { ...record, factors: [...all, { ...all[0], id: "other" }] };
		});
		expect(await h.decided.reissue("dax", await h.decided.fenceOf("dax"))).toEqual({
			kind: "full",
		});
		expect((await h.decided.held("dax")).map((f) => f.kind)).toEqual(["code", "code"]);
		expect(h.events).toEqual([]);
	});

	it("keeps one place for two bindings at once of a subject holding no codes, where the first set lands", async () => {
		const h = await serve({ "max-factors": 4 });
		// A first factor, its codes not yet written; two more bind at once, neither as the first.
		await bindLater(h, "fia");
		const [one, two] = [await h.provedCode("fia"), await h.provedCode("fia")];
		const bound = await Promise.all([
			h.decided.bind("fia", one.pending, one.state),
			h.decided.bind("fia", two.pending, two.state),
		]);
		expect(bound.map((b) => b.kind === "bound" && b.codesDue)).toEqual([true, true]);
		const first = await h.decided.reissue("fia", await h.decided.fenceOf("fia"));
		expect(first.kind).toBe("reissued");
		expect((await h.decided.held("fia")).map((f) => f.kind).sort()).toEqual([
			"backup",
			"code",
			"code",
			"code",
		]);
		// The second reissue replaces the set: it takes no further place.
		expect((await h.decided.reissue("fia", await h.decided.fenceOf("fia"))).kind).toBe("reissued");
		expect(await h.decided.held("fia")).toHaveLength(4);
	});

	it("owes no codes where no way back is composed", async () => {
		const h = await serve({}, { kinds: [code] });
		const bound = await bindLater(h, "eve");
		expect(bound.kind === "bound" && bound.codesDue).toBe(false);
	});
});

describe("challenges sent before a proof", () => {
	afterEach(() => {
		ping.answer = "sent";
		ping.reason = undefined;
	});

	it("sends the kind's challenge sealed, and judges the proof with what it kept", async () => {
		const { decided, bindKind, idOf } = await serve({}, { kinds: [pinged] });
		await bindKind("una", "ping", "p0");
		const factor = await idOf("una", "ping");
		const sent = await decided.challenge("una", factor, 1234);
		if (sent.kind !== "sent") throw new Error(sent.kind);
		expect([sent.factorKind, sent.show, ping.until]).toEqual(["ping", { to: "p0" }, 1234]);
		expect(sent.sealed).not.toContain(ping.kept);
		expect((await decided.prove("una", factor, ping.kept)).kind).toBe("invalid");
		await expect(decided.prove("una", factor, ping.kept, "forged")).rejects.toSatisfy(
			isUnavailable,
		);
		expect(await decided.prove("una", factor, ping.kept, sent.sealed)).toEqual({
			kind: "valid",
			amr: ["otp", "mfa"],
		});
	});

	it("opens a challenge only for the subject and factor it was sent for, and is unavailable on another", async () => {
		const { decided, bindKind, idOf } = await serve({}, { kinds: [pinged] });
		await bindKind("una", "ping", "p0");
		await bindKind("una", "ping", "p1");
		await bindKind("vic", "ping", "p0");
		const [first, second] = (await decided.held("una")).map((f) => f.id);
		const theirs = await decided.challenge("vic", await idOf("vic", "ping"), 1);
		if (theirs.kind !== "sent") throw new Error(theirs.kind);
		await expect(decided.prove("una", first ?? "", ping.kept, theirs.sealed)).rejects.toSatisfy(
			isUnavailable,
		);
		const mine = await decided.challenge("una", first ?? "", 1);
		if (mine.kind !== "sent") throw new Error(mine.kind);
		await expect(decided.prove("una", second ?? "", ping.kept, mine.sealed)).rejects.toSatisfy(
			isUnavailable,
		);
	});

	it("answers none for a kind that sends no challenge, unknown for no such factor, and the kind's refusal with its reason", async () => {
		const { decided, bindCode, bindKind, idOf } = await serve(
			{},
			{ kinds: [code, backup, pinged] },
		);
		const bound = await bindCode("wes");
		expect(await decided.challenge("wes", bound.factor.id, 1)).toEqual({ kind: "none" });
		expect(await decided.challenge("wes", "none", 1)).toEqual({ kind: "unknown" });
		expect(await decided.challenge("amy", bound.factor.id, 1)).toEqual({ kind: "unknown" });
		await bindKind("wes", "ping", "p0");
		const factor = await idOf("wes", "ping");
		ping.answer = "limited";
		expect(await decided.challenge("wes", factor, 1)).toEqual({ kind: "limited" });
		ping.answer = "refused";
		expect(await decided.challenge("wes", factor, 1)).toEqual({
			kind: "refused",
			factorKind: "ping",
		});
		ping.reason = "contact-changed";
		expect(await decided.challenge("wes", factor, 1)).toEqual({
			kind: "refused",
			factorKind: "ping",
			reason: "contact-changed",
		});
	});

	it("gives a kind the subject's factors of that kind when it enrols one", async () => {
		const { bindKind } = await serve({}, { kinds: [code, backup, pinged] });
		await bindKind("xia", "ping", "p0");
		expect(ping.held).toEqual([]);
		await bindKind("xia", "ping", "p1");
		expect(ping.held).toEqual([{ secret: "p0", state: "p0" }]);
	});
});

describe("values no two factors may hold", () => {
	it("refuses a factor whose value another subject's factor holds, leaving nothing of it", async () => {
		const { decided, bindKind, idOf, events } = await serve({}, { kinds: [card, backup] });
		expect(await bindKind("ann", "card", "c1")).toMatchObject({ kind: "bound" });
		events.length = 0;
		expect(await bindKind("bob", "card", "c1")).toEqual({ kind: "duplicate" });
		expect(await bindKind("ann", "card", "c1")).toEqual({ kind: "duplicate" });
		expect([await decided.held("bob"), events]).toEqual([[], []]);
		expect(await bindKind("bob", "card", "c2")).toMatchObject({ kind: "bound" });
		expect(
			await decided.remove("ann", await idOf("ann", "card"), await decided.fenceOf("ann")),
		).toBe("removed");
		expect(await bindKind("bob", "card", "c1")).toMatchObject({ kind: "bound" });
	});

	it("counts a factor of a unique value once its claim names it; one written before claims, unless another holds it", async () => {
		const { decided, bindKind, place } = await serve({}, { kinds: [card, backup] });
		await bindKind("ann", "card", "c1");
		// A duplicate writes neither the factor nor a claim.
		expect(await bindKind("bob", "card", "c1")).toEqual({ kind: "duplicate" });
		expect(await decided.countingWritten("bob")).toBe(false);
		expect(await bindKind("cid", "card", "c2")).toMatchObject({ kind: "bound" });
		expect([await decided.countingWritten("ann"), await decided.countingWritten("cid")]).toEqual([
			true,
			true,
		]);
		// Its claim missing, as 0.18 left one whose claim was never made: it may yet be another's.
		await place.records.remove(claimKeyOf("card", "c2"));
		expect(await decided.countingWritten("cid")).toBe(false);
		// A factor written before claims were kept carries no mark: it counts unless another holds its value.
		const unmarked = (record: StoredFactors) => {
			const list = record as unknown as { factors: { claims?: true }[] };
			const factors = list.factors.map(({ claims: _, ...rest }) => rest);
			return { value: { ...list, factors } as unknown as StoredFactors };
		};
		expect(await bindKind("dee", "card", "c3")).toMatchObject({ kind: "bound" });
		await place.factors.update(listKeyOf("dee"), unmarked);
		await place.records.remove(claimKeyOf("card", "c3"));
		expect(await decided.countingWritten("dee")).toBe(true);
		expect(await bindKind("eve", "card", "c3")).toMatchObject({ kind: "bound" });
		expect([await decided.countingWritten("dee"), await decided.countingWritten("eve")]).toEqual([
			false,
			true,
		]);
	});

	it("refuses removing the last factor that stands beside a factor whose claim is missing", async () => {
		const { decided, bindKind, bindCode, idOf, place } = await serve(
			{ mode: "required" },
			{ kinds: [code, backup, card] },
		);
		await bindCode("zed");
		expect(await bindKind("zed", "card", "c1")).toMatchObject({ kind: "bound" });
		// Its claim missing, as 0.18 left one: the card does not stand for zed.
		await place.records.remove(claimKeyOf("card", "c1"));
		const fence = await decided.fenceOf("zed");
		expect(await decided.remove("zed", await idOf("zed", "code"), fence)).toBe("last");
		expect((await decided.held("zed")).map((f) => f.kind)).toContain("code");
	});

	it("refuses a first binding another counting factor beat to the subject, binding nothing and recording it", async () => {
		const { decided, provedCode, bindCode, events } = await serve({ mode: "required" });
		const beaten = await provedCode("liz");
		await bindCode("liz");
		events.length = 0;
		expect(await decided.bind("liz", beaten.pending, beaten.state)).toEqual({
			kind: "first-binding-closed",
		});
		expect((await decided.held("liz")).filter((f) => f.kind === "code")).toHaveLength(1);
		expect(events).toEqual([
			expect.objectContaining({
				kind: "mfa.first_binding_conflict",
				subject: "liz",
				attributes: { kind: "code", reason: "competing" },
			}),
		]);
		// Begun once one counts, a binding is no first one, and binds beside it.
		const later = await provedCode("liz");
		expect((await decided.bind("liz", later.pending, later.state)).kind).toBe("bound");
	});

	it("binds a binding asked from a login only as the subject's first, whenever it began", async () => {
		const { decided, bindCode, provedCode, events } = await serve({ mode: "required" });
		await bindCode("ned");
		events.length = 0;
		const login = { kind: "login" } as const;
		expect(await decided.begin("ned", "code", undefined, undefined, login)).toEqual({
			kind: "first-binding-closed",
		});
		expect(events).toEqual([
			expect.objectContaining({
				kind: "mfa.first_binding_conflict",
				subject: "ned",
				attributes: { kind: "code", reason: "competing" },
			}),
		]);
		// A pending begun beside a counting factor, as one begun before a login could be refused.
		const begun = await provedCode("ned");
		expect(await decided.bind("ned", begun.pending, begun.state, undefined, login)).toEqual({
			kind: "first-binding-closed",
		});
		expect((await decided.held("ned")).filter((f) => f.kind === "code")).toHaveLength(1);
		const session = { kind: "session", handle: "h" } as const;
		expect((await decided.bind("ned", begun.pending, begun.state, undefined, session)).kind).toBe(
			"bound",
		);
	});

	it("binds one of two first bindings finished at once, refusing the other", async () => {
		const { decided, provedCode } = await serve({ mode: "required" });
		const [one, two] = [await provedCode("mo"), await provedCode("mo")];
		const bound = await Promise.all([
			decided.bind("mo", one.pending, one.state),
			decided.bind("mo", two.pending, two.state),
		]);
		expect(bound.map((b) => b.kind).sort()).toEqual(["bound", "first-binding-closed"]);
	});

	it("binds only one of two factors of one value bound at once", async () => {
		const { decided, events } = await serve({}, { kinds: [card, backup] });
		const proved = async (subject: string) => {
			const begun = await decided.begin(subject, "card");
			if (begun.kind !== "begun") throw new Error(begun.kind);
			const valid = await decided.provePending(subject, begun.pending, "c1");
			if (valid.kind !== "valid") throw new Error(valid.kind);
			return () => decided.bind(subject, begun.pending, valid.state);
		};
		/** Binds the value for each subject at once; answers the subject left holding it. */
		const race = async (subjects: string[]) => {
			const binds = await Promise.all(subjects.map(proved));
			const bound = await Promise.all(binds.map((bind) => bind()));
			expect(bound.map((b) => b.kind).sort()).toEqual(["bound", "duplicate"]);
			// The duplicate leaves nothing; the binding writes no codes beside the one bound.
			const held = await Promise.all(subjects.map((subject) => decided.held(subject)));
			expect(held.flat().map((f) => f.kind)).toEqual(["card"]);
			return subjects[bound.findIndex((b) => b.kind === "bound")] ?? "";
		};
		const first = await race(["cat", "dan"]);
		expect(events.filter((e) => e.kind === "mfa.factor.enrolled")).toHaveLength(1);
		// Once the factor holding it goes, two new ones race for its stale claim.
		const [gone] = (await decided.held(first)).filter((f) => f.kind === "card");
		expect(await decided.remove(first, gone?.id ?? "", await decided.fenceOf(first))).toBe(
			"removed",
		);
		await race(["eli", "fay"]);
	});
});

describe("a binding begun", () => {
	afterEach(() => {
		told.answer = undefined;
	});

	it("answers the kind's limit or refusal, and a secret whose value another factor holds as duplicate", async () => {
		const { decided, bindKind, idOf } = await serve({}, { kinds: [toldKind, backup] });
		told.answer = { kind: "limited" };
		expect(await decided.begin("ann", "told")).toEqual({ kind: "limited" });
		told.answer = { kind: "refused" };
		expect(await decided.begin("ann", "told")).toEqual({ kind: "refused" });
		// What a kind adds to its answer is not passed on.
		told.answer = { kind: "duplicate", why: "same address" } as Enrolled;
		expect(await decided.begin("ann", "told")).toEqual({ kind: "duplicate" });
		told.answer = undefined;
		expect(await bindKind("ann", "told", "t1")).toMatchObject({ kind: "bound" });
		expect(await decided.begin("bob", "told")).toEqual({ kind: "duplicate" });
		expect(await decided.begin("ann", "told")).toEqual({ kind: "duplicate" });
		expect(
			await decided.remove("ann", await idOf("ann", "told"), await decided.fenceOf("ann")),
		).toBe("removed");
		expect((await decided.begin("bob", "told")).kind).toBe("begun");
	});

	it("writes no codes when the way back will not enrol, as when the store cannot answer, the factor standing", async () => {
		const { decided, provedCode } = await serve({}, { kinds: [code, stuck] });
		const { pending, state } = await provedCode("cal");
		const bound = await decided.bind("cal", pending, state);
		if (bound.kind !== "bound") throw new Error(bound.kind);
		await expect(decided.reissue("cal", bound.fence)).rejects.toThrow(Unavailable);
		expect((await decided.held("cal")).map((f) => f.kind)).toEqual(["code"]);
	});
});

it("refuses to start under required when no composed kind counts", async () => {
	const told = defineModule({ name: "kind-told" }, (m) => [
		m.contribute(factorKinds).by(() => ({
			kind: "told",
			amr: ["sms"],
			addsSecondFactor: false,
			guessable: false,
			counts: true,
			enroll: async () => ({ secret: "s", show: {} }),
			verify: async () => ({ kind: "valid" as const, state: null }),
		})),
	]);
	// A kind that counts but adds no second factor is mfa-entry's to refuse; one that counts at all is mfa's.
	await expect(serve({ mode: "required" }, { kinds: [told, backup] })).resolves.toBeDefined();
	const refused = await serve({ mode: "required" }, { kinds: [backup] }).catch((e) => e);
	expect(refused).toBeInstanceOf(BootRefused);
	expect((refused as BootRefused).refusals.map((r) => r.where)).toEqual(["mfa.mode"]);
	await expect(serve({ mode: "optional" }, { kinds: [backup] })).resolves.toBeDefined();
});

it("refuses to start without a module holding sessions to the factors, whatever the mode", async () => {
	for (const mode of ["required", "optional"] as const) {
		const refused = await serve({ mode }, { enforced: false }).catch((e) => e);
		expect(refused, mode).toBeInstanceOf(BootRefused);
		expect((refused as BootRefused).refusals).toEqual([
			{
				where: "mfa",
				reason: "mfa needs a module holding sessions to its factors; compose mfa-entry",
			},
		]);
	}
});

it("refuses to start over a factor store that cannot write a list and a claim as one", async () => {
	const { factors } = memoryFactors();
	const { updateTogether: _, ...lacking } = factors;
	const store = defineModule({ name: "factor-store" }, (m) => [
		m.provide(factorStore).by(() => lacking as FactorStore),
	]);
	const refused = await serve({}, { store }).catch((error) => error);
	expect(refused).toBeInstanceOf(BootRefused);
	expect((refused as BootRefused).refusals).toEqual([
		{
			where: "mfa",
			reason: "its factor store cannot write a list and a claim as one (updateTogether)",
		},
	]);
});

it("refuses to start without a step that proves factors, naming what it lacks", async () => {
	const refused = await serve({}, { steps: [] }).catch((error) => error);
	expect(refused).toBeInstanceOf(BootRefused);
	expect((refused as BootRefused).refusals.map((r) => r.where)).toEqual(["mfa.proof-steps"]);
});

it("accepts as a label 1 to 64 characters, well formed, with no line break, control or bidirectional control", () => {
	const fits = [
		"phone",
		"a".repeat(64),
		"\u{1f511}".repeat(64),
		" ~\u00a0\u061b\u061d\u200d\u2010\u2027\u202f\u2065\u206a",
	];
	expect(fits.filter((label) => !isLabel(label))).toEqual([]);
	const refused = ["", "a".repeat(65), "\u{1f511}".repeat(65), "\ud800", "x\udc00"];
	const breaking = ["\u0000", "\n", "\u001f", "\u007f", "\u009f", "\u2028", "\u2029"];
	const reordering = ["\u061c", "\u200e", "\u200f", "\u202a", "\u202e", "\u2066", "\u2069"];
	const marked = [...breaking, ...reordering].map((c) => `desk${c}top`);
	expect([...refused, ...marked].filter((label) => isLabel(label))).toEqual([]);
});

it("passes where an ask came from to the kind unread", async () => {
	const { decided, bindKind, idOf } = await serve({}, { kinds: [code, backup, pinged] });
	const login = { kind: "login", email: "ann@example.test" } as const;
	const session = { kind: "session", handle: "h1" } as const;
	ping.from.length = 0;
	const begun = await decided.begin("nobody", "ping", undefined, undefined, session);
	expect([begun.kind, ping.from]).toEqual(["begun", [session]]);
	await bindKind("nobody", "ping", "p0");
	ping.from.length = 0;
	await decided.challenge("nobody", await idOf("nobody", "ping"), 1, login);
	expect(ping.from).toEqual([login]);
});

describe("a gate contributed before a first counting factor", () => {
	const asked: unknown[] = [];
	const gate = defineModule({ name: "gate" }, (m) => [
		m.contribute(firstBindingGates).by(() => ({
			admits: async (ask) => {
				asked.push(ask);
				return ask.passed === "ok";
			},
		})),
	]);

	it("asks the gate with what the caller gave, only while the subject holds no counting factor", async () => {
		asked.length = 0;
		const { decided, bindCode } = await serve({}, { extra: [gate] });
		const login = { kind: "login", email: "ann@example.invalid" } as const;
		expect(await decided.begin("ann", "code")).toEqual({ kind: "binding-proof-required" });
		const begun = await decided.begin("ann", "code", "ok", "t", login);
		expect(begun.kind).toBe("begun");
		expect(asked).toEqual([
			{ subject: "ann", kind: "code", transaction: undefined, passed: undefined, from: undefined },
			{ subject: "ann", kind: "code", transaction: "t", passed: "ok", from: login },
		]);
		expect(await decided.countingHeld("ann", "binding")).toBe(false);
		await bindCode("ann", undefined, "ok");
		expect(await decided.countingHeld("ann", "binding")).toBe(true);
		asked.length = 0;
		expect((await decided.begin("ann", "code")).kind).toBe("begun");
		expect(asked).toEqual([]);
	});
});

it("refuses manage-within, now session's one recent-authentication window", () => {
	expect(section.safeParse({ "manage-within": "5m" }).success).toBe(false);
});

describe("the extension points mfa-extensions offers", () => {
	it("are offered by mfa-extensions alone, never again by mfa", () => {
		for (const name of ["factorKinds", "firstBindingGates", "secondFactorAmr", "witnessing"]) {
			expect(Object.keys(offered), name).not.toContain(name);
		}
	});

	it("leaves the factor contracts to mfa-reading, mfa-binding and mfa-managing, offering no factors of its own", () => {
		for (const name of ["factors", "factorReading", "factorBinding", "factorManaging"]) {
			expect(Object.keys(offered), name).not.toContain(name);
		}
	});

	it("asks a gate contributed through mfa-extensions before a first binding, and a kind through it", async () => {
		const gate = defineModule({ name: "gate-by-extensions" }, (m) => [
			m.contribute(extensions.firstBindingGates).by(() => ({ admits: async () => false })),
		]);
		const { decided } = await serve({}, { extra: [gate] });
		expect(await decided.begin("zed", "code")).toEqual({ kind: "binding-proof-required" });
		const kind = defineModule({ name: "kind-by-extensions" }, (m) => [
			m.contribute(extensions.factorKinds).by(() => ({
				kind: "other",
				amr: [],
				addsSecondFactor: true,
				guessable: false,
				counts: true,
				enroll: async () => ({ secret: "o", show: {} }),
				verify: async () => ({ kind: "invalid" as const }),
			})),
		]);
		const other = await serve({}, { extra: [kind] });
		expect((await other.decided.begin("amy", "other")).kind).toBe("begun");
	});
});

it("provides reading, binding and managing as one implementation in each app", async () => {
	const { app } = await serve();
	const reading = app.get(factorReading);
	expect(app.get(factorBinding)).toBe(reading);
	expect(app.get(factorManaging)).toBe(reading);
	// The later serve takes over the stop after each test: this app is stopped here.
	await app.stop(1000);
	const other = await serve();
	expect(other.app.get(factorReading)).not.toBe(reading);
});

describe("an enrollment witness", () => {
	it("refuses to start with a witness composed and no witnessing, so the witness is never left unasked", async () => {
		const witness = witnessStandIn();
		await expect(serve({}, { extra: [witness.module] })).rejects.toSatisfy(
			(error) =>
				error instanceof BootRefused &&
				error.refusals.some((r) => r.where === "mfa" && r.reason.includes("mfa-witnessing")),
		);
	});

	it("asks a contributed witnessing in place of its own, and refuses to start with two", async () => {
		const asked: string[] = [];
		const told: Witnessing = {
			standing: async (subject, counts) => {
				asked.push(`standing ${subject}`);
				return counts ? "held" : "none";
			},
			settle: async (subject) => {
				asked.push(`settle ${subject}`);
			},
			cleared: async (subject) => {
				asked.push(`cleared ${subject}`);
			},
		};
		const contributing = (name: string) =>
			defineModule({ name }, (m) => [m.contribute(witnessing).by(() => told)]);
		const { decided, bindCode } = await serve({}, { extra: [contributing("told")] });
		await bindCode("ola");
		await decided.clear("ola");
		expect(asked).toEqual(expect.arrayContaining(["standing ola", "settle ola", "cleared ola"]));
		await expect(
			serve({}, { extra: [contributing("one"), contributing("two")] }),
		).rejects.toBeInstanceOf(BootRefused);
	});

	describe("what a reset gives its witnessing to read after it", () => {
		/** A witnessing keeping each reset's `after`, to be read when a test asks. */
		const keeping = () => {
			const afters: (() => Promise<string>)[] = [];
			const told: Witnessing = {
				standing: async (_subject, counts) => (counts ? "held" : "none"),
				settle: async () => {},
				cleared: async (_subject, after) => {
					if (after) afters.push(after);
				},
			};
			const module = defineModule({ name: "keeping" }, (m) => [
				m.contribute(witnessing).by(() => told),
			]);
			return { module, afters };
		};

		it("answers none after a reset nothing followed, and again for the next reset", async () => {
			const kept = keeping();
			const { decided, bindCode } = await serve({}, { extra: [kept.module] });
			await bindCode("ann");
			await decided.clear("ann");
			expect(await kept.afters[0]?.()).toBe("none");
			await decided.clear("ann");
			expect(await kept.afters[1]?.()).toBe("none");
		});

		it("answers counting where a binding wrote a factor after the reset", async () => {
			const kept = keeping();
			const { decided, bindCode } = await serve({}, { extra: [kept.module] });
			await bindCode("ben");
			await decided.clear("ben");
			await bindCode("ben");
			expect(await kept.afters[0]?.()).toBe("counting");
		});

		it("answers unsure where a factor written after the reset does not stand, its claim lost", async () => {
			const kept = keeping();
			const { decided, bindKind, place } = await serve({}, { kinds: [card], extra: [kept.module] });
			await decided.clear("cal");
			expect((await bindKind("cal", "card", "c-9")).kind).toBe("bound");
			expect(await kept.afters[0]?.()).toBe("counting");
			await place.records.remove(claimKeyOf("card", "c-9"));
			expect(await kept.afters[0]?.()).toBe("unsure");
		});

		it("answers unsure once the subject's record is lost after the reset, though a later reset answers none", async () => {
			const kept = keeping();
			const { decided, bindCode, place } = await serve({}, { extra: [kept.module] });
			await bindCode("eli");
			await decided.clear("eli");
			await place.records.remove(listKeyOf("eli"));
			expect(await kept.afters[0]?.()).toBe("unsure");
			await decided.clear("eli");
			expect(await kept.afters[1]?.()).toBe("none");
		});

		it("answers unsure, not counting, where the record goes after its factors were read", async () => {
			const kept = keeping();
			const { decided, bindCode, place } = await serve({}, { extra: [kept.module] });
			await decided.clear("fay");
			await bindCode("fay");
			let reads = 0;
			place.hooks.afterRead = async (key) => {
				if (key !== listKeyOf("fay")) return;
				reads += 1;
				if (reads === 1) await place.records.remove(key);
			};
			expect(await kept.afters[0]?.()).toBe("unsure");
		});
	});

	it("tells how the subject's counting factors stand as written: counting, unclaimed or none", async () => {
		const { decided, bindKind, place } = await serve({}, { kinds: [card] });
		expect(await decided.writtenStanding("gus")).toBe("none");
		expect((await bindKind("gus", "card", "c-7")).kind).toBe("bound");
		expect(await decided.writtenStanding("gus")).toBe("counting");
		await place.records.remove(claimKeyOf("card", "c-7"));
		expect(await decided.writtenStanding("gus")).toBe("unclaimed");
		expect(await decided.countingWritten("gus")).toBe(false);
	});

	it("counts the subject's counting factors written that do not stand, one beside a factor that does included", async () => {
		const { decided, bindKind, place } = await serve({}, { kinds: [card] });
		expect(await decided.unclaimedWritten("gus")).toBe(0);
		expect((await bindKind("gus", "card", "c-7")).kind).toBe("bound");
		expect((await bindKind("gus", "card", "c-8")).kind).toBe("bound");
		expect(await decided.unclaimedWritten("gus")).toBe(0);
		await place.records.remove(claimKeyOf("card", "c-7"));
		// One stands, so the subject reads as counting: only this count tells the other.
		expect(await decided.writtenStanding("gus")).toBe("counting");
		expect(await decided.unclaimedWritten("gus")).toBe(1);
		await place.records.remove(claimKeyOf("card", "c-8"));
		expect(await decided.unclaimedWritten("gus")).toBe(2);
	});

	it("tells whether every session needs a second factor, as the mode says", async () => {
		expect((await serve({ mode: "required" })).decided.secondFactorRequired()).toBe(true);
		expect((await serve({ mode: "optional" })).decided.secondFactorRequired()).toBe(false);
	});

	it("binds a first pending sealed by an earlier version, holding a token and no fence", async () => {
		const { app, decided } = await serve();
		const sealed = app
			.get(seal)
			.seal(JSON.stringify({ kind: "code", secret: "s", first: true, token: "t" }), "hal\npending");
		expect((await decided.bind("hal", sealed, 0)).kind).toBe("bound");
		expect((await decided.held("hal")).map((f) => f.kind)).toEqual(["code"]);
	});

	it("keeps today's behaviour without a witness: a wiped store reads as never enrolled", async () => {
		const { decided, bindCode, place } = await serve();
		await bindCode("lee");
		await place.factors.update(listKeyOf("lee"), () => ({ value: storedList("lee", []) }));
		expect(await decided.asks("lee")).toBe("nothing");
	});
});

describe("a binding writing its factor and the claim on its value together", () => {
	it("writes the factor of a unique value and its claim in one write, never one without the other", async () => {
		const { decided, bindKind, place } = await serve({}, { kinds: [card] });
		const saved: string[] = [];
		place.hooks.beforeSave = async (key) => void saved.push(key);
		expect((await bindKind("ann", "card", "c-1")).kind).toBe("bound");
		expect(saved).toEqual([]);
		expect(place.peek(claimKeyOf("card", "c-1"))).toEqual({
			listKey: listKeyOf("ann"),
			factor: (await decided.held("ann"))[0]?.id,
		});
		expect(await decided.writtenStanding("ann")).toBe("counting");
	});

	it("writes neither the factor nor its claim for a first binding of a unique value another counting factor beat", async () => {
		const { decided, bindCode, bindKind, place } = await serve(
			{ mode: "required" },
			{ kinds: [code, backup, card] },
		);
		const begun = await decided.begin("liz", "card");
		if (begun.kind !== "begun") throw new Error(begun.kind);
		const valid = await decided.provePending("liz", begun.pending, "c-2");
		if (valid.kind !== "valid") throw new Error(valid.kind);
		await bindCode("liz");
		expect(await decided.bind("liz", begun.pending, valid.state)).toEqual({
			kind: "first-binding-closed",
		});
		expect(place.peek(claimKeyOf("card", "c-2"))).toBeUndefined();
		expect((await decided.held("liz")).map((f) => f.kind)).not.toContain("card");
		// The value stays free for another.
		expect((await bindKind("max", "card", "c-2")).kind).toBe("bound");
	});

	it("writes neither the factor nor its claim for a binding of a unique value whose fence moved as it wrote", async () => {
		const { decided, bindKind, place } = await serve({}, { kinds: [code, backup, card] });
		const begun = await decided.begin("lia", "card");
		if (begun.kind !== "begun") throw new Error(begun.kind);
		const valid = await decided.provePending("lia", begun.pending, "c-3");
		if (valid.kind !== "valid") throw new Error(valid.kind);
		// The fence moves once the binding has read it: the write itself must refuse.
		let moved = false;
		place.hooks.afterRead = async (key) => {
			if (key !== listKeyOf("lia") || moved) return;
			moved = true;
			await decided.fence("lia");
		};
		expect(await decided.bind("lia", begun.pending, valid.state)).toEqual({ kind: "fenced" });
		delete place.hooks.afterRead;
		expect(moved).toBe(true);
		expect(place.peek(claimKeyOf("card", "c-3"))).toBeUndefined();
		expect(await decided.held("lia")).toEqual([]);
		expect((await bindKind("max", "card", "c-3")).kind).toBe("bound");
	});

	it("binds nothing where another factor holds the value, and takes a claim its factor left", async () => {
		const { decided, bindKind, place } = await serve({}, { kinds: [card] });
		expect((await bindKind("ann", "card", "c-2")).kind).toBe("bound");
		expect((await bindKind("bob", "card", "c-2")).kind).toBe("duplicate");
		expect(await decided.held("bob")).toEqual([]);
		await decided.clear("ann");
		expect((await bindKind("bob", "card", "c-2")).kind).toBe("bound");
		expect((place.peek(claimKeyOf("card", "c-2")) as unknown as { listKey: string }).listKey).toBe(
			listKeyOf("bob"),
		);
	});

	it("leaves the factor with its claim where the write's answer is lost, so it counts though the bind is unavailable", async () => {
		const { decided, bindKind, place } = await serve({}, { kinds: [card] });
		place.hooks.afterTogether = async () => {
			throw new Unavailable("factor-store");
		};
		await expect(bindKind("cid", "card", "c-3")).rejects.toSatisfy(isUnavailable);
		place.hooks.afterTogether = undefined;
		expect(await decided.writtenStanding("cid")).toBe("counting");
		expect((await bindKind("dee", "card", "c-3")).kind).toBe("duplicate");
	});

	it("answers full as before, writing no claim for it", async () => {
		const { decided, bindKind, place } = await serve({ "max-factors": 2 }, { kinds: [card] });
		expect((await bindKind("eve", "card", "c-4")).kind).toBe("bound");
		// Two bindings begun while one place is left: the second to bind finds none.
		const proved = async (proof: string) => {
			const begun = await decided.begin("eve", "card");
			if (begun.kind !== "begun") throw new Error(begun.kind);
			const done = await decided.provePending("eve", begun.pending, proof);
			if (done.kind !== "valid") throw new Error(done.kind);
			return { pending: begun.pending, state: done.state };
		};
		const [five, six] = [await proved("c-5"), await proved("c-6")];
		expect((await decided.bind("eve", five.pending, five.state)).kind).toBe("bound");
		expect((await decided.bind("eve", six.pending, six.state)).kind).toBe("full");
		expect(place.peek(claimKeyOf("card", "c-6"))).toBeUndefined();
	});
});
