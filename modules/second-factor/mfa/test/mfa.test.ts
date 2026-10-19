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
import { logins } from "@mod/login-gates";
import gatesModule from "@mod/login-gates/module";
import * as extensions from "@mod/mfa-extensions";
import {
	type Enrolled,
	factorKinds,
	firstBindingGates,
	type Opened,
	type Sending,
} from "@mod/mfa-extensions";
import { witnessStandIn } from "@mod/mfa-witness/testing";
import { seal } from "@mod/seal";
import sealModule from "@mod/seal/module";
import { sealConfig } from "@mod/seal/testing";
import { sessionStandIn } from "@mod/session/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { afterEach, describe, expect, it } from "vitest";
import * as offered from "../src/contract.ts";
import { factors, isLabel, proofSteps } from "../src/contract.ts";
import mfaModule from "../src/module.ts";
import { listKeyOf, storedList } from "../src/records/records.ts";
import { section } from "../src/section.ts";
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

async function serve(
	settings: Partial<MfaSettings> = {},
	{ steps = [step], kinds = [code, backup], extra = [] as Module[] } = {},
) {
	const audit = auditStandIn();
	const place = memoryFactors();
	const app = await assemble({
		modules: [
			http,
			audit.module,
			subjectRevocationStandIn,
			place.module,
			sealModule,
			sessionStandIn,
			gatesModule,
			mfaModule,
			...kinds,
			...steps,
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
	const decided = app.get(factors);
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
		return { ...bound, secret };
	};
	/** Binds a factor of the kind, its first proof being `proof`. */
	const bindKind = async (subject: string, kind: string, proof: string) => {
		const begun = await decided.begin(subject, kind);
		if (begun.kind !== "begun") throw new Error(begun.kind);
		const proved = await decided.provePending(subject, begun.pending, proof);
		if (proved.kind !== "valid") throw new Error(proved.kind);
		return decided.bind(subject, begun.pending, proved.state);
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
		expect(bound.recoveryCodes).toBeDefined();
		// Named, so a caller that cannot show them can take them back.
		const codes = (await decided.held("zed")).find((f) => f.id === bound.recoveryCodesFactor);
		expect(codes?.kind).toBe("backup");
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
			const held = await Promise.all(subjects.map((subject) => decided.held(subject)));
			expect(
				held
					.flat()
					.map((f) => f.kind)
					.sort(),
			).toEqual(["backup", "card"]);
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

	it("binds nothing when the way back will not enrol, as when the store cannot answer", async () => {
		const { decided, provedCode } = await serve({}, { kinds: [code, stuck] });
		const { pending, state } = await provedCode("cal");
		await expect(decided.bind("cal", pending, state)).rejects.toThrow(Unavailable);
		expect(await decided.held("cal")).toEqual([]);
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
		for (const name of ["factorKinds", "firstBindingGates", "secondFactorAmr"]) {
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

describe("an enrollment witness", () => {
	/** mfa beside a witness in memory; `wipe` loses a subject's factors, as a store wiped or rolled back would. */
	const witnessed = async (settings: Partial<MfaSettings> = {}) => {
		const witness = witnessStandIn();
		const served = await serve(settings, { extra: [witness.module] });
		const wipe = (subject: string) =>
			served.place.factors.update(listKeyOf(subject), () => ({ value: storedList(subject, []) }));
		const counted = async (subject: string) =>
			(await served.decided.held(subject)).filter((f) => f.kind === "code").length;
		return { ...served, witness, wipe, counted };
	};

	it("refuses to start with two witnesses", async () => {
		const [one, two] = [witnessStandIn("witness-one"), witnessStandIn("witness-two")];
		await expect(serve({}, { extra: [one.module, two.module] })).rejects.toBeInstanceOf(
			BootRefused,
		);
	});

	it("marks the subject before its first counting factor is written, and only then", async () => {
		const { bindCode, witness } = await witnessed();
		await bindCode("ana");
		expect(witness.marks.has("ana")).toBe(true);
		witness.marks.clear();
		await bindCode("ana");
		expect(witness.marks.has("ana")).toBe(false);
	});

	it("answers unavailable where a wiped store would read as never enrolled: login, a first binding, and credentials", async () => {
		const { decided, bindCode, wipe, events } = await witnessed();
		await bindCode("bea");
		await wipe("bea");
		events.length = 0;
		await expect(decided.asks("bea")).rejects.toSatisfy(isUnavailable);
		await expect(decided.begin("bea", "code")).rejects.toSatisfy(isUnavailable);
		await expect(decided.countingHeld("bea", "credentials")).rejects.toSatisfy(isUnavailable);
		expect(events.map((e) => [e.kind, e.attributes])).toEqual([
			["mfa.enrollment_inconsistent", { at: "login" }],
			["mfa.enrollment_inconsistent", { at: "binding" }],
			["mfa.enrollment_inconsistent", { at: "credentials" }],
		]);
	});

	it("judges whether a counting factor is held against the witness, recording where it was asked", async () => {
		const { decided, bindCode, wipe, events } = await witnessed();
		await bindCode("dee");
		expect(await decided.countingHeld("dee", "credentials")).toBe(true);
		await wipe("dee");
		events.length = 0;
		await expect(decided.countingHeld("dee", "credentials")).rejects.toSatisfy(isUnavailable);
		await expect(decided.countingHeld("dee", "binding")).rejects.toSatisfy(isUnavailable);
		expect(events.map((e) => [e.kind, e.attributes])).toEqual([
			["mfa.enrollment_inconsistent", { at: "credentials" }],
			["mfa.enrollment_inconsistent", { at: "binding" }],
		]);
		expect(await decided.countingHeld("eli", "login")).toBe(false);
	});

	it("tells whether every session needs a second factor, as the mode says", async () => {
		expect((await serve({ mode: "required" })).decided.secondFactorRequired()).toBe(true);
		expect((await serve({ mode: "optional" })).decided.secondFactorRequired()).toBe(false);
	});

	it("refuses a first binding begun before the owner's, once the store is wiped, writing nothing", async () => {
		const { decided, provedCode, bindCode, wipe, counted, events } = await witnessed();
		const stale = await provedCode("cid");
		await bindCode("cid");
		await wipe("cid");
		events.length = 0;
		expect(await decided.bind("cid", stale.pending, stale.state)).toEqual({
			kind: "first-binding-closed",
		});
		expect(await counted("cid")).toBe(0);
		expect(events.map((e) => [e.kind, e.attributes])).toEqual([
			["mfa.first_binding_conflict", { kind: "code", reason: "competing" }],
		]);
	});

	it("asks the witness again with the same token, three times at most, before it writes nothing", async () => {
		const { decided, provedCode, witness, counted } = await witnessed();
		const begun = await provedCode("dan");
		witness.failing.enroll = 2;
		expect((await decided.bind("dan", begun.pending, begun.state)).kind).toBe("bound");
		const other = await provedCode("eli");
		witness.failing.enroll = 4;
		await expect(decided.bind("eli", other.pending, other.state)).rejects.toSatisfy(isUnavailable);
		expect([await counted("eli"), witness.marks.has("eli")]).toEqual([0, false]);
	});

	it("binds over a mark its own token set when its answer was lost", async () => {
		const { decided, provedCode, witness, counted } = await witnessed();
		const begun = await provedCode("fay");
		witness.lost.enroll = 1;
		expect((await decided.bind("fay", begun.pending, begun.state)).kind).toBe("bound");
		expect(await counted("fay")).toBe(1);
	});

	it("takes back its own factor when a reset cleared the mark while it was being written", async () => {
		const { decided, provedCode, witness, counted, events } = await witnessed();
		const begun = await provedCode("gus");
		// The reset's clear lands after the enroll that set the mark, before the factor is read again.
		witness.next.afterEnroll = () => witness.marks.delete("gus");
		events.length = 0;
		expect(await decided.bind("gus", begun.pending, begun.state)).toEqual({
			kind: "first-binding-closed",
		});
		expect(await counted("gus")).toBe(0);
		expect(events.map((e) => [e.kind, e.attributes])).toEqual([
			["mfa.first_binding_conflict", { kind: "code", reason: "reset-cleared" }],
		]);
	});

	it("leaves the witness's mark when a reset's clear lands while it binds a first factor: only a reset clears one", async () => {
		const { decided, provedCode, witness, counted, place } = await witnessed();
		await place.factors.save(listKeyOf("gil"), storedList("gil", []), "endless");
		const begun = await provedCode("gil");
		// While this binding writes, a reset clears the factors and the mark, and a newer binding marks.
		place.raceNextChange((record) => {
			witness.marks.set("gil", "newer");
			return { ...record, factors: [], fences: 1 };
		});
		expect(await decided.bind("gil", begun.pending, begun.state)).toEqual({ kind: "fenced" });
		expect(await counted("gil")).toBe(0);
		expect(witness.marks.get("gil")).toBe("newer");
	});

	it("takes back its own factor once more when the store cannot answer the first time", async () => {
		const { decided, provedCode, witness, counted, place } = await witnessed();
		const begun = await provedCode("guy");
		witness.next.afterEnroll = () => witness.marks.delete("guy");
		// The store fails the first take-back, which comes after the mark is read again.
		witness.next.beforeRead = () => place.down.failNext("update");
		expect(await decided.bind("guy", begun.pending, begun.state)).toEqual({
			kind: "first-binding-closed",
		});
		expect(await counted("guy")).toBe(0);
	});

	it("refuses a first pending that holds no token, as one sealed before the witness was composed", async () => {
		const { app, decided, counted } = await witnessed();
		const sealed = app
			.get(seal)
			.seal(JSON.stringify({ kind: "code", secret: "s", first: true }), "hal\npending");
		expect(await decided.bind("hal", sealed, 0)).toEqual({ kind: "first-binding-closed" });
		expect(await counted("hal")).toBe(0);
	});

	it("never removes the last counting factor under optional mode, as only a reset clears the mark", async () => {
		const { decided, bindCode, idOf } = await witnessed();
		await bindCode("ivy");
		expect(
			await decided.remove("ivy", await idOf("ivy", "code"), await decided.fenceOf("ivy")),
		).toBe("last");
	});

	it("clears the mark after a reset's removal, and answers unavailable while it cannot, the factors gone", async () => {
		const { decided, bindCode, witness, counted } = await witnessed();
		await bindCode("jo");
		expect((await decided.clear("jo")).count).toBe(2);
		expect(witness.marks.has("jo")).toBe(false);
		await bindCode("jo");
		witness.failing.clear = 1;
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
		expect(await counted("kim")).toBe(1);
	});

	it("keeps today's behaviour without a witness: a wiped store reads as never enrolled", async () => {
		const { decided, bindCode, place } = await serve();
		await bindCode("lee");
		await place.factors.update(listKeyOf("lee"), () => ({ value: storedList("lee", []) }));
		expect(await decided.asks("lee")).toBe("nothing");
	});
});
