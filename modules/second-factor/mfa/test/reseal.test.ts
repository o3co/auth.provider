import { createHash, randomBytes } from "node:crypto";
import { auditStandIn } from "@mod/audit/testing";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import gatesModule from "@mod/login-gates/module";
import { type FactorBinding, factorBinding } from "@mod/mfa-binding";
import { factorKinds } from "@mod/mfa-extensions";
import { type FactorReading, factorReading } from "@mod/mfa-reading";
import { resealing, seal } from "@mod/seal";
import sealModule from "@mod/seal/module";
import { sessionStandIn } from "@mod/session/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { afterEach, expect, it } from "vitest";
import { enforcers, proofSteps } from "../src/contract.ts";
import mfaModule from "../src/module.ts";
import type { StoredFactors } from "../src/store.ts";
import { mfaConfig } from "../src/testing.ts";
import { memoryFactors } from "./stores.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });
let stop = async () => {};
afterEach(() => stop());

const key = (id: string) => ({ id, key: randomBytes(32).toString("base64") });
const [past, current, gone] = [key("past"), key("current"), key("gone")];
type Held = { subject?: string; factors: { id: string; secret: string }[] };
const listKey = (subject: string) =>
	`s-${createHash("sha256").update(subject).digest("base64url")}`;

/** A counting kind whose proof is the secret and a counter that must go up. */
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
			if (given !== secret) return { kind: "invalid" as const };
			return Number(n) > (typeof state === "number" ? state : -1)
				? { kind: "valid" as const, state: Number(n) }
				: { kind: "replayed" as const };
		},
	})),
]);
const step = defineModule({ name: "step" }, (m) => [
	m.contribute(proofSteps).by(() => ({ name: "step" })),
]);
/** A seal over a ring of its own, to write what another key sealed. */
const sealOver = async (ring: Readonly<Record<string, unknown>>) =>
	(await assemble({ modules: [sealModule], config: { ...kernelConfig(), seal: ring } })).get(seal);

/** A module holding sessions to the factors, as `mfa-entry` does in an app. */
const enforcer = defineModule({ name: "enforcer" }, (m) => [
	m.contribute(enforcers).by(() => ({ name: "enforcer" })),
]);

/** mfa over a ring with `past` as a previous key; `aged` binds a code factor, its secret then sealed by `by`. */
async function rotated() {
	const place = memoryFactors();
	const app = await assemble({
		modules: [
			http,
			auditStandIn().module,
			sessionStandIn,
			subjectRevocationStandIn,
			place.module,
			sealModule,
			gatesModule,
			mfaModule,
			enforcer,
			code,
			step,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			seal: { current, previous: [past] },
			...mfaConfig(),
		},
		runtime,
	});
	stop = () => app.stop(1000);
	// mfa's faces the test binds and proves through, as one.
	const decided: FactorReading & FactorBinding = {
		...app.get(factorReading),
		...app.get(factorBinding),
	};
	const read = async (subject: string) =>
		(await place.factors.read(listKey(subject))) as unknown as Held;
	const aged = async (subject: string, by: { id: string; key: string }) => {
		const begun = await decided.begin(subject, "code", undefined, "t");
		if (begun.kind !== "begun") throw new Error(begun.kind);
		const secret = String((begun.show as { secret: string }).secret);
		const proved = await decided.provePending(subject, begun.pending, `${secret}:0`);
		if (proved.kind !== "valid") throw new Error(proved.kind);
		const bound = await decided.bind(subject, begun.pending, proved.state);
		if (bound.kind !== "bound") throw new Error(bound.kind);
		const id = bound.factor.id;
		const sealed = (await sealOver({ current: by })).seal(secret, `${subject}\n${id}`);
		await place.factors.update(listKey(subject), (record) => {
			const held = record as unknown as Held;
			const factors = held.factors.map((f) => (f.id === id ? { ...f, secret: sealed } : f));
			return { value: { ...held, factors } as unknown as StoredFactors };
		});
		const sealedNow = async () => (await read(subject)).factors.find((f) => f.id === id)?.secret;
		return { id, secret, sealedNow };
	};
	const reseal = () => app.get(resealing).reseal();
	return { place, decided, read, aged, reseal };
}

it("seals again each factor's secret a past key sealed, walking every list, and counts one no key opens as left", async () => {
	const h = await rotated();
	const [ann, bob, cid] = [
		await h.aged("ann", past),
		await h.aged("bob", past),
		await h.aged("cid", gone),
	];
	expect(await h.reseal()).toEqual([{ name: "mfa", resealed: 2, left: 1 }]);
	expect(await ann.sealedNow()).toMatch(/^current\./);
	expect(await bob.sealedNow()).toMatch(/^current\./);
	expect(await cid.sealedNow()).toMatch(/^gone\./);
	const sealed = await ann.sealedNow();
	expect(await h.reseal()).toEqual([{ name: "mfa", resealed: 0, left: 1 }]);
	expect((await h.decided.prove("ann", ann.id, `${ann.secret}:5`)).kind).toBe("valid");
	// What the current key sealed stays as it was, through a walk and a proof.
	expect(await ann.sealedNow()).toBe(sealed);
});

it("counts as left a list that holds no subject, or another subject than its key names", async () => {
	const h = await rotated();
	await h.aged("ann", past);
	await h.aged("bob", past);
	const drop = (key: string, change: (held: Held) => Held) =>
		h.place.factors.update(key, (r) => ({
			value: change(r as unknown as Held) as unknown as StoredFactors,
		}));
	await drop(listKey("ann"), ({ subject: _gone, ...rest }) => rest);
	await drop(listKey("bob"), (held) => ({ ...held, subject: "someone" }));
	expect(await h.reseal()).toEqual([{ name: "mfa", resealed: 0, left: 2 }]);
});

it("seals a past key's secret again as a proof writes the factor", async () => {
	const h = await rotated();
	const ann = await h.aged("ann", past);
	expect((await h.decided.prove("ann", ann.id, `${ann.secret}:5`)).kind).toBe("valid");
	expect(await ann.sealedNow()).toMatch(/^current\./);
});

it("leaves a secret another write changed meanwhile, and does not count it", async () => {
	const h = await rotated();
	const ann = await h.aged("ann", past);
	h.place.raceNextChange((record) => {
		const held = record as unknown as Held;
		const factors = held.factors.map((f) =>
			f.id === ann.id ? { ...f, secret: "current.theirs" } : f,
		);
		return { ...held, factors } as unknown as StoredFactors;
	});
	expect(await h.reseal()).toEqual([{ name: "mfa", resealed: 0, left: 0 }]);
	expect(await ann.sealedNow()).toBe("current.theirs");
});
