import { randomBytes } from "node:crypto";
import { auditStandIn } from "@mod/audit/testing";
import cookiesModule from "@mod/cookies/module";
import { csrfStandIn } from "@mod/csrf/testing";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, unavailableSwitch } from "@mod/kernel/testing";
import gatesModule from "@mod/login-gates/module";
import { type FactorStore, factorStore, factors, proofSteps, type StoredFactors } from "@mod/mfa";
import mfaModule from "@mod/mfa/module";
import { type MfaSettings, mfaConfig } from "@mod/mfa/testing";
import mfaEntry from "@mod/mfa-entry/module";
import { factorKinds } from "@mod/mfa-extensions";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { memoryRecords } from "@mod/records/testing";
import sealModule from "@mod/seal/module";
import { sealConfig } from "@mod/seal/testing";
import { sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { afterEach } from "vitest";
import type { z } from "zod";
import managementModule from "../src/module.ts";
import { section } from "../src/section.ts";

/** How far the kernel's clock runs ahead of the host's; it goes back after each test. */
export const clock = { shift: 0 };
const runtime = quietRuntime({ clock: { now: () => Date.now() + clock.shift } });
let stop = async () => {};
export const factorsDown = unavailableSwitch<FactorStore>("factor store");
/** Runs once before the factor store's next change, as a request racing in between would. */
export const beforeNextChange: { run?: (() => Promise<unknown>) | undefined } = {};
afterEach(async () => {
	clock.shift = 0;
	factorsDown.restore();
	beforeNextChange.run = undefined;
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
		enroll: async () => {
			const codes = [randomBytes(4).toString("hex"), randomBytes(4).toString("hex")];
			return { secret: JSON.stringify(codes), show: codes };
		},
		verify: async () => ({ kind: "invalid" as const }),
	})),
]);
/** The step that proves factors at login, which `mfa` asks for; these routes prove none. */
const step = defineModule({ name: "step" }, (m) => [
	m.contribute(proofSteps).by(() => ({ name: "step" })),
]);

/** mfa's factor lists on the records stand-in, kept without end. */
const factorStand = () => {
	const stand = memoryRecords<StoredFactors>(() => 0, { shards: 1, perShard: 1 });
	return defineModule({ name: "factor-store" }, (m) => [
		m.provide(factorStore).by(() =>
			factorsDown.wrap({
				save: (key: string, record: StoredFactors) => stand.records.create(key, record, "endless"),
				read: stand.records.read,
				update: async (...args: Parameters<typeof stand.records.change>) => {
					const run = beforeNextChange.run;
					beforeNextChange.run = undefined;
					await run?.();
					return stand.records.change(...args);
				},
				scan: stand.records.scan,
			}),
		),
	]);
};

/** What a call changes from a same-origin form POST by the shared browser. */
interface Call {
	readonly json?: boolean;
	readonly headers?: Record<string, string>;
}

/** Settings for both sections; each goes to the module that reads it. */
type Settings = Partial<MfaSettings> & Partial<z.input<typeof section>>;
const ownKeys = Object.keys(section.shape);

export async function serve(settings: Settings = {}) {
	const pick = (own: boolean) =>
		Object.fromEntries(Object.entries(settings).filter(([k]) => ownKeys.includes(k) === own));
	const app = await assemble({
		modules: [
			http,
			auditStandIn().module,
			csrfStandIn,
			cookiesModule,
			sessionStandIn,
			subjectRevocationStandIn,
			rateLimitStandIn,
			factorStand(),
			sealModule,
			gatesModule,
			mfaModule,
			mfaEntry,
			code,
			backup,
			step,
			managementModule,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "trusted-proxies": ["127.0.0.1"], "public-origin": "https://as.example" }),
			...sealConfig(),
			...mfaConfig(pick(false)),
			"mfa-management": pick(true),
		},
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	const base = `http://127.0.0.1:${app.get(listening).port()}`;
	let jar = new Map<string, string>();
	/** A POST sends everything in its body, a form unless said. */
	const call = async (
		method: "GET" | "POST",
		path: string,
		form: Record<string, unknown> = {},
		how: Call = {},
	) => {
		const res = await fetch(`${base}${path}`, {
			method,
			headers: {
				"content-type": how.json ? "application/json" : "application/x-www-form-urlencoded",
				"x-forwarded-proto": "https",
				"x-forwarded-for": "198.51.100.1",
				origin: "https://as.example",
				cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; "),
				...how.headers,
			},
			...(method === "POST"
				? {
						body: how.json
							? JSON.stringify(form)
							: new URLSearchParams(form as Record<string, string>),
					}
				: {}),
		});
		return { status: res.status, body: (await res.json()) as Record<string, unknown> };
	};
	/** A fresh browser, signed in by password; `proved` adds a second factor proved at that sign-in. */
	const signIn = async (subject = "alice", { proved = false } = {}) => {
		jar = new Map();
		const amr = proved ? ["pwd", "otp", "mfa"] : ["pwd"];
		const facts = { subject, amr, authenticatedAt: runtime.clock.now() };
		const { cookies } = await app.get(sessions).complete(testRequest(), facts);
		for (const c of cookies) {
			const [name = "", value = ""] = (c.split(";")[0] ?? "").split("=");
			jar.set(name, value);
		}
	};
	/** Binds a code factor for the subject through mfa, and answers its id. */
	const bindCode = async (subject = "alice") => {
		const decided = app.get(factors);
		const begun = await decided.begin(subject, "code");
		if (begun.kind !== "begun") throw new Error(begun.kind);
		const secret = String((begun.show as { secret: string }).secret);
		const proved = await decided.provePending(subject, begun.pending, `${secret}:0`);
		if (proved.kind !== "valid") throw new Error(proved.kind);
		const bound = await decided.bind(subject, begun.pending, proved.state);
		if (bound.kind !== "bound") throw new Error(bound.kind);
		return bound.factor.id;
	};
	return { app, call, signIn, bindCode, jar: () => jar, port: () => app.get(listening).port() };
}
