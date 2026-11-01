import { randomBytes } from "node:crypto";
import { auditStandIn } from "@mod/audit/testing";
import cookiesModule from "@mod/cookies/module";
import { csrfStandIn } from "@mod/csrf/testing";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import {
	assemble,
	defineModule,
	type ExtensionPoint,
	kernelConfig,
	type Module,
} from "@mod/kernel";
import { quietRuntime, recordingLog, switchedModule, unavailableSwitch } from "@mod/kernel/testing";
import { type LoginFrom, logins } from "@mod/login-gates";
import gatesModule from "@mod/login-gates/module";
import { type FactorStore, factorStore, type StoredFactors } from "@mod/mfa";
import mfaModule from "@mod/mfa/module";
import { type MfaSettings, mfaConfig, updatingTogether } from "@mod/mfa/testing";
import bindingProofModule from "@mod/mfa-binding-proof/module";
import mfaEntry from "@mod/mfa-entry/module";
import { factorKinds } from "@mod/mfa-extensions";
import flowsModule from "@mod/mfa-flows/module";
import { type FlowSettings, flowKeys, flowsConfig } from "@mod/mfa-flows/testing";
import mfaRevocation from "@mod/mfa-revocation/module";
import { type Lockouts, lockouts } from "@mod/rate-limit";
import rateLimitModule from "@mod/rate-limit/module";
import { memoryRecords } from "@mod/records/testing";
import sealModule from "@mod/seal/module";
import { sealConfig } from "@mod/seal/testing";
import { type Sessions, sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import sessionRequirements from "@mod/session-requirements/module";
import { simulatedStore } from "@mod/store/testing";
import {
	type RevocationFollower,
	type Revocations,
	revocationFollowers,
	revocations,
} from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { afterEach } from "vitest";
import enrollmentModule from "../src/module.ts";
import { memoryTransactions } from "./stores.ts";

/** How far the kernel's clock runs ahead of the host's; it goes back after each test. */
export const clock = { shift: 0 };
export const logged = recordingLog();
export const runtime = quietRuntime({
	clock: { now: () => Date.now() + clock.shift },
	log: logged.log,
});
let stop = async () => {};
export const revocationsDown = unavailableSwitch<Revocations>("subject-revocation");
export const factorsDown = unavailableSwitch<FactorStore>("factor store");
export const sessionsDown = unavailableSwitch<Sessions>("sessions");
export const during = {
	/** Runs once as the next lockout is released, before the release, as another request or a failure would. */
	release: undefined as (() => Promise<void>) | undefined,
	/** Runs once while the next recovery code is judged, as another request would. */
	backup: undefined as (() => Promise<void>) | undefined,
	/** Runs once while the next code is judged, as another request would. */
	code: undefined as (() => Promise<void>) | undefined,
	/** Runs once after the factor store's next write, before it answers, as a slow store would. */
	written: undefined as (() => Promise<void>) | undefined,
	/** Runs once before mfa's fence follows the next revocation, its record already written, as a slow follower would. */
	follow: undefined as (() => Promise<void>) | undefined,
	/** Runs once after the next session raised or opened, before it answers, as a slow store would. */
	entered: undefined as (() => Promise<void>) | undefined,
	/** Changes the next raise's answer once, as a raise not written would. */
	raised: undefined as
		| ((answer: Awaited<ReturnType<Sessions["raise"]>>) => Awaited<ReturnType<Sessions["raise"]>>)
		| undefined,
	/** Changes the factor list once before the factor store's next change, as another request writing in between would. */
	rewrite: undefined as ((record: StoredFactors) => StoredFactors) | undefined,
	/** How many of the next revocations move the boundary but answer that a close did not finish. */
	unfinishedRecords: 0,
};
/** Once the next proof is judged, the bind writes; then a copy of the factor lands before the reissue writes, taking the codes' place. */
export const takingTheCodesPlace = () => {
	during.code = async () => {
		during.written = async () => {
			during.rewrite = (record) => {
				const { factors: all } = record as unknown as { factors: { id: string }[] };
				return { ...record, factors: [...all, { ...all[0], id: "other" }] } as never;
			};
		};
	};
};
/** The name of the browser's mfa transaction cookie, when it holds one. */
export const transactionCookie = (jar: ReadonlyMap<string, string>) =>
	[...jar.keys()].find((name) => name.includes("mfa"));
/** Sessions whose next raise or opening holds its answer while `during.entered` runs once. */
const entering = {
	...sessionsDown,
	wrap: (kept: Sessions): Sessions => {
		const held = async <T>(answer: Promise<T>) => {
			const done = await answer;
			const run = during.entered;
			during.entered = undefined;
			await run?.();
			return done;
		};
		return sessionsDown.wrap({
			...kept,
			raise: async (...args: Parameters<Sessions["raise"]>) => {
				const answer = await held(kept.raise(...args));
				const change = during.raised;
				during.raised = undefined;
				return change ? change(answer) : answer;
			},
			complete: (...args: Parameters<Sessions["complete"]>) => held(kept.complete(...args)),
			open: (...args: Parameters<Sessions["open"]>) => held(kept.open(...args)),
		});
	},
};
/** mfa-revocation, its follower holding the fence's move while `during.follow` runs once. */
const heldFollower: Module = Object.freeze({
	...mfaRevocation,
	contributes: (mfaRevocation.contributes ?? []).map((part) =>
		part.point !== (revocationFollowers as ExtensionPoint<unknown>)
			? part
			: {
					point: part.point,
					create: async (context: Parameters<typeof part.create>[0]) => {
						const follower = (await part.create(context)) as RevocationFollower;
						return {
							...follower,
							follow: async (...args: Parameters<RevocationFollower["follow"]>) => {
								const run = during.follow;
								during.follow = undefined;
								await run?.();
								return follower.follow(...args);
							},
						};
					},
				},
	),
});
const recording = {
	...revocationsDown,
	wrap: (kept: Revocations): Revocations =>
		revocationsDown.wrap({
			...kept,
			record: async (subject, options) => {
				const done = await kept.record(subject, options);
				if (during.unfinishedRecords === 0) return done;
				during.unfinishedRecords--;
				return { complete: false };
			},
		}),
};
const releasing = {
	...unavailableSwitch<Lockouts>(),
	wrap: (lockout: Lockouts): Lockouts => ({
		...lockout,
		releaseUnder: async (name, key, policy, terms) => {
			const run = during.release;
			during.release = undefined;
			await run?.();
			return lockout.releaseUnder(name, key, policy, terms);
		},
	}),
};
afterEach(async () => {
	clock.shift = 0;
	revocationsDown.restore();
	factorsDown.restore();
	sessionsDown.restore();
	during.release = undefined;
	during.backup = undefined;
	during.raised = undefined;
	during.rewrite = undefined;
	during.unfinishedRecords = 0;
	during.follow = undefined;
	await stop();
});

/** A guessable, counting kind: the proof is the secret and a counter that must go up. */
const code = defineModule({ name: "kind-code", replicaSafe: false, takes: [] }, (m) => [
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
			const run = during.code;
			during.code = undefined;
			await run?.();
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
const backup = defineModule({ name: "kind-backup", replicaSafe: false, takes: [] }, (m) => [
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
		verify: async (secret, state, proof) => {
			const run = during.backup;
			during.backup = undefined;
			await run?.();
			const used = Array.isArray(state) ? (state as string[]) : [];
			if (!(JSON.parse(secret) as string[]).includes(proof)) return { kind: "invalid" as const };
			return used.includes(proof)
				? { kind: "replayed" as const }
				: { kind: "valid" as const, state: [...used, proof] };
		},
	})),
]);

/** A write's answer, held while `during.written` runs once. */
const afterWrite = async <T>(write: Promise<T>) => {
	const done = await write;
	const run = during.written;
	during.written = undefined;
	await run?.();
	return done;
};

/** mfa's factor lists on the records stand-in, kept without end. */
const factorStand = () => {
	const stand = memoryRecords<StoredFactors>(() => 0, { shards: 1, perShard: 1 });
	const joint = updatingTogether(stand.records);
	return defineModule({ name: "factor-store", replicaSafe: false, takes: [] }, (m) => [
		m.provide(factorStore).by(() =>
			factorsDown.wrap({
				save: (key: string, record: StoredFactors) =>
					afterWrite(stand.records.create(key, record, "endless")),
				read: stand.records.read,
				update: async (...args: Parameters<typeof stand.records.change>) => {
					const rewrite = during.rewrite;
					during.rewrite = undefined;
					if (rewrite)
						await stand.records.change(args[0], (record) => ({ value: rewrite(record) }));
					return afterWrite(stand.records.change(...args));
				},
				scan: stand.records.scan,
				updateTogether: (...args: Parameters<typeof joint>) => afterWrite(joint(...args)),
			}),
		),
	]);
};

/** What a call changes from a form POST by the shared browser. */
interface Call {
	readonly jar?: Map<string, string>;
	readonly json?: boolean;
	readonly headers?: Record<string, string>;
	readonly form?: URLSearchParams;
}

/** Settings for both sections; each goes to the module that reads it. */
type Settings = Partial<MfaSettings> & Partial<FlowSettings>;

export async function serve(settings: Settings = {}, extra: Module[] = []) {
	const pick = (own: boolean) =>
		Object.fromEntries(Object.entries(settings).filter(([k]) => flowKeys.includes(k) === own));
	const simulated = simulatedStore();
	const kept = memoryTransactions(() => runtime.clock.now());
	const audit = auditStandIn();
	const input = {
		modules: [
			http,
			audit.module,
			csrfStandIn,
			cookiesModule,
			switchedModule(sessionStandIn, sessions, entering),
			sessionRequirements,
			switchedModule(subjectRevocationStandIn, revocations, recording),
			simulated.module,
			factorStand(),
			kept.module,
			gatesModule,
			switchedModule(rateLimitModule, lockouts, releasing),
			sealModule,
			mfaModule,
			// What moves the fence on a revocation, as combinations composes it beside mfa-flows.
			heldFollower,
			mfaEntry,
			bindingProofModule,
			flowsModule,
			enrollmentModule,
			code,
			backup,
			...extra,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "trusted-proxies": ["127.0.0.1"], "public-origin": "https://as.example" }),
			...sealConfig(),
			...mfaConfig(pick(false)),
			...flowsConfig(pick(true)),
		},
		runtime,
	};
	const app = await assemble(input);
	await app.start();
	stop = () => app.stop(1000);
	const base = `http://127.0.0.1:${app.get(listening).port()}`;
	let jar = new Map<string, string>();
	const keep = (set: readonly string[], into = jar) => {
		for (const c of set) {
			const [pair = ""] = c.split(";");
			const [name = "", value = ""] = pair.split("=");
			if (value) into.set(name, value);
			else into.delete(name);
		}
	};
	/** A GET names its transaction in the header; a POST sends everything in its body, a form unless said. */
	const call = async (
		method: "GET" | "POST",
		path: string,
		form: Record<string, unknown> = {},
		how: Call = {},
	) => {
		const use = how.jar ?? jar;
		const res = await fetch(`${base}${path}`, {
			method,
			headers: {
				"content-type": how.json ? "application/json" : "application/x-www-form-urlencoded",
				"x-forwarded-proto": "https",
				"x-forwarded-for": "198.51.100.1",
				origin: "https://as.example",
				cookie: [...use].map(([k, v]) => `${k}=${v}`).join("; "),
				...(method === "GET" && form.transaction_id
					? { "mfa-transaction": String(form.transaction_id) }
					: {}),
				...how.headers,
			},
			...(method === "POST"
				? {
						body: how.json
							? JSON.stringify(form)
							: (how.form ?? new URLSearchParams(form as Record<string, string>)),
					}
				: {}),
		});
		keep(res.headers.getSetCookie(), use);
		return { status: res.status, body: (await res.json()) as Record<string, unknown> };
	};
	/** A fresh browser, signed in by password. */
	const signIn = async (subject = "alice") => {
		jar = new Map();
		const facts = { subject, amr: ["pwd"], authenticatedAt: runtime.clock.now() };
		const { cookies } = await app.get(sessions).complete(testRequest(), facts);
		keep(cookies);
	};
	/** Enrolls a code factor from a signed-in browser and answers its secret and the recovery codes. */
	const enrollCode = async (subject = "alice") => {
		await signIn(subject);
		const begun = await call("POST", "/session/mfa/enrollment", { kind: "code" });
		const done = await call("POST", "/session/mfa/enrollment/complete", {
			transaction_id: String(begun.body.transaction),
			proof: `${begun.body.secret}:0`,
		});
		return { secret: String(begun.body.secret), done };
	};
	/** Starts a password login through the gates from a fresh browser. */
	const login = async (
		subject = "alice",
		done: unknown = { redirect_to: "https://app.example/back" },
		from?: LoginFrom,
	) => {
		jar = new Map();
		const facts = { subject, amr: ["pwd"], authenticatedAt: runtime.clock.now() };
		const outcome = await app.get(logins).login(testRequest(), facts, done, from);
		keep(outcome.cookies);
		return outcome;
	};
	/** A password login held by mfa: its transaction, the browser holding it, and its factors by kind. */
	const heldLogin = async (subject = "alice", from?: LoginFrom) => {
		const outcome = await login(subject, undefined, from);
		if (outcome.kind !== "held") throw new Error(`the login of ${subject} was not held`);
		const tx = String((outcome.answer as { transaction: string }).transaction);
		const own = new Map(jar);
		const info = await call(
			"GET",
			"/session/mfa/transaction",
			{ transaction_id: tx },
			{ jar: own },
		);
		const factors = (info.body.factors ?? []) as { id: string; kind: string }[];
		const factor = (kind = "code") => factors.find((f) => f.kind === kind)?.id ?? "";
		return { tx, jar: own, factor };
	};
	return {
		app,
		input,
		kept,
		call,
		signIn,
		enrollCode,
		login,
		heldLogin,
		jar: () => jar,
		events: audit.events,
	};
}
