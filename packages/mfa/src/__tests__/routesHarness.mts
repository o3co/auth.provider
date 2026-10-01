/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * What the MFA routes' suites drive the composed application with, beside
 * `moduleHarness.mts`: a frozen clock on a TOTP step, a TOTP factor sealed
 * under the suite's key and seeded in the factor store, the codes it takes,
 * the browser's calls to `/session/mfa/*` on its cookie jar, a recording
 * audit sink, and a tap on the cookie sessions' store. Not a test file.
 */

import { randomBytes } from "node:crypto";
import type {
	AuditEvent,
	AuditSink,
	InterruptionAnswer,
	MfaFactor,
	MfaFactorData,
	MfaFactorRecord,
	MfaFactorStore,
	Module,
	PrimaryAuthentication,
	PrimaryContinuation,
	RequirementInterruption,
	SessionRequirement,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import { defineModule } from "@o3co/auth-provider-core";
import type { RecordingMailSender } from "@o3co/auth-provider-core/testing";
import express from "express";
import type request from "supertest";
import { expect, vi } from "vitest";
import { readMfaSettings } from "#/config.mjs";
import { createRecoveryCodeFactor, generateRecoveryCodes } from "#/recovery/factor.mjs";
import { createMfaSealing, type MfaSealing } from "#/sealing.mjs";
import {
	mfaConfigForTests,
	type SeedTotpFactorOptions,
	seedTotpFactor,
	totpCodeForTests,
} from "#/testing/index.mjs";
import { decodeBase32 } from "#/totp/base32.mjs";
import { totpStep } from "#/totp/rfc6238.mjs";
import {
	ALICE,
	login,
	MFA_KEY,
	mfaSection,
	type SpyLogger,
	sessionIdSet,
} from "./moduleHarness.mjs";

/** The instant every suite freezes the clock at: 10 s into TOTP step 60 000 000 (30 s steps). */
export const T0 = 1_800_000_010_000;

/** The TOTP step {@link T0} falls in. */
export const STEP0 = totpStep(T0, 30);

/** Freezes `Date` at {@link T0}, leaving the timers real, so supertest still runs. */
export function freezeClock(at: number = T0): void {
	if (!vi.isFakeTimers()) vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(at);
}

/** Puts `Date` back. */
export function thawClock(): void {
	vi.useRealTimers();
}

/** The sealing the MFA module builds from the suite's `mfa` section: the same ring, so what it seals the module opens. */
export function suiteSealing(): MfaSealing {
	const settings = readMfaSettings(mfaSection("required"), { deploymentMode: "unset" });
	return createMfaSealing({ ring: settings.encryptionKeys });
}

/** A factor id as the provider makes one: 16 random bytes, base64url. */
export const newFactorId = (): string => randomBytes(16).toString("base64url");

/** A seeded TOTP factor: its record as stored, and its secret. */
export interface SeededTotp {
	readonly record: MfaFactorRecord;
	readonly secret: Buffer;
}

/**
 * Seeds a TOTP factor for `subject` in `store` through the package's testing
 * entry, under the suite's key: SHA1, 6 digits, 30 s, its data sealed to the
 * record it is stored in, unless `sealedFor` names another subject.
 */
export const seedTotp = (
	store: MfaFactorStore,
	subject: string = ALICE.id,
	options: Omit<SeedTotpFactorOptions, "config" | "factorStore" | "subject"> = {},
): Promise<SeededTotp> =>
	seedTotpFactor({
		config: mfaConfigForTests({ key: MFA_KEY }),
		factorStore: store,
		subject,
		...options,
	});

/** Seeds a record of `kind` for `subject` whose data is `data`, sealed to it. */
export async function seedFactor(
	store: MfaFactorStore,
	kind: string,
	data: MfaFactorData,
	subject: string = ALICE.id,
): Promise<MfaFactorRecord> {
	const id = newFactorId();
	const record: MfaFactorRecord = {
		id,
		subject,
		kind,
		label: undefined,
		binding: "password",
		createdAt: new Date(T0 - 86_400_000),
		lastUsedAt: undefined,
		version: 0,
		data: suiteSealing().sealFactorData({ subject, id, kind }, data),
	};
	await store.create(record);
	return record;
}

/** A recovery-code set of `count` codes as the factor issues it, digested under the suite's key: its codes and the record's data. */
export function recoverySet(count: number): {
	readonly codes: readonly string[];
	readonly data: MfaFactorData;
} {
	if (count === 0) return { codes: [], data: { codes: [] } };
	const set = generateRecoveryCodes(
		createRecoveryCodeFactor({ count }),
		suiteSealing().digestsFor("recovery_code"),
	);
	if (set === undefined) throw new Error("the recovery-code factor issued no set");
	return set;
}

/** The TOTP code of `secret` at `atMs`, `offset` steps away (SHA1, 6 digits, 30 s). */
export const totpCode = (secret: Buffer, offset = 0, atMs: number = Date.now()): string =>
	totpCodeForTests(secret, { atMs, offset });

/** A code no step in the window has, for `secret` at `atMs`. */
export function wrongCode(secret: Buffer, atMs: number = Date.now()): string {
	const window = new Set([-2, -1, 0, 1, 2].map((offset) => totpCode(secret, offset, atMs)));
	for (let n = 0; ; n++) {
		const candidate = String(n).padStart(6, "0");
		if (!window.has(candidate)) return candidate;
	}
}

/** The opened data of `record` as the factor store now holds it. */
export async function storedData(
	store: MfaFactorStore,
	record: Pick<MfaFactorRecord, "subject" | "id" | "kind">,
): Promise<{ readonly record: MfaFactorRecord; readonly data: MfaFactorData }> {
	const stored = (await store.list(record.subject)).find((entry) => entry.id === record.id);
	if (stored === undefined) throw new Error("the factor is gone");
	const opened = suiteSealing().openFactorData(record, stored.data);
	if (opened.state !== "ok") throw new Error(`the factor's data does not open: ${opened.state}`);
	return { record: stored, data: opened.value };
}

export type Agent = ReturnType<typeof request.agent>;

/** A fresh CSRF token on the agent's jar: what the page echoes on every POST. */
export async function csrfOf(agent: Agent): Promise<{ header: string; token: string }> {
	const res = await agent.get("/session/csrf");
	return { header: res.body.header_name as string, token: res.body.csrf_token as string };
}

/** `POST /session/mfa<path>` as the page sends it: a fresh CSRF token, the JSON body, any other headers given. */
export async function mfaPost(
	agent: Agent,
	path: string,
	body: Record<string, unknown>,
	headers: Record<string, string> = {},
): Promise<request.Response> {
	const { header, token } = await csrfOf(agent);
	const call = agent.post(`/session/mfa${path}`).set(header, token);
	for (const [name, value] of Object.entries(headers)) call.set(name, value);
	return call.send(body);
}

/** `GET /session/mfa/transaction` with `id` in the `MFA-Transaction` header. */
export const readTransaction = (agent: Agent, id: string): request.Test =>
	agent.get("/session/mfa/transaction").set("MFA-Transaction", id);

/** A verification of `proof` for `factorId` on `transaction`. */
export const verify = (
	agent: Agent,
	transaction: string,
	factorId: string,
	proof: unknown,
): Promise<request.Response> =>
	mfaPost(agent, "/verify", { transaction_id: transaction, factor_id: factorId, proof });

/** A login interrupted for its second factor: the agent holding the regenerated session, the transaction, and the session id it is bound to. */
export interface BegunLogin {
	readonly agent: Agent;
	readonly transaction: string;
	readonly boundTo: string;
}

/** `POST /session/login` answered `403 mfa_required`, as the page receives it. */
export async function beginLogin(
	app: express.Express,
	user: { readonly username: string; readonly password: string } = ALICE,
): Promise<BegunLogin> {
	const { agent, res } = await login(app, { username: user.username, password: user.password });
	expect(res.status, JSON.stringify(res.body)).toBe(403);
	expect(res.body.error).toBe("mfa_required");
	const boundTo = sessionIdSet(res);
	if (boundTo === undefined) throw new Error("the login's 403 set no session");
	return { agent, transaction: res.body.transaction as string, boundTo };
}

/**
 * A lockout whose hard hold the smallest configured `hardLimit` (10) reaches:
 * the backoff at the ninth consecutive failure, and no weekly hold before it.
 */
export const HARD_AT_TEN = {
	threshold: 9,
	hardLimit: 10,
	weeklyBudget: 100,
	baseSeconds: 900,
} as const;

/**
 * Brings alice's run to {@link HARD_AT_TEN}'s hard limit through the routes,
 * Date frozen: five wrong TOTP codes in one login, four in a second (the
 * ninth starts the 900-second backoff), then, past the backoff, one in a
 * third. Answers that third login, one of its attempts spent. The
 * five-and-four split assumes the default five attempts per transaction.
 */
export async function wrongCodesToTheHardLimit(
	app: express.Express,
	totp: SeededTotp,
): Promise<BegunLogin> {
	for (const count of [5, 4]) {
		const { agent, transaction } = await beginLogin(app);
		for (let n = 0; n < count; n++) {
			const res = await verify(agent, transaction, totp.record.id, wrongCode(totp.secret));
			expect(res.status, JSON.stringify(res.body)).toBe(401);
		}
	}
	vi.setSystemTime(Date.now() + HARD_AT_TEN.baseSeconds * 1000 + 1000);
	const third = await beginLogin(app);
	const tenth = await verify(
		third.agent,
		third.transaction,
		totp.record.id,
		wrongCode(totp.secret),
	);
	expect(tenth.status, JSON.stringify(tenth.body)).toBe(401);
	return third;
}

/** `POST /session/login` answered `403 mfa_enrollment_required`, as the page receives it: a first binding begun. */
export async function beginFirstBinding(
	app: express.Express,
	user: { readonly username: string; readonly password: string } = ALICE,
): Promise<BegunLogin & { readonly hints: Record<string, unknown> }> {
	const { agent, res } = await login(app, { username: user.username, password: user.password });
	expect(res.status, JSON.stringify(res.body)).toBe(403);
	expect(res.body.error).toBe("mfa_enrollment_required");
	const boundTo = sessionIdSet(res);
	if (boundTo === undefined) throw new Error("the login's 403 set no session");
	return {
		agent,
		transaction: res.body.transaction as string,
		boundTo,
		hints: res.body.hints as Record<string, unknown>,
	};
}

/** `POST /session/mfa/enrollment` for `kind` on `transaction`. */
export const beginEnrollment = (
	agent: Agent,
	transaction: string,
	kind: unknown,
): Promise<request.Response> =>
	mfaPost(agent, "/enrollment", { transaction_id: transaction, kind });

/** `POST /session/mfa/enrollment/complete` with `proof` on `transaction`, and a `label` when given. */
export const completeEnrollment = (
	agent: Agent,
	transaction: string,
	proof: unknown,
	label?: unknown,
): Promise<request.Response> =>
	mfaPost(agent, "/enrollment/complete", {
		transaction_id: transaction,
		proof,
		...(label === undefined ? {} : { label }),
	});

/** A browser signed in: the agent holding the authenticated session, and the sid of the `UserSession` its login wrote. */
export interface SignedIn {
	readonly agent: Agent;
	readonly sid: string;
}

/** Runs `signIn` with `store`'s `create` watched, and answers the agent with the sid of the session it wrote. */
async function watchingCreate(
	store: UserSessionStore,
	signIn: () => Promise<Agent>,
): Promise<SignedIn> {
	const create = vi.spyOn(store, "create");
	try {
		const agent = await signIn();
		const sid = (create.mock.calls.at(-1)?.[0] as { sid?: unknown } | undefined)?.sid;
		if (typeof sid !== "string") throw new Error("the login wrote no session");
		return { agent, sid };
	} finally {
		create.mockRestore();
	}
}

/** `POST /session/login` as `user` (alice by default), established with no second factor asked. */
export const signIn = (
	app: express.Express,
	store: UserSessionStore,
	user: { readonly username: string; readonly password: string } = ALICE,
): Promise<SignedIn> =>
	watchingCreate(store, async () => {
		const { agent, res } = await login(app, { username: user.username, password: user.password });
		expect(res.status, JSON.stringify(res.body)).toBe(200);
		return agent;
	});

/** A login of alice interrupted for her TOTP factor `seeded`, and established by its code: a session with a second factor verified now. */
export const signInWithTotp = (
	app: express.Express,
	store: UserSessionStore,
	seeded: SeededTotp,
): Promise<SignedIn> =>
	watchingCreate(store, async () => {
		const { agent, transaction } = await beginLogin(app);
		const res = await verify(agent, transaction, seeded.record.id, totpCode(seeded.secret));
		expect(res.status, JSON.stringify(res.body)).toBe(200);
		return agent;
	});

/** `POST /session/mfa/enrollment` for `kind` with no transaction: a factor added from the account page. */
export const enrollFromAccount = (agent: Agent, kind: unknown): Promise<request.Response> =>
	mfaPost(agent, "/enrollment", { kind });

/** `POST /session/mfa/step-up`, naming `transaction` when given. */
export const stepUp = (agent: Agent, transaction?: string): Promise<request.Response> =>
	mfaPost(agent, "/step-up", transaction === undefined ? {} : { transaction_id: transaction });

/** The account-email proof given on `transaction`: challenged, then the code `sender` was handed last verified. */
export async function giveEmailProof(
	agent: Agent,
	transaction: string,
	sender: RecordingMailSender,
): Promise<request.Response> {
	const challenged = await mfaPost(agent, "/challenge", {
		transaction_id: transaction,
		factor_id: "account-email",
	});
	expect(challenged.status, JSON.stringify(challenged.body)).toBe(200);
	const code = sender.sent.at(-1)?.code;
	if (code === undefined) throw new Error("nothing was sent");
	return verify(agent, transaction, "account-email", code);
}

/** The step-up a first binding is answered with: `403 step_up_required`, naming the requirement and its page. */
export const STEP_UP_REQUIRED = {
	error: "step_up_required",
	requirement: "mfa",
	page: "https://auth.example/mfa",
} as const;

/** The code a TOTP enrollment's `secret` (base32, SHA1, 6 digits, 30 s) takes now. */
export function totpProofOf(secret: unknown): string {
	const key = typeof secret === "string" ? decodeBase32(secret) : undefined;
	if (key === undefined) throw new Error("the enrollment answered no secret");
	return totpCode(key);
}

/** An audit sink that keeps what it is handed. */
export interface RecordingAuditSink extends AuditSink {
	readonly events: AuditEvent[];
	/** The events of `type`, oldest first. */
	of(type: string): AuditEvent[];
}

/** A {@link RecordingAuditSink}. */
export function recordingAuditSink(): RecordingAuditSink {
	const events: AuditEvent[] = [];
	return {
		kind: "recording",
		events,
		of: (type) => events.filter((event) => event.type === type),
		async record(event) {
			events.push(event);
		},
	};
}

/** A module contributing `factor` under its kind. */
export const contributing = (factor: MfaFactor) =>
	defineModule({
		name: `test:factor-${factor.kind}`,
		contributes: { mfaFactors: { [factor.kind]: () => factor } },
	});

/** Every argument every level of `logger` was called with, as one text: what a log line could leak. */
export const loggedText = (logger: SpyLogger): string =>
	JSON.stringify(
		(["trace", "debug", "info", "warn", "error", "fatal"] as const).flatMap(
			(level) => logger[level].mock.calls,
		),
	);

/** The 403 {@link extraRequirement} answers a login it interrupts with. */
export const EXTRA_INTERRUPTION: InterruptionAnswer = {
	status: 403,
	body: { error: "extra_required", expires_in: 60 },
};

/** A requirement beside `mfa`: its module, its name, and every ceremony it opened. */
export interface ExtraRequirement {
	readonly name: string;
	readonly module: Module;
	readonly opened: { readonly sessionId: string; readonly continuation: PrimaryContinuation }[];
}

/**
 * A session requirement a deployment might install beside MFA, registered
 * after it: it reaches nothing, meets every use, and at a login interrupts
 * with {@link EXTRA_INTERRUPTION} — or answers what `admitPrimary` says.
 */
export function extraRequirement(
	options: {
		readonly admitPrimary?: (
			primary: PrimaryAuthentication,
		) => Promise<"establish" | RequirementInterruption>;
	} = {},
): ExtraRequirement {
	const name = "extra";
	const opened: ExtraRequirement["opened"] = [];
	const interruption: RequirementInterruption = {
		open: async (sessionId, continuation) => {
			opened.push({ sessionId, continuation });
			return EXTRA_INTERRUPTION;
		},
	};
	const reach: ReadonlySet<string> = new Set();
	const module = defineModule({
		name: "test:extra-requirement",
		contributes: {
			sessionRequirements: {
				[name]: (): SessionRequirement => ({
					name,
					get reach() {
						return reach;
					},
					stepUpPage: undefined,
					remediations: [],
					hintKeys: [],
					admit: async () => ({ outcome: "met" }),
					admitPrimary: options.admitPrimary ?? (async () => interruption),
				}),
			},
		},
	});
	return { name, module, opened };
}

/** Whether `res` hands the browser a fresh CSRF token: a cookie named as the composition's CSRF guard names it. */
export const setsCsrfToken = (
	res: request.Response,
	guard: { readonly cookieName: string },
): boolean =>
	([] as string[])
		.concat(res.headers["set-cookie"] ?? [])
		.some((line) => line.startsWith(`${guard.cookieName}=`));

/** express-session's store, as far as these tests make it fail. */
export interface CookieSessionStore {
	destroy(sid: string, done: (err?: unknown) => void): void;
	set(sid: string, session: unknown, done: (err?: unknown) => void): void;
}

/**
 * A module mounted behind the session middleware that hands the tests the
 * cookie sessions' store, tells whether a cookie session is signed in, and
 * holds a request on a cookie session until released, then saves it back as
 * it was loaded.
 */
export function cookieSessionTap() {
	const tapped: { store?: CookieSessionStore } = {};
	let release: () => void = () => {};
	let reached: () => void = () => {};
	const held = { reached: new Promise<void>((resolve) => (reached = resolve)) };
	const gate = new Promise<void>((resolve) => (release = resolve));
	const router = express.Router();
	router.get("/", (req, res) => {
		tapped.store = (req as unknown as { sessionStore: CookieSessionStore }).sessionStore;
		const session = (req as unknown as { session?: { isAuthenticated?: unknown } }).session;
		res.json({ authenticated: session?.isAuthenticated === true });
	});
	router.get("/hold", async (req, res) => {
		reached();
		await gate;
		const session = (req as unknown as { session: { save(done: () => void): void } }).session;
		session.save(() => res.status(204).end());
	});
	const module = defineModule({
		name: "test:cookie-session-tap",
		contributes: {
			routes: [
				() => ({
					id: "test-cookie-session-tap",
					mountPath: "/test-tap",
					after: ["session-middleware"],
					handler: router,
				}),
			],
		},
	});
	return { module, tapped, held, release: () => release() };
}
