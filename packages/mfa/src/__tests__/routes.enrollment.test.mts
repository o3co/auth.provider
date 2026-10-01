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
 * The forced first binding at a login (the MFA ADR's F3, D12, D22, D24, D25),
 * through the composed application: `POST /session/mfa/enrollment` begins a
 * counting factor's enrollment on the login's transaction, and
 * `POST /session/mfa/enrollment/complete` takes its proof, then — in this
 * order — consumes the transaction, writes the factor, issues the recovery
 * codes, marks the witness, and resumes the login. What each failure writes,
 * and what it leaves standing.
 */

import {
	createInMemoryUserSessionStore,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactor,
	type MfaFactorRecord,
	type MfaTransactionStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createRecordingMailSender, createTestMfaFactor } from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readLongCode } from "#/codes.mjs";
import { mfaRecoveryCodeFactorConfigForTests } from "#/testing/index.mjs";
import { decodeBase32 } from "#/totp/base32.mjs";
import {
	ALICE,
	BOB,
	boot,
	configFor,
	disposeAll,
	events,
	WitnessingUserRepository,
} from "./moduleHarness.mjs";
import {
	beginEnrollment,
	beginFirstBinding,
	beginLogin,
	completeEnrollment,
	contributing,
	EXTRA_INTERRUPTION,
	extraRequirement,
	freezeClock,
	mfaPost,
	recordingAuditSink,
	seedTotp,
	setsCsrfToken,
	storedData,
	suiteSealing,
	T0,
	thawClock,
	totpProofOf,
	verify,
	wrongCode,
} from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
});

const SHOWN = /^[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){3}$/;

const UNKNOWN_KIND = {
	error: "invalid_request",
	error_description: "Unknown second factor kind",
};
const NOT_OPEN = {
	error: "invalid_request",
	error_description: "No enrollment is open in this MFA transaction",
};

/** Alice's records as the factor store holds them, by kind. */
const recordsOf = async (store: { list(subject: string): Promise<readonly MfaFactorRecord[]> }) =>
	Object.fromEntries((await store.list(ALICE.id)).map((record) => [record.kind, record]));

describe("the first login of a subject with no factor", () => {
	it("binds TOTP and gets its recovery codes: the codes answered once, the factor and the codes written, the session established with the second factor", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const audit = recordingAuditSink();
		const { app, handle, userSessionStore, transactionStore } = await boot({
			config: configFor("required"),
			factorStore,
			auditSink: audit,
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginFirstBinding(app);

		const begun = await beginEnrollment(agent, transaction, "totp");
		expect(begun.status).toBe(200);
		expect(begun.headers["cache-control"]).toBe("no-store");
		expect(begun.body).toEqual({
			secret: expect.stringMatching(/^[A-Z2-7]{32}$/),
			otpauth_uri: expect.stringMatching(/^otpauth:\/\/totp\//),
			algorithm: "SHA1",
			digits: 6,
			period: 30,
		});
		expect((await transactionStore.get(transaction))?.pendingEnrollment).toMatchObject({
			kind: "totp",
		});

		const done = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(done.status).toBe(200);
		expect(done.headers["cache-control"]).toBe("no-store");
		expect(done.body).toEqual({
			message: "Logged in successfully",
			factor: { id: expect.stringMatching(/^[A-Za-z0-9_-]{22}$/), kind: "totp" },
			recovery_codes: expect.any(Array),
		});
		const codes = done.body.recovery_codes as string[];
		expect(codes).toHaveLength(10);
		for (const code of codes) expect(code).toMatch(SHOWN);
		const guard = handle.components.csrfGuard;
		if (guard === undefined) throw new Error("the composition holds no CSRF guard");
		expect(setsCsrfToken(done, guard)).toBe(true);

		const records = await recordsOf(factorStore);
		expect(Object.keys(records).sort()).toEqual(["recovery_code", "totp"]);
		expect(records.totp).toMatchObject({
			id: done.body.factor.id,
			subject: ALICE.id,
			binding: "password",
			label: undefined,
			version: 0,
			createdAt: new Date(T0),
		});
		const totp = await storedData(factorStore, records.totp as MfaFactorRecord);
		expect(totp.data).toMatchObject({ secret: begun.body.secret, algorithm: "SHA1", digits: 6 });
		expect(records.recovery_code).toMatchObject({ binding: "password", version: 0 });
		const recovery = await storedData(factorStore, records.recovery_code as MfaFactorRecord);
		const kept = recovery.data.codes as { keyId: string; digest: string }[];
		const digests = suiteSealing().digestsFor("recovery_code");
		codes.forEach((code, index) => {
			expect(digests.matchesDigest([readLongCode(code) as string], kept[index] as never)).toBe(
				"match",
			);
		});
		expect(JSON.stringify(recovery.data)).not.toContain(codes[0] as string);

		expect(await transactionStore.get(transaction)).toBeNull();
		expect(create).toHaveBeenCalledTimes(1);
		expect(create.mock.calls[0]?.[0]).toMatchObject({
			sub: ALICE.id,
			amr: ["pwd", "otp", "mfa"],
			authentication: { primary: "pwd", mfaAt: new Date(T0) },
		});

		expect(audit.of("mfa.factor.enrolled")).toEqual([
			expect.objectContaining({
				subject: ALICE.id,
				details: { kind: "totp", purpose: "login", binding: "password", by: "user" },
			}),
		]);
		expect(audit.of("mfa.recovery_codes.generated")).toEqual([
			expect.objectContaining({
				subject: ALICE.id,
				details: {
					kind: "recovery_code",
					purpose: "login",
					binding: "password",
					by: "user",
					regenerated: false,
				},
			}),
		]);
		expect(audit.of("mfa.verified")).toEqual([]);
		expect(JSON.stringify(audit.events)).not.toContain(codes[0] as string);
		expect(JSON.stringify(audit.events)).not.toContain(ALICE.email);
	});

	it("writes in this order: the transaction consumed, the factor, the recovery codes, the witness marked, then the session", async () => {
		const calls: string[] = [];
		const transactions = createMemoryMfaTransactionStore();
		const factors = createMemoryMfaFactorStore();
		const sessions = createInMemoryUserSessionStore();
		const directory = new (class extends WitnessingUserRepository {
			override async markMfaEnrolled(subject: string, enrolled: boolean): Promise<void> {
				calls.push("mark");
				await super.markMfaEnrolled(subject, enrolled);
			}
		})();
		const { app } = await boot({
			config: configFor("required"),
			transactionStore: {
				...transactions,
				consume: async (...args) => {
					calls.push("consume");
					return transactions.consume(...args);
				},
			},
			factorStore: {
				...factors,
				create: async (record) => {
					calls.push(`create ${record.kind}`);
					return factors.create(record);
				},
			},
			userSessionStore: {
				...sessions,
				create: async (...args) => {
					calls.push("session");
					return sessions.create(...args);
				},
			} as UserSessionStore,
			userRepository: directory,
		});
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const done = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(done.status).toBe(200);
		expect(calls).toEqual(["consume", "create totp", "create recovery_code", "mark", "session"]);
		expect(directory.marks).toEqual([{ subject: ALICE.id, enrolled: true }]);
	});

	it("records a label the page gives, and refuses one it cannot show before anything is spent", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { app, transactionStore } = await boot({ config: configFor("required"), factorStore });
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const refused = await completeEnrollment(
			agent,
			transaction,
			totpProofOf(begun.body.secret),
			"line\nbreak",
		);
		expect(refused.status).toBe(400);
		expect(refused.body).toEqual({ error: "invalid_request", error_description: "Invalid label" });
		expect((await transactionStore.get(transaction))?.attempts).toBe(0);

		const done = await completeEnrollment(
			agent,
			transaction,
			totpProofOf(begun.body.secret),
			"My phone",
		);
		expect(done.status).toBe(200);
		expect(done.body.factor).toEqual({ id: expect.any(String), kind: "totp", label: "My phone" });
		expect((await recordsOf(factorStore)).totp?.label).toBe("My phone");
	});
});

describe("what a first binding refuses", () => {
	it("answers a wrong proof 401 with the attempts left, and writes nothing", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { app, transactionStore, userSessionStore } = await boot({
			config: configFor("required"),
			factorStore,
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");
		const secret = decodeBase32(begun.body.secret as string) ?? Buffer.alloc(0);

		const res = await completeEnrollment(agent, transaction, wrongCode(secret));

		expect(res.status).toBe(401);
		expect(res.body).toEqual({
			error: "mfa_invalid",
			error_description: "Second factor not accepted",
			attempts_remaining: 4,
		});
		expect(await factorStore.list(ALICE.id)).toEqual([]);
		expect(await transactionStore.get(transaction)).toMatchObject({ attempts: 1 });
		expect(create).not.toHaveBeenCalled();
	});

	it("opens no enrollment on a transaction that asks for a second factor — a subject holding one, or one whose only record does not open — and keeps nothing", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await seedTotp(factorStore);
		// Bob's only record carries data sealed to alice's record: it does not open for him.
		await seedTotp(factorStore, BOB.id, { sealedFor: ALICE.id });
		const { app, transactionStore } = await boot({ config: configFor("required"), factorStore });
		for (const user of [ALICE, BOB]) {
			const { agent, transaction } = await beginLogin(app, user);

			const begun = await beginEnrollment(agent, transaction, "totp");
			expect(begun.status, user.username).toBe(400);
			expect(begun.body, user.username).toEqual(NOT_OPEN);
			const complete = await completeEnrollment(agent, transaction, "123456");
			expect(complete.status, user.username).toBe(400);
			expect(complete.body, user.username).toEqual(NOT_OPEN);
			expect(await transactionStore.get(transaction), user.username).toMatchObject({
				version: 0,
				attempts: 0,
				pendingEnrollment: undefined,
			});
		}
	});

	it("offers only a counting factor the user may enroll: an unknown kind, recovery codes and a kind this user cannot enroll are refused, and nothing kept", async () => {
		const refusing: MfaFactor = {
			...createTestMfaFactor({ kind: "picky" }),
			enrollable: () => false,
		};
		const { app, transactionStore } = await boot({
			config: configFor("required"),
			extraModules: [contributing(refusing)],
		});
		const { agent, transaction } = await beginFirstBinding(app);
		for (const kind of ["sms", "recovery_code", "picky", 5, undefined]) {
			const res = await beginEnrollment(agent, transaction, kind);
			expect(res.status, String(kind)).toBe(400);
			expect(res.body, String(kind)).toEqual(UNKNOWN_KIND);
		}
		expect((await transactionStore.get(transaction))?.version).toBe(0);
	});

	it("answers a completion with no enrollment begun 400, spending nothing", async () => {
		const { app, transactionStore } = await boot({ config: configFor("required") });
		const { agent, transaction } = await beginFirstBinding(app);

		const res = await completeEnrollment(agent, transaction, "123456");

		expect(res.status).toBe(400);
		expect(res.body).toEqual({
			error: "invalid_request",
			error_description: "No enrollment is pending in this MFA transaction",
		});
		expect((await transactionStore.get(transaction))?.attempts).toBe(0);
	});

	it("answers 503 once when the factor cannot begin its enrollment — as the WebAuthn factor for an account without a username — and keeps nothing", async () => {
		const failing: MfaFactor = {
			...createTestMfaFactor({ kind: "strict" }),
			beginEnrollment: async () => {
				throw new RangeError("the account has no username as well-formed text");
			},
		};
		const { app, logger, transactionStore } = await boot({
			config: configFor("required"),
			extraModules: [contributing(failing)],
		});
		const { agent, transaction } = await beginFirstBinding(app);

		const res = await beginEnrollment(agent, transaction, "strict");

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_factor_enrollment_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			kind: "strict",
			err: { name: "RangeError" },
		});
		expect((await transactionStore.get(transaction))?.version).toBe(0);
	});

	it("refuses to bind once the subject holds a factor it did not hold at the login — another session bound one — answering 401 login_required and writing nothing", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { app, userSessionStore } = await boot({ config: configFor("required"), factorStore });
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");
		await seedTotp(factorStore);

		const res = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(res.status).toBe(401);
		expect(res.body).toEqual({ error: "login_required", error_description: "Log in again" });
		expect((await factorStore.list(ALICE.id)).map((record) => record.kind)).toEqual(["totp"]);
		expect(create).not.toHaveBeenCalled();
	});

	it("sits behind the CSRF guard: a POST without the token is refused and keeps nothing", async () => {
		const { app, transactionStore } = await boot({ config: configFor("required") });
		const { agent, transaction } = await beginFirstBinding(app);

		const res = await agent
			.post("/session/mfa/enrollment")
			.send({ transaction_id: transaction, kind: "totp" });

		expect(res.status).toBe(403);
		expect((await transactionStore.get(transaction))?.version).toBe(0);
	});
});

describe("a first binding that races or fails part-way", () => {
	it("binds once when the proof is sent twice at once: one completes, the other finds the transaction spent — one factor and one set of codes", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { app } = await boot({ config: configFor("required"), factorStore });
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");
		const proof = totpProofOf(begun.body.secret);

		const answers = await Promise.all([
			completeEnrollment(agent, transaction, proof),
			completeEnrollment(agent, transaction, proof),
		]);

		expect(answers.map((res) => res.status).sort()).toEqual([200, 400]);
		expect((await factorStore.list(ALICE.id)).map((record) => record.kind).sort()).toEqual([
			"recovery_code",
			"totp",
		]);
	});

	it("keeps the binding when the witness cannot be marked: one warning, and the login completes", async () => {
		const directory = new WitnessingUserRepository();
		directory.failWith(new Error("Store unreachable"));
		const factorStore = createMemoryMfaFactorStore();
		const { app, logger } = await boot({
			config: configFor("required"),
			factorStore,
			userRepository: directory,
		});
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const done = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(done.status).toBe(200);
		expect(events(logger, "warn").filter((event) => event.startsWith("mfa_enrollment_"))).toEqual([
			"mfa_enrollment_witness_unwritten",
		]);
		expect((await factorStore.list(ALICE.id)).map((record) => record.kind).sort()).toEqual([
			"recovery_code",
			"totp",
		]);
	});

	it("keeps the binding when the codes cannot be written after the factor was: the answer says none were issued, one error line, no codes event", async () => {
		const factors = createMemoryMfaFactorStore();
		const audit = recordingAuditSink();
		const { app, logger, userSessionStore } = await boot({
			config: configFor("required"),
			factorStore: {
				...factors,
				create: async (record) => {
					if (record.kind === "recovery_code") throw new Error("factor store unreachable");
					return factors.create(record);
				},
			},
			auditSink: audit,
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const done = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(done.status).toBe(200);
		expect(done.body).toEqual({
			message: "Logged in successfully",
			factor: { id: expect.any(String), kind: "totp" },
			recovery_codes_issued: false,
		});
		expect(events(logger, "error")).toEqual(["mfa_recovery_codes_unwritten"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			sub: ALICE.id,
			err: { name: "Error" },
		});
		expect((await factors.list(ALICE.id)).map((record) => record.kind)).toEqual(["totp"]);
		expect(audit.of("mfa.factor.enrolled")).toHaveLength(1);
		expect(audit.of("mfa.recovery_codes.generated")).toEqual([]);
		expect(create).toHaveBeenCalledTimes(1);
	});

	it("answers 503 once when the factor cannot be written, the transaction spent, and no session written", async () => {
		const factors = createMemoryMfaFactorStore();
		const { app, logger, userSessionStore, transactionStore } = await boot({
			config: configFor("required"),
			factorStore: {
				...factors,
				create: async () => {
					throw new Error("factor store unreachable");
				},
			},
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const done = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(done.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_store_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			route: "enrollment",
			store: "mfa_factor",
			step: "create",
		});
		expect(await transactionStore.get(transaction)).toBeNull();
		expect(create).not.toHaveBeenCalled();
	});

	it("answers another requirement that interrupts the resumed login: its 403, the factor bound, and no session written", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const extra = extraRequirement();
		const { app, userSessionStore } = await boot({
			config: configFor("required", {}, {}, ["mfa", extra.name]),
			factorStore,
			extraModules: [extra.module],
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const res = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(res.status).toBe(403);
		expect(res.body).toEqual(EXTRA_INTERRUPTION.body);
		expect(extra.opened).toEqual([
			{
				sessionId: expect.any(String),
				continuation: expect.objectContaining({
					interruptedBy: extra.name,
					done: [{ requirement: "mfa", adds: { amr: ["otp", "mfa"], mfaAtMs: T0 } }],
				}),
			},
		]);
		expect((await factorStore.list(ALICE.id)).map((record) => record.kind)).toContain("totp");
		expect(create).not.toHaveBeenCalled();
	});

	it("issues no recovery codes while their factor is off: the answer carries none and says nothing of them", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const audit = recordingAuditSink();
		const { app } = await boot({
			config: {
				...configFor("required"),
				...mfaRecoveryCodeFactorConfigForTests({ enabled: false }),
			} as never,
			factorStore,
			auditSink: audit,
		});
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const done = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(done.status).toBe(200);
		expect(done.body).toEqual({
			message: "Logged in successfully",
			factor: { id: expect.any(String), kind: "totp" },
		});
		expect((await factorStore.list(ALICE.id)).map((record) => record.kind)).toEqual(["totp"]);
		expect(audit.of("mfa.recovery_codes.generated")).toEqual([]);
	});
});

/** Every caller waits until `n` have arrived, then all go on. */
function barrier(n: number): () => Promise<void> {
	let arrived = 0;
	let release: () => void = () => {};
	const open = new Promise<void>((resolve) => {
		release = resolve;
	});
	return async () => {
		arrived += 1;
		if (arrived >= n) release();
		await open;
	};
}

/**
 * Holds each first-binding mark `store` is asked to note until `n` are:
 * every completion reads the mark, and passes its checks, before any notes it.
 */
function notingTogether(store: MfaTransactionStore, n: number): void {
	const arrive = barrier(n);
	const note = store.noteFirstBinding.bind(store);
	vi.spyOn(store, "noteFirstBinding").mockImplementation(async (subject, atMs, untilMs) => {
		await arrive();
		return note(subject, atMs, untilMs);
	});
}

describe("two transactions of one subject racing the first binding", () => {
	it("leaves at most one first factor: a completion that finds another record beside its own after writing it removes its own, answers 401 login_required and records mfa.first_binding_conflict", async () => {
		const memory = createMemoryMfaFactorStore();
		const arrive = barrier(2);
		const audit = recordingAuditSink();
		const directory = new WitnessingUserRepository();
		const { app, userSessionStore, transactionStore } = await boot({
			config: configFor("required"),
			// Both completions pass the zero-records check before either writes.
			factorStore: {
				...memory,
				create: async (record) => {
					if (record.kind === "totp") await arrive();
					return memory.create(record);
				},
			},
			auditSink: audit,
			userRepository: directory,
		});
		notingTogether(transactionStore, 2);
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const owner = await beginFirstBinding(app);
		const other = await beginFirstBinding(app);
		expect(owner.transaction).not.toBe(other.transaction);
		const ownerBegun = await beginEnrollment(owner.agent, owner.transaction, "totp");
		const otherBegun = await beginEnrollment(other.agent, other.transaction, "totp");

		const answers = await Promise.all([
			completeEnrollment(owner.agent, owner.transaction, totpProofOf(ownerBegun.body.secret)),
			completeEnrollment(other.agent, other.transaction, totpProofOf(otherBegun.body.secret)),
		]);

		const records = await memory.list(ALICE.id);
		const bound = records.filter((record) => record.kind === "totp");
		expect(bound.length).toBeLessThanOrEqual(1);
		const completed = answers.filter((res) => res.status === 200);
		const refused = answers.filter((res) => res.status === 401);
		expect(completed.length + refused.length).toBe(2);
		expect(completed).toHaveLength(bound.length);
		for (const res of refused) {
			expect(res.body).toEqual({ error: "login_required", error_description: "Log in again" });
		}
		// Only a binding that stands issues codes, marks the witness, is audited and signs in.
		expect(records.filter((record) => record.kind === "recovery_code")).toHaveLength(bound.length);
		expect(directory.marks).toHaveLength(bound.length);
		expect(audit.of("mfa.factor.enrolled")).toHaveLength(bound.length);
		expect(audit.of("mfa.recovery_codes.generated")).toHaveLength(bound.length);
		expect(create).toHaveBeenCalledTimes(bound.length);
		expect(audit.of("mfa.first_binding_conflict")).toHaveLength(refused.length);
		for (const event of audit.of("mfa.first_binding_conflict")) {
			expect(event).toMatchObject({ subject: ALICE.id });
			expect(event.details).toEqual({ kind: "totp", removed: true });
		}
	});

	/** Two logins of alice, each with a TOTP enrollment begun, whose completions write their factors past each other; `remove` as given. */
	async function racing(remove: (subject: string, id: string) => Promise<void>) {
		const memory = createMemoryMfaFactorStore();
		const arrive = barrier(2);
		const audit = recordingAuditSink();
		const booted = await boot({
			config: configFor("required"),
			factorStore: {
				...memory,
				create: async (record) => {
					if (record.kind === "totp") await arrive();
					return memory.create(record);
				},
				remove: (subject, id) => remove(subject, id).then(() => memory.remove(subject, id)),
			},
			auditSink: audit,
		});
		notingTogether(booted.transactionStore, 2);
		const logins = [await beginFirstBinding(booted.app), await beginFirstBinding(booted.app)];
		const begun = await Promise.all(
			logins.map((login) => beginEnrollment(login.agent, login.transaction, "totp")),
		);
		const answers = await Promise.all(
			logins.map((login, index) =>
				completeEnrollment(login.agent, login.transaction, totpProofOf(begun[index]?.body.secret)),
			),
		);
		return { ...booted, memory, audit, answers };
	}

	it("tries its own factor's removal three times, and when it still cannot remove it says so: 503, mfa.first_binding_conflict with removed false, and one error line naming the subject and the kind", async () => {
		let removals = 0;
		const { answers, audit, logger, memory } = await racing(async () => {
			removals += 1;
			throw new Error("factor store unreachable");
		});

		expect(answers.map((res) => res.status)).toEqual([503, 503]);
		expect(removals).toBe(6);
		// Both first factors stand; what an operator sees says so.
		expect((await memory.list(ALICE.id)).filter((record) => record.kind === "totp")).toHaveLength(
			2,
		);
		expect(audit.of("mfa.first_binding_conflict").map((event) => event.details)).toEqual([
			{ kind: "totp", removed: false },
			{ kind: "totp", removed: false },
		]);
		const standing = logger.error.mock.calls.filter(
			(call) => call[1] === "mfa_first_binding_factor_standing",
		);
		expect(standing).toHaveLength(2);
		for (const [line] of standing) {
			expect(line).toMatchObject({ sub: ALICE.id, kind: "totp", err: { name: "Error" } });
			expect(Object.keys(line as object).sort()).toEqual(["err", "kind", "sub"]);
		}
	});

	it("leaves at most one factor when a removal fails once and then succeeds: removed true", async () => {
		const failed = new Set<string>();
		const { answers, audit, memory } = await racing(async (_subject, id) => {
			if (!failed.has(id)) {
				failed.add(id);
				throw new Error("factor store unreachable");
			}
		});

		const bound = (await memory.list(ALICE.id)).filter((record) => record.kind === "totp");
		expect(bound.length).toBeLessThanOrEqual(1);
		expect(answers.filter((res) => res.status === 200)).toHaveLength(bound.length);
		for (const event of audit.of("mfa.first_binding_conflict")) {
			expect(event.details).toEqual({ kind: "totp", removed: true });
		}
	});

	it("says a factor it could neither check nor remove still stands: the re-read's outage and the standing factor, each once", async () => {
		const memory = createMemoryMfaFactorStore();
		let written = false;
		const { app, logger } = await boot({
			config: configFor("required"),
			factorStore: {
				...memory,
				create: async (record) => {
					await memory.create(record);
					written = true;
				},
				list: async (subject) => {
					if (written) throw new Error("factor store unreachable");
					return memory.list(subject);
				},
				remove: async () => {
					throw new Error("factor store unreachable");
				},
			},
		});
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const res = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual([
			"mfa_store_unavailable",
			"mfa_first_binding_factor_standing",
		]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({ store: "mfa_factor", step: "list" });
		expect(logger.error.mock.calls[1]?.[0]).toMatchObject({ sub: ALICE.id, kind: "totp" });
		expect(await memory.list(ALICE.id)).toHaveLength(1);
	});

	it("removes its own factor and answers 503 once when the records cannot be read again after it was written: never a binding it could not check", async () => {
		const memory = createMemoryMfaFactorStore();
		let written = false;
		const { app, logger, userSessionStore } = await boot({
			config: configFor("required"),
			factorStore: {
				...memory,
				create: async (record) => {
					await memory.create(record);
					written = true;
				},
				list: async (subject) => {
					if (written) throw new Error("factor store unreachable");
					return memory.list(subject);
				},
			},
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const res = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_store_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			route: "enrollment",
			store: "mfa_factor",
			step: "list",
		});
		expect(await memory.list(ALICE.id)).toEqual([]);
		expect(create).not.toHaveBeenCalled();
	});
});

describe("a first binding whose own factor is gone when it reads the records again", () => {
	it("does not stand: removed as its own, 401 login_required, mfa.first_binding_conflict removed true — no codes, no witness mark, D25's flag kept, no session", async () => {
		const memory = createMemoryMfaFactorStore();
		const transactions = createMemoryMfaTransactionStore();
		// An operator reset left D25's flag, so the binding is given with the proof and would clear it.
		await transactions.requireEmailProofAtNextBinding(ALICE.id);
		const sender = createRecordingMailSender();
		const audit = recordingAuditSink();
		const directory = new WitnessingUserRepository();
		const { app, userSessionStore } = await boot({
			config: configFor("required", { enrollment: { requireEmailProof: "never" } }),
			factorStore: {
				...memory,
				// The factor is written, and a reset removes the subject's records before the re-read.
				create: async (record) => {
					await memory.create(record);
					if (record.kind === "totp") await memory.removeAllForSubject(record.subject);
				},
			},
			transactionStore: transactions,
			mailSender: sender,
			auditSink: audit,
			userRepository: directory,
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginFirstBinding(app);
		await mfaPost(agent, "/challenge", { transaction_id: transaction, factor_id: "account-email" });
		const code = sender.sent.at(-1)?.code;
		expect((await verify(agent, transaction, "account-email", code)).status).toBe(200);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const res = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(res.status).toBe(401);
		expect(res.body).toEqual({ error: "login_required", error_description: "Log in again" });
		expect(await memory.list(ALICE.id)).toEqual([]);
		expect(directory.marks).toEqual([]);
		expect(await transactions.emailProofRequiredAtNextBinding(ALICE.id)).toBe(true);
		expect(create).not.toHaveBeenCalled();
		expect(audit.of("mfa.first_binding_conflict").map((event) => event.details)).toEqual([
			{ kind: "totp", removed: true },
		]);
		expect(audit.of("mfa.factor.enrolled")).toEqual([]);
		expect(audit.of("mfa.recovery_codes.generated")).toEqual([]);
	});
});
