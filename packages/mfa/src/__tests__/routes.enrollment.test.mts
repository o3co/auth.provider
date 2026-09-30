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
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestMfaFactor } from "@o3co/auth-provider-core/testing";
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
	recordingAuditSink,
	seedTotp,
	setsCsrfToken,
	storedData,
	suiteSealing,
	T0,
	thawClock,
	totpProofOf,
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
