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
	type MfaFactorStore,
	type MfaTransactionStore,
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
	barrier,
	beginEnrollment,
	beginFirstBinding,
	beginLogin,
	completeEnrollment,
	contributing,
	EXTRA_INTERRUPTION,
	extraRequirement,
	freezeClock,
	leasingOneAfterAnother,
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
		// Written unshown, then marked shown by compare-and-set before its codes were answered.
		expect(records.recovery_code).toMatchObject({ binding: "password", version: 1 });
		const recovery = await storedData(factorStore, records.recovery_code as MfaFactorRecord);
		expect(recovery.data).toMatchObject({ generation: 0, shown: true });
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

	it("writes in this order: the transaction consumed, the factor, the recovery codes, the witness marked, the session, then the codes marked shown", async () => {
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
				createIf: async (record, expected) => {
					calls.push(`create ${record.kind}`);
					return factors.createIf(record, expected);
				},
				update: async (...args) => {
					calls.push("update");
					return factors.update(...args);
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
		expect(calls).toEqual([
			"consume",
			"create totp",
			"create recovery_code",
			"mark",
			"session",
			"update",
		]);
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
				createIf: async (record, expected) => {
					if (record.kind === "recovery_code") throw new Error("factor store unreachable");
					return factors.createIf(record, expected);
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
				createIf: async () => {
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

/**
 * Lets every acquire of the subject's lease on `store` through, and finds
 * none held at its release, as a store that dropped a lease early would (an
 * evicting Redis): two completions can then write past each other, only the
 * checks after the write stand between them, and each says it overran.
 */
function leaseAdmittingEveryWriter(store: MfaTransactionStore): void {
	let tokens = 0;
	vi.spyOn(store, "acquireSubjectLease").mockImplementation(async () => ({
		outcome: "acquired",
		token: `admitted-${++tokens}`,
	}));
	vi.spyOn(store, "releaseSubjectLease").mockResolvedValue(false);
}

/** How many times `logger` said a write overran the subject's lease. */
const overruns = (logger: { readonly error: { readonly mock: { readonly calls: unknown[][] } } }) =>
	logger.error.mock.calls.filter((call) => call[1] === "mfa_subject_lease_overrun").length;

/** Alice's one recovery-code set, opened, as `store` now holds it. */
async function aliceSet(store: MfaFactorStore) {
	const set = (await store.list(ALICE.id)).find((record) => record.kind === "recovery_code");
	if (set === undefined) throw new Error("alice holds no recovery-code set");
	return storedData(store, set);
}

describe("a login's first binding marks its recovery codes shown only in the answer that carries them", () => {
	it("leaves the set unshown when another requirement interrupts the resumed login: its 403 carries no codes, and no codes event", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const audit = recordingAuditSink();
		const extra = extraRequirement();
		const { app } = await boot({
			config: configFor("required", {}, {}, ["mfa", extra.name]),
			factorStore,
			auditSink: audit,
			extraModules: [extra.module],
		});
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const res = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(res.status).toBe(403);
		expect(res.body).toEqual(EXTRA_INTERRUPTION.body);
		const set = await aliceSet(factorStore);
		expect(set.record.version).toBe(0);
		expect(set.data).toMatchObject({ shown: false });
		expect(audit.of("mfa.factor.enrolled")).toHaveLength(1);
		expect(audit.of("mfa.recovery_codes.generated")).toEqual([]);
	});

	it("says a set it could not write once even when another requirement interrupts the resumed login", async () => {
		const factors = createMemoryMfaFactorStore();
		const extra = extraRequirement();
		const { app, logger } = await boot({
			config: configFor("required", {}, {}, ["mfa", extra.name]),
			factorStore: {
				...factors,
				createIf: async (record, expected) => {
					if (record.kind === "recovery_code") throw new Error("factor store unreachable");
					return factors.createIf(record, expected);
				},
			},
			extraModules: [extra.module],
		});
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const res = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(res.status).toBe(403);
		expect(res.body).toEqual(EXTRA_INTERRUPTION.body);
		expect(events(logger, "error")).toEqual(["mfa_recovery_codes_unwritten"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({ sub: ALICE.id });
	});

	it("leaves the set unshown when core will not resume the login: 401 login_required", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const store = createMemoryMfaTransactionStore();
		const { app } = await boot({
			config: configFor("required"),
			factorStore,
			transactionStore: {
				...store,
				// Its continuation waits on a requirement this deployment no longer has.
				consume: async (...args) => {
					const consumed = await store.consume(...args);
					return consumed === null || consumed.continuation === undefined
						? consumed
						: { ...consumed, continuation: { ...consumed.continuation, interruptedBy: "gone" } };
				},
			},
		});
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const res = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(res.status).toBe(401);
		expect(res.body).toEqual({ error: "login_required", error_description: "Log in again" });
		const set = await aliceSet(factorStore);
		expect(set.record.version).toBe(0);
		expect(set.data).toMatchObject({ shown: false });
	});

	it("leaves the set unshown when the session store cannot write the session: 503", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const sessions = createInMemoryUserSessionStore();
		const { app } = await boot({
			config: configFor("required"),
			factorStore,
			userSessionStore: {
				...sessions,
				create: async () => {
					throw new Error("session store unreachable");
				},
			} as UserSessionStore,
		});
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const res = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(res.status).toBe(503);
		expect(res.body).not.toHaveProperty("recovery_codes");
		const set = await aliceSet(factorStore);
		expect(set.record.version).toBe(0);
		expect(set.data).toMatchObject({ shown: false });
	});

	it("answers no codes when the set changed before the answer: the login completes with a fresh CSRF token, recovery_codes_issued false, said once, no codes event", async () => {
		const factors = createMemoryMfaFactorStore();
		const sessions = createInMemoryUserSessionStore();
		const audit = recordingAuditSink();
		const { app, handle, logger } = await boot({
			config: configFor("required"),
			factorStore: factors,
			auditSink: audit,
			userSessionStore: {
				...sessions,
				// Another writer replaces the set while the session is written.
				create: async (...args) => {
					const { items, generation } = await factors.listVersioned(ALICE.id);
					const set = items.find((record) => record.kind === "recovery_code");
					if (set !== undefined && generation !== null) {
						await factors.removeIf(ALICE.id, set.id, generation);
					}
					return sessions.create(...args);
				},
			} as UserSessionStore,
		});
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const done = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect(done.body).toEqual({
			message: "Logged in successfully",
			factor: { id: expect.any(String), kind: "totp" },
			recovery_codes_issued: false,
		});
		const guard = handle.components.csrfGuard;
		if (guard === undefined) throw new Error("the composition holds no CSRF guard");
		expect(setsCsrfToken(done, guard)).toBe(true);
		expect(events(logger, "error")).toEqual(["mfa_recovery_codes_unwritten"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({ sub: ALICE.id });
		expect(audit.of("mfa.recovery_codes.generated")).toEqual([]);
	});

	it("answers no codes when the mark cannot be written: the set left unshown", async () => {
		const factors = createMemoryMfaFactorStore();
		const { app, logger } = await boot({
			config: configFor("required"),
			factorStore: {
				...factors,
				update: async () => {
					throw new Error("factor store unreachable");
				},
			},
		});
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const done = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect(done.body).not.toHaveProperty("recovery_codes");
		expect(done.body.recovery_codes_issued).toBe(false);
		expect(events(logger, "error")).toEqual(["mfa_recovery_codes_unwritten"]);
		const set = await aliceSet(factors);
		expect(set.record.version).toBe(0);
		expect(set.data).toMatchObject({ shown: false });
	});
});

describe("a binding's transaction-store writes under the lease", () => {
	it("answers 503, nothing bound, when the first-binding note is not answered within a Store call's time", async () => {
		const memory = createMemoryMfaFactorStore();
		const { app, transactionStore } = await boot({
			config: configFor("required", { storeTimeoutMs: 1_000 }),
			factorStore: memory,
		});
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");
		vi.spyOn(transactionStore, "noteFirstBinding").mockReturnValue(new Promise<never>(() => {}));
		const create = vi.spyOn(memory, "createIf");

		const done = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(done.status, JSON.stringify(done.body)).toBe(503);
		expect(create).not.toHaveBeenCalled();
	});
});

describe("two first bindings of one subject completed at once under the lease", () => {
	it("serialises them: one binds; the other is refused — 401 login_required, by the first-binding mark or by the records it reads under the lease, or 409 busy — and one factor stands, with no overrun and nothing removed", async () => {
		const memory = createMemoryMfaFactorStore();
		const audit = recordingAuditSink();
		const { app, logger } = await boot({
			config: configFor("required"),
			factorStore: memory,
			auditSink: audit,
		});
		const removeIf = vi.spyOn(memory, "removeIf");
		const owner = await beginFirstBinding(app);
		const other = await beginFirstBinding(app);
		const ownerBegun = await beginEnrollment(owner.agent, owner.transaction, "totp");
		const otherBegun = await beginEnrollment(other.agent, other.transaction, "totp");

		const answers = await Promise.all([
			completeEnrollment(owner.agent, owner.transaction, totpProofOf(ownerBegun.body.secret)),
			completeEnrollment(other.agent, other.transaction, totpProofOf(otherBegun.body.secret)),
		]);

		const statuses = answers.map((res) => res.status).sort();
		expect([
			[200, 401],
			[200, 409],
		]).toContainEqual(statuses);
		const bound = (await memory.list(ALICE.id)).filter((record) => record.kind === "totp");
		expect(bound).toHaveLength(1);
		const loser = answers.find((res) => res.status !== 200);
		expect(loser?.body.error).toBe(loser?.status === 401 ? "login_required" : "mfa_factors_busy");
		// Audited only when the loser's own read under the lease refused it.
		expect(audit.of("mfa.first_binding_conflict").length).toBeLessThanOrEqual(1);
		expect(removeIf).not.toHaveBeenCalled();
		expect(overruns(logger)).toBe(0);
	});
});

describe("a first binding refused by a counting factor its read under the lease finds and its read before the lease did not", () => {
	it("is audited once as mfa.first_binding_conflict, with the subject and the kind alone: 401 login_required, its factor never written, its transaction kept", async () => {
		const memory = createMemoryMfaFactorStore();
		const audit = recordingAuditSink();
		const { app, transactionStore } = await boot({
			config: configFor("required"),
			factorStore: memory,
			auditSink: audit,
		});
		const owner = await beginFirstBinding(app);
		const other = await beginFirstBinding(app);
		const ownerBegun = await beginEnrollment(owner.agent, owner.transaction, "totp");
		const otherBegun = await beginEnrollment(other.agent, other.transaction, "totp");
		leasingOneAfterAnother(transactionStore);

		const answers = await Promise.all([
			completeEnrollment(owner.agent, owner.transaction, totpProofOf(ownerBegun.body.secret)),
			completeEnrollment(other.agent, other.transaction, totpProofOf(otherBegun.body.secret)),
		]);

		expect(answers.map((res) => res.status).sort()).toEqual([200, 401]);
		const lost = answers.findIndex((res) => res.status === 401);
		expect(answers[lost]?.body).toEqual({
			error: "login_required",
			error_description: "Log in again",
		});
		expect((await memory.list(ALICE.id)).filter((record) => record.kind === "totp")).toHaveLength(
			1,
		);
		const conflicts = audit.of("mfa.first_binding_conflict");
		expect(conflicts).toHaveLength(1);
		expect(conflicts[0]).toMatchObject({ subject: ALICE.id });
		expect(conflicts[0]?.details).toEqual({ kind: "totp" });
		const loser = [owner, other][lost];
		if (loser === undefined) throw new Error("no completion lost");
		expect(await transactionStore.get(loser.transaction)).toBeDefined();
	});

	it("is not audited when the read before the lease already found the counting factor: 401 login_required, nothing written", async () => {
		const memory = createMemoryMfaFactorStore();
		const audit = recordingAuditSink();
		const { app } = await boot({
			config: configFor("required"),
			factorStore: memory,
			auditSink: audit,
		});
		const owner = await beginFirstBinding(app);
		const other = await beginFirstBinding(app);
		const ownerBegun = await beginEnrollment(owner.agent, owner.transaction, "totp");
		const otherBegun = await beginEnrollment(other.agent, other.transaction, "totp");
		const bound = await completeEnrollment(
			owner.agent,
			owner.transaction,
			totpProofOf(ownerBegun.body.secret),
		);
		expect(bound.status, JSON.stringify(bound.body)).toBe(200);

		const res = await completeEnrollment(
			other.agent,
			other.transaction,
			totpProofOf(otherBegun.body.secret),
		);

		expect(res.status, JSON.stringify(res.body)).toBe(401);
		expect(res.body.error).toBe("login_required");
		expect((await memory.list(ALICE.id)).filter((record) => record.kind === "totp")).toHaveLength(
			1,
		);
		expect(audit.of("mfa.first_binding_conflict")).toEqual([]);
	});
});

describe("two transactions of one subject racing the first binding past a lease the store does not hold", () => {
	/** Two logins of alice, each with a TOTP enrollment begun, whose completions reach their factors' writes together. */
	async function racing() {
		const memory = createMemoryMfaFactorStore();
		const removeIf = vi.spyOn(memory, "removeIf");
		const arrive = barrier(2);
		const audit = recordingAuditSink();
		const directory = new WitnessingUserRepository();
		const booted = await boot({
			config: configFor("required"),
			// Both completions read the set, and pass its checks, before either writes.
			factorStore: {
				...memory,
				createIf: async (record, expected) => {
					if (record.kind === "totp") await arrive();
					return memory.createIf(record, expected);
				},
			},
			auditSink: audit,
			userRepository: directory,
		});
		leaseAdmittingEveryWriter(booted.transactionStore);
		notingTogether(booted.transactionStore, 2);
		const create = vi.spyOn(booted.userSessionStore as UserSessionStore, "create");
		const logins = [await beginFirstBinding(booted.app), await beginFirstBinding(booted.app)];
		expect(logins[0]?.transaction).not.toBe(logins[1]?.transaction);
		const begun = await Promise.all(
			logins.map((login) => beginEnrollment(login.agent, login.transaction, "totp")),
		);
		const proofs = begun.map((res) => totpProofOf(res.body.secret));
		const answers = await Promise.all(
			logins.map((login, index) =>
				completeEnrollment(login.agent, login.transaction, proofs[index]),
			),
		);
		return {
			...booted,
			memory,
			audit,
			directory,
			logins,
			proofs,
			answers,
			removeIf,
			create,
		};
	}

	it("lets exactly one bind: the other's factor is never written, 401 login_required, and only the one that stands issues codes, marks the witness, is audited and signs in", async () => {
		const { answers, memory, audit, directory, create, logger } = await racing();

		const records = await memory.list(ALICE.id);
		expect(records.filter((record) => record.kind === "totp")).toHaveLength(1);
		expect(records.filter((record) => record.kind === "recovery_code")).toHaveLength(1);
		expect(answers.map((res) => res.status).sort()).toEqual([200, 401]);
		expect(answers.find((res) => res.status === 401)?.body).toEqual({
			error: "login_required",
			error_description: "Log in again",
		});
		expect(directory.marks).toHaveLength(1);
		expect(audit.of("mfa.factor.enrolled")).toHaveLength(1);
		expect(audit.of("mfa.recovery_codes.generated")).toHaveLength(1);
		expect(audit.of("mfa.first_binding_conflict")).toEqual([]);
		expect(create).toHaveBeenCalledTimes(1);
		expect(overruns(logger)).toBe(2);
	});

	it("removes nothing to settle the race, and spends the loser's transaction: a second completion of it is 400", async () => {
		const { answers, removeIf, logins, proofs } = await racing();

		expect(removeIf).not.toHaveBeenCalled();
		const lost = answers.findIndex((res) => res.status === 401);
		const loser = logins[lost];
		if (loser === undefined) throw new Error("no completion lost");
		const again = await completeEnrollment(loser.agent, loser.transaction, proofs[lost]);
		expect(again.status, JSON.stringify(again.body)).toBe(400);
	});
});

describe("a first binding whose factor a reset's removal, stalled past its lease, removes before its codes", () => {
	it("writes no codes after the removal: the set's write is refused, nothing of the binding's stands, and the answer says no codes were issued", async () => {
		const memory = createMemoryMfaFactorStore();
		const audit = recordingAuditSink();
		const { app } = await boot({
			config: configFor("required"),
			factorStore: {
				...memory,
				// The factor is written, and a reset's removal lands before the codes.
				createIf: async (record, expected) => {
					const answer = await memory.createIf(record, expected);
					if (record.kind === "totp") await memory.removeAllForSubject(record.subject);
					return answer;
				},
			},
			auditSink: audit,
		});
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const res = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body).not.toHaveProperty("recovery_codes");
		expect(res.body.recovery_codes_issued).toBe(false);
		expect(await memory.list(ALICE.id)).toEqual([]);
		expect(audit.of("mfa.recovery_codes.generated")).toEqual([]);
		expect(audit.of("mfa.first_binding_conflict")).toEqual([]);
	});
});

describe("a factor's answers, read by name, and the copy of what it hands to be sealed", () => {
	/** Counts each named read in `reads`. */
	const counter = () => {
		const reads: Record<string, number> = {};
		const counted =
			<T,>(name: string, value: T) =>
			(): T => {
				reads[name] = (reads[name] ?? 0) + 1;
				return value;
			};
		/** An answer whose every field is a getter on its class: an answer is read by name. */
		const answer = (name: string, fields: Record<string, unknown>): never => {
			class Answer {}
			for (const [key, value] of Object.entries(fields)) {
				Object.defineProperty(Answer.prototype, key, { get: counted(`${name}.${key}`, value) });
			}
			return new Answer() as never;
		};
		/** Plain JSON-shaped data whose `secret` is an own getter. */
		const plainSecret = (name: string, secret: string) =>
			Object.defineProperty({}, "secret", {
				get: counted(`${name}.secret`, secret),
				enumerable: true,
			});
		return { reads, answer, plainSecret };
	};

	/** Boots with `factor` installed, and alice at her first binding. */
	async function atFirstBinding(factor: MfaFactor) {
		const factorStore = createMemoryMfaFactorStore();
		const booted = await boot({
			config: configFor("required"),
			factorStore,
			extraModules: [contributing(factor)],
		});
		const { agent, transaction } = await beginFirstBinding(booted.app);
		return { ...booted, factorStore, agent, transaction };
	}

	it("binds a factor whose enrollment answers class instances behind getters, reading each field once, and hands amrFor and the seal one plain copy of the data", async () => {
		const { reads, answer, plainSecret } = counter();
		const base = createTestMfaFactor({ kind: "orm" });
		const handed: unknown[] = [];
		const { factorStore, agent, transaction } = await atFirstBinding({
			...base,
			amrFor: (data) => {
				handed.push(data);
				return base.amrFor(data);
			},
			beginEnrollment: async (ctx) => {
				const started = await base.beginEnrollment(ctx);
				return answer("start", {
					state: plainSecret("state", String(started.state.secret)),
					response: started.response,
					mail: undefined,
				});
			},
			completeEnrollment: async (ctx) => {
				const completion = await base.completeEnrollment(ctx);
				if (!completion.ok) return completion;
				return answer("completion", {
					ok: true,
					data: plainSecret("data", String(completion.data.secret)),
					label: undefined,
				});
			},
		});

		const begun = await beginEnrollment(agent, transaction, "orm");
		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		const done = await completeEnrollment(agent, transaction, begun.body.secret);
		expect(done.status, JSON.stringify(done.body)).toBe(200);

		expect(reads).toEqual({
			"start.state": 1,
			"start.response": 1,
			"start.mail": 1,
			"state.secret": 1,
			"completion.ok": 1,
			"completion.data": 1,
			"completion.label": 1,
			"data.secret": 1,
		});
		const [bound] = (await factorStore.list(ALICE.id)).filter((record) => record.kind === "orm");
		if (bound === undefined) throw new Error("no factor was bound");
		// amrFor was handed the copy: plain, frozen, the getter not read again — what was sealed.
		const [copy] = handed;
		expect(Object.isFrozen(copy)).toBe(true);
		expect((await storedData(factorStore, bound)).data).toEqual(copy);
		expect(copy).toEqual({ secret: begun.body.secret });
	});

	it("refuses, 503 once and keeping nothing, an enrollment whose state is a class's instance or a list", async () => {
		class SecretState {
			get secret(): string {
				return "s";
			}
		}
		for (const state of [new SecretState(), ["s"]]) {
			const base = createTestMfaFactor({ kind: "strict" });
			const { logger, transactionStore, agent, transaction } = await atFirstBinding({
				...base,
				beginEnrollment: async () => ({ state: state as never, response: { secret: "s" } }),
			});

			const res = await beginEnrollment(agent, transaction, "strict");

			expect(res.status).toBe(503);
			expect(events(logger, "error")).toEqual(["mfa_factor_enrollment_unavailable"]);
			expect((await transactionStore.get(transaction))?.version).toBe(0);
			await disposeAll();
		}
	});

	it("refuses a completion whose data is a class's instance — 503 once, nothing bound — never sealing it as an empty object", async () => {
		class TotpData {
			get secret(): string {
				return "s";
			}
		}
		const base = createTestMfaFactor({ kind: "strict" });
		const { logger, factorStore, agent, transaction } = await atFirstBinding({
			...base,
			completeEnrollment: async (ctx) => {
				const completion = await base.completeEnrollment(ctx);
				return completion.ok ? { ok: true, data: new TotpData() as never } : completion;
			},
		});
		const begun = await beginEnrollment(agent, transaction, "strict");

		const done = await completeEnrollment(agent, transaction, begun.body.secret);

		expect(done.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_factor_unreadable"]);
		expect((await factorStore.list(ALICE.id)).filter((record) => record.kind === "strict")).toEqual(
			[],
		);
	});

	it("answers 503 once, the enrollment unreadable, when reading a completion's reason or label throws", async () => {
		for (const throwing of ["reason", "label"] as const) {
			const base = createTestMfaFactor({ kind: "strict" });
			const { logger, factorStore, agent, transaction } = await atFirstBinding({
				...base,
				completeEnrollment: async () =>
					Object.defineProperties(
						{ ok: throwing === "label", data: { secret: "s" } },
						{
							[throwing]: {
								get: () => {
									throw new Error("the answer cannot be read");
								},
								enumerable: true,
							},
						},
					) as never,
			});
			const begun = await beginEnrollment(agent, transaction, "strict");

			const done = await completeEnrollment(agent, transaction, begun.body.secret, "Phone");

			expect(done.status, throwing).toBe(503);
			expect(events(logger, "error"), throwing).toEqual(["mfa_factor_unreadable"]);
			expect(
				(await factorStore.list(ALICE.id)).filter((record) => record.kind === "strict"),
				throwing,
			).toEqual([]);
			await disposeAll();
		}
	});
});
