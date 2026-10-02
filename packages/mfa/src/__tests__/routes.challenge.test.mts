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
 * `POST /session/mfa/challenge` through the composed application, over the
 * TOTP factor, which needs no challenge, and core's factor double, which
 * answers one: where the challenge's state is kept, that a verification
 * takes it once, and what is audited. See ADR
 * 2026-09-25-multi-factor-authentication, F1 step 4, D7 (as amended at step
 * 3), D11 and D28.
 */

import { randomBytes } from "node:crypto";
import {
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactor,
	type MfaTransactionStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestMfaFactor } from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createMfaSealing } from "#/sealing.mjs";
import { ALICE, boot, configFor, disposeAll, events } from "./moduleHarness.mjs";
import {
	beginLogin,
	contributing,
	freezeClock,
	mfaPost,
	recordingAuditSink,
	seedFactor,
	seedTotp,
	storedData,
	thawClock,
	verify,
} from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
});

/** Core's factor double, answering a challenge: its proof is `secret:nonce`. */
const challenged = (overrides: Partial<MfaFactor> = {}): MfaFactor => ({
	...createTestMfaFactor({ kind: "test", challenge: true }),
	...overrides,
});

/** Boots with the double installed beside TOTP, and alice holding one of its factors under `secret`. */
async function withChallengedFactor(
	factor: MfaFactor = challenged(),
	transactionStore: MfaTransactionStore = createMemoryMfaTransactionStore(),
) {
	const factorStore = createMemoryMfaFactorStore();
	const record = await seedFactor(factorStore, "test", { secret: "s3cret" });
	const audit = recordingAuditSink();
	const booted = await boot({
		config: configFor("required"),
		factorStore,
		transactionStore,
		auditSink: audit,
		extraModules: [contributing(factor)],
	});
	return { ...booted, record, audit };
}

describe("POST /session/mfa/challenge", () => {
	it("answers 200 {} for a factor that needs no challenge, and writes and audits nothing", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record } = await seedTotp(factorStore);
		const audit = recordingAuditSink();
		const { app, transactionStore } = await boot({
			config: configFor("required"),
			factorStore,
			auditSink: audit,
		});
		const { agent, transaction } = await beginLogin(app);

		const res = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: record.id,
		});

		expect(res.status).toBe(200);
		expect(res.body).toEqual({});
		expect(res.headers["cache-control"]).toBe("no-store");
		expect((await transactionStore.get(transaction))?.version).toBe(0);
		expect(audit.of("mfa.challenge.sent")).toEqual([]);
	});

	it("keeps a factor's challenge on the transaction, its state sealed, answers the factor's response, and audits it", async () => {
		const { app, transactionStore, record, audit } = await withChallengedFactor();
		const { agent, transaction } = await beginLogin(app);

		const res = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: record.id,
		});

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ nonce: expect.stringMatching(/^[0-9a-f]{16}$/) });
		const stored = await transactionStore.get(transaction);
		expect(stored?.challenge).toEqual({
			factorId: record.id,
			kind: "test",
			state: expect.any(String),
			expiresAtMs: stored?.expiresAtMs,
		});
		expect(stored?.challenge?.state).not.toContain(res.body.nonce as string);
		expect(stored?.attempts).toBe(0);
		expect(audit.of("mfa.challenge.sent")).toEqual([
			expect.objectContaining({
				type: "mfa.challenge.sent",
				subject: ALICE.id,
				details: { kind: "test", purpose: "login" },
			}),
		]);
	});

	it("answers a factor the subject does not hold 400 invalid_request, and keeps nothing", async () => {
		const { app, transactionStore } = await withChallengedFactor();
		const { agent, transaction } = await beginLogin(app);

		const res = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: "not-a-factor",
		});

		expect(res.status).toBe(400);
		expect(res.body).toEqual({
			error: "invalid_request",
			error_description: "Unknown second factor",
		});
		expect((await transactionStore.get(transaction))?.challenge).toBeUndefined();
	});

	it("answers 503 once when the factor cannot issue its challenge, and keeps nothing", async () => {
		const { app, logger, transactionStore, record, audit } = await withChallengedFactor(
			challenged({
				challenge: async () => {
					throw new Error("relay unreachable");
				},
			}),
		);
		const { agent, transaction } = await beginLogin(app);

		const res = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: record.id,
		});

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "MFA temporarily unavailable",
		});
		expect(events(logger, "error")).toEqual(["mfa_factor_challenge_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({ kind: "test", factorId: record.id });
		expect((await transactionStore.get(transaction))?.challenge).toBeUndefined();
		expect(audit.of("mfa.challenge.sent")).toEqual([]);
	});

	it("answers 503 once when the factor's challenge answers something that is not an object, and keeps nothing", async () => {
		const { app, logger, transactionStore, record } = await withChallengedFactor(
			challenged({ challenge: async () => ({ state: { nonce: "n" }, response: "a string" }) }),
		);
		const { agent, transaction } = await beginLogin(app);

		const res = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: record.id,
		});

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_factor_challenge_unavailable"]);
		expect((await transactionStore.get(transaction))?.challenge).toBeUndefined();
	});

	it("answers 400 as an unknown transaction when the transaction moved on before the challenge was kept, and audits nothing", async () => {
		const store = createMemoryMfaTransactionStore();
		const { app, record, audit } = await withChallengedFactor(challenged(), {
			...store,
			update: async () => null,
		});
		const { agent, transaction } = await beginLogin(app);

		const res = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: record.id,
		});

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
		expect(audit.of("mfa.challenge.sent")).toEqual([]);
	});

	it.each<[string, unknown]>([
		["nothing", undefined],
		["true", true],
		["the transaction unmoved", "unmoved"],
	])(
		"answers 503 once when the transaction store answers %s for the challenge it keeps, and audits nothing",
		async (_label, answer) => {
			const store = createMemoryMfaTransactionStore();
			const { app, logger, record, audit } = await withChallengedFactor(challenged(), {
				...store,
				update: async (...args) => {
					const written = await store.update(...args);
					return (
						answer === "unmoved" ? written && { ...written, version: args[1] } : answer
					) as never;
				},
			});
			const { agent, transaction } = await beginLogin(app);

			const res = await mfaPost(agent, "/challenge", {
				transaction_id: transaction,
				factor_id: record.id,
			});

			expect(res.status).toBe(503);
			expect(events(logger, "error")).toEqual(["mfa_store_unavailable"]);
			expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
				route: "challenge",
				store: "mfa_transaction",
				step: "update",
			});
			expect(audit.of("mfa.challenge.sent")).toEqual([]);
		},
	);

	it("answers 503 once when the transaction store cannot keep the challenge", async () => {
		const store = createMemoryMfaTransactionStore();
		let armed = false;
		const { app, logger, record, audit } = await withChallengedFactor(challenged(), {
			...store,
			update: async (...args) => {
				if (armed) throw new Error("the store is down");
				return store.update(...args);
			},
		});
		const { agent, transaction } = await beginLogin(app);
		armed = true;

		const res = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: record.id,
		});

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_store_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			route: "challenge",
			store: "mfa_transaction",
			step: "update",
		});
		expect(audit.of("mfa.challenge.sent")).toEqual([]);
	});
});

describe("a challenge whose state does not open (D11)", () => {
	/** A transaction store whose taken challenge carries `state(transactionId)` in place of the one kept. */
	const answeringState = (state: (transactionId: string) => string): MfaTransactionStore => {
		const store = createMemoryMfaTransactionStore();
		return {
			...store,
			takeChallenge: async (id, version) => {
				const taken = await store.takeChallenge(id, version);
				return taken ? { ...taken, state: state(id) } : null;
			},
		};
	};

	it.each<[string, (transactionId: string) => string, Record<string, unknown>]>([
		[
			"sealed under a key the ring no longer holds",
			(transactionId) =>
				createMfaSealing({ ring: [{ id: "k-gone", key: randomBytes(32) }] }).sealState(
					{ transactionId, kind: "test", use: "challenge" },
					{ nonce: "n" },
				),
			{ keyId: "k-gone" },
		],
		["corrupted", () => "not-an-envelope", {}],
	])(
		"%s: a right proof is answered 503 once, the attempt it reserved spent — never a wrong code",
		async (_label, state, logged) => {
			const { app, logger, record, audit, transactionStore, userSessionStore } =
				await withChallengedFactor(challenged(), answeringState(state));
			const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
			const { agent, transaction } = await beginLogin(app);
			const issued = await mfaPost(agent, "/challenge", {
				transaction_id: transaction,
				factor_id: record.id,
			});

			const res = await verify(
				agent,
				transaction,
				record.id,
				`s3cret:${issued.body.nonce as string}`,
			);

			expect(res.status).toBe(503);
			expect(res.body).toEqual({
				error: "temporarily_unavailable",
				error_description: "MFA temporarily unavailable",
			});
			expect(events(logger, "error")).toEqual(["mfa_factor_unreadable"]);
			const line = logger.error.mock.calls[0]?.[0] as Record<string, unknown>;
			expect(line).toMatchObject({ route: "verify", kind: "test", state: "challenge", ...logged });
			if (!("keyId" in logged)) expect(line).not.toHaveProperty("keyId");
			expect(audit.of("mfa.verify.failure")).toEqual([]);
			expect(create).not.toHaveBeenCalled();
			expect((await transactionStore.get(transaction))?.attempts).toBe(1);
		},
	);
});

describe("a verification against a challenge", () => {
	it("verifies the proof against the challenge it takes, once: a second verification finds none, and a new challenge serves the next", async () => {
		const { app, transactionStore, record, audit } = await withChallengedFactor();
		const { agent, transaction } = await beginLogin(app);
		const first = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: record.id,
		});
		const nonce = first.body.nonce as string;

		const wrong = await verify(agent, transaction, record.id, `wrong:${nonce}`);
		expect(wrong.status).toBe(401);
		expect((await transactionStore.get(transaction))?.challenge).toBeUndefined();
		const replayed = await verify(agent, transaction, record.id, `s3cret:${nonce}`);
		expect(replayed.status).toBe(401);

		const second = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: record.id,
		});
		const res = await verify(
			agent,
			transaction,
			record.id,
			`s3cret:${second.body.nonce as string}`,
		);
		expect(res.status).toBe(200);
		expect(audit.of("mfa.verify.failure").map((event) => event.details?.reason)).toEqual([
			"invalid",
			"expired",
		]);
		expect(audit.of("mfa.verified")).toHaveLength(1);
	});

	it("leaves a challenge a factor keeps across attempts for the next verification: a wrong proof, then the right one, against one challenge", async () => {
		const { app, transactionStore, record } = await withChallengedFactor(
			challenged({ reusableChallenge: true }),
		);
		const { agent, transaction } = await beginLogin(app);
		const issued = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: record.id,
		});
		const nonce = issued.body.nonce as string;

		expect((await verify(agent, transaction, record.id, `wrong:${nonce}`)).status).toBe(401);
		expect((await transactionStore.get(transaction))?.challenge?.factorId).toBe(record.id);
		expect((await verify(agent, transaction, record.id, `s3cret:${nonce}`)).status).toBe(200);
	});

	it("answers 503 once, before the transaction is consumed and with no session written, when the factor verifies a factor the subject does not hold", async () => {
		const double = challenged();
		const { app, logger, record, userSessionStore, transactionStore } = await withChallengedFactor({
			...double,
			verify: async (ctx) => {
				const result = await double.verify(ctx);
				return result.ok ? { ...result, factorId: "someone-elses" } : result;
			},
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);
		const issued = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: record.id,
		});

		const res = await verify(
			agent,
			transaction,
			record.id,
			`s3cret:${issued.body.nonce as string}`,
		);

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_factor_unreadable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({ state: "verification" });
		expect(await transactionStore.get(transaction)).not.toBeNull();
		expect(create).not.toHaveBeenCalled();
	});

	it("does not take a challenge issued for another factor as this one's", async () => {
		const { app, factorStore, record } = await withChallengedFactor();
		const other = await seedFactor(factorStore, "test", { secret: "0ther" });
		const { agent, transaction } = await beginLogin(app);
		const issued = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: record.id,
		});

		const res = await verify(agent, transaction, other.id, `0ther:${issued.body.nonce as string}`);

		expect(res.status).toBe(401);
	});
});

describe("a factor's answers, read by name, and the copy of what it hands to be sealed", () => {
	/** Counts each named read in `reads`, answering `value`. */
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
		/** A plain object whose field `key` is an own getter: plain JSON-shaped data. */
		const plainWithGetter = (name: string, key: string, value: unknown) =>
			Object.defineProperty({}, key, { get: counted(`${name}.${key}`, value), enumerable: true });
		return { reads, answer, plainWithGetter };
	};

	it("keeps a challenge whose answer is a class's instance behind getters, reading each field once and sealing the plain state it holds", async () => {
		const { reads, answer, plainWithGetter } = counter();
		const { app, record } = await withChallengedFactor(
			challenged({
				challenge: async () => {
					const nonce = randomBytes(8).toString("hex");
					return answer("issued", {
						state: plainWithGetter("state", "nonce", nonce),
						response: { nonce },
						mail: undefined,
					});
				},
			}),
		);
		const { agent, transaction } = await beginLogin(app);

		const res = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: record.id,
		});
		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(reads).toEqual({
			"issued.state": 1,
			"issued.response": 1,
			"issued.mail": 1,
			"state.nonce": 1,
		});

		const verified = await verify(
			agent,
			transaction,
			record.id,
			`s3cret:${res.body.nonce as string}`,
		);
		expect(verified.status).toBe(200);
	});

	it("refuses a challenge whose state is a class's instance, 503 once, keeping nothing", async () => {
		class NonceState {
			get nonce(): string {
				return "n";
			}
		}
		const { app, logger, transactionStore, record } = await withChallengedFactor(
			challenged({
				challenge: async () => ({ state: new NonceState() as never, response: { nonce: "n" } }),
			}),
		);
		const { agent, transaction } = await beginLogin(app);

		const res = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: record.id,
		});

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_factor_challenge_unavailable"]);
		expect((await transactionStore.get(transaction))?.challenge).toBeUndefined();
	});

	it("answers 503 once, the challenge failed, when reading its answer's mail throws, keeping nothing", async () => {
		const { app, logger, transactionStore, record } = await withChallengedFactor(
			challenged({
				challenge: async () =>
					new (class {
						readonly state = { nonce: "n" };
						readonly response = { nonce: "n" };
						get mail(): undefined {
							throw new Error("the answer cannot be read");
						}
					})() as never,
			}),
		);
		const { agent, transaction } = await beginLogin(app);

		const res = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: record.id,
		});

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_factor_challenge_unavailable"]);
		expect((await transactionStore.get(transaction))?.challenge).toBeUndefined();
	});

	/** Boots the double, re-verified by `verify`, with alice holding another factor of its kind ahead of hers. */
	async function withVerifier(overrides: Partial<MfaFactor>) {
		const factorStore = createMemoryMfaFactorStore();
		// Another factor of the kind ahead of it: finding the one verified walks past it.
		await seedFactor(factorStore, "test", { secret: "0ther" });
		const record = await seedFactor(factorStore, "test", { secret: "s3cret" });
		const booted = await boot({
			config: configFor("required"),
			factorStore,
			extraModules: [contributing(challenged(overrides))],
		});
		const { agent, transaction } = await beginLogin(booted.app);
		const challenge = () =>
			mfaPost(agent, "/challenge", { transaction_id: transaction, factor_id: record.id });
		return { ...booted, factorStore, record, agent, transaction, challenge };
	}

	it("reads a verification's answer once, by name — a refusal's and a success's — and hands amrFor and the seal one plain copy of the data it answers", async () => {
		const { reads, answer, plainWithGetter } = counter();
		const base = challenged();
		const handed: unknown[] = [];
		const { factorStore, record, agent, transaction, challenge } = await withVerifier({
			amrFor: (data) => {
				handed.push(data);
				return base.amrFor(data);
			},
			verify: async (ctx) => {
				const result = await base.verify(ctx);
				return result.ok
					? answer("verified", {
							ok: true,
							factorId: result.factorId,
							next: plainWithGetter("next", "secret", "s3cret"),
						})
					: answer("refused", { ok: false, reason: result.reason, factorId: ctx.factor.id });
			},
		});

		await challenge();
		expect((await verify(agent, transaction, record.id, "wrong:proof")).status).toBe(401);
		const res = await verify(
			agent,
			transaction,
			record.id,
			`s3cret:${(await challenge()).body.nonce as string}`,
		);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(reads).toEqual({
			"refused.ok": 1,
			"refused.reason": 1,
			"refused.factorId": 1,
			"verified.ok": 1,
			"verified.factorId": 1,
			"verified.next": 1,
			"next.secret": 1,
		});
		// amrFor was handed the copy: plain, frozen, the getter not read again — what was sealed.
		const [copy] = handed;
		expect(Object.isFrozen(copy)).toBe(true);
		expect(Object.getOwnPropertyDescriptor(copy, "secret")).toMatchObject({ value: "s3cret" });
		expect((await storedData(factorStore, record)).data).toEqual(copy);
	});

	it("refuses a correct proof whose answered data is a class's instance — 503 once, the factor's data left as it was — never sealing it as an empty object", async () => {
		class TotpData {
			get secret(): string {
				return "s3cret";
			}
		}
		const base = challenged();
		const { factorStore, record, agent, transaction, challenge, logger } = await withVerifier({
			verify: async (ctx) => {
				const result = await base.verify(ctx);
				return result.ok ? { ...result, next: new TotpData() as never } : result;
			},
		});
		const before = await storedData(factorStore, record);

		const res = await verify(
			agent,
			transaction,
			record.id,
			`s3cret:${(await challenge()).body.nonce as string}`,
		);

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_factor_unreadable"]);
		const after = await storedData(factorStore, record);
		expect(after.data).toEqual({ secret: "s3cret" });
		expect(after.record.version).toBe(before.record.version);
	});

	it("answers 503 once, the factor unreadable, when reading its verification's answer throws, as when the verification itself throws", async () => {
		const { app, logger, record } = await withChallengedFactor(
			challenged({
				verify: async () =>
					new (class {
						get ok(): boolean {
							throw new Error("the answer cannot be read");
						}
					})() as never,
			}),
		);
		const { agent, transaction } = await beginLogin(app);
		const issued = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: record.id,
		});

		const res = await verify(
			agent,
			transaction,
			record.id,
			`s3cret:${issued.body.nonce as string}`,
		);

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_factor_unreadable"]);
	});

	it("answers 503 once, the factor unreadable, when reading its refusal's reason throws", async () => {
		const { app, logger, record } = await withChallengedFactor(
			challenged({
				verify: async () =>
					new (class {
						readonly ok = false;
						get reason(): string {
							throw new Error("the answer cannot be read");
						}
					})() as never,
			}),
		);
		const { agent, transaction } = await beginLogin(app);
		await mfaPost(agent, "/challenge", { transaction_id: transaction, factor_id: record.id });

		const res = await verify(agent, transaction, record.id, "wrong:proof");

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_factor_unreadable"]);
	});
});
