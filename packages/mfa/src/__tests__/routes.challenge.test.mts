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

import {
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactor,
	type MfaTransactionStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestMfaFactor } from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ALICE, boot, configFor, disposeAll, events } from "./moduleHarness.mjs";
import {
	beginLogin,
	contributing,
	freezeClock,
	mfaPost,
	recordingAuditSink,
	seedFactor,
	seedTotp,
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
