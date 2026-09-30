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
 * `POST /session/mfa/verify` and `POST /session/mfa/challenge` through the
 * composed application, over a seeded TOTP factor: a TOTP login end to end,
 * RFC 6238's rules on the codes it accepts, the transaction's attempts, the
 * binding, the guards every POST sits behind, and what the routes log and
 * audit. See ADR 2026-09-25-multi-factor-authentication, F1, F6, D21, D27
 * and D28.
 */

import {
	type CsrfGuard,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	createMemoryRateLimiter,
	type RateLimiter,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { encodeBase32 } from "#/totp/base32.mjs";
import {
	ALICE,
	boot,
	configFor,
	disposeAll,
	events,
	login,
	sessionIdSet,
} from "./moduleHarness.mjs";
import {
	beginLogin,
	csrfOf,
	freezeClock,
	loggedText,
	mfaPost,
	readTransaction,
	recordingAuditSink,
	STEP0,
	seedFactor,
	seedTotp,
	setsCsrfToken,
	storedData,
	T0,
	thawClock,
	totpCode,
	verify,
	wrongCode,
} from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
});

/** The composition's CSRF guard. */
const csrfGuardOf = (handle: { readonly components: { readonly csrfGuard?: CsrfGuard } }) => {
	const guard = handle.components.csrfGuard;
	if (guard === undefined) throw new Error("the composition holds no CSRF guard");
	return guard;
};

const UNKNOWN = {
	error: "invalid_request",
	error_description: "Unknown or expired MFA transaction",
};

const UNKNOWN_FACTOR = { error: "invalid_request", error_description: "Unknown second factor" };

/** A second factor refused, with the attempts the transaction has left. */
const refused = (attemptsRemaining: number) => ({
	error: "mfa_invalid",
	error_description: "Second factor not accepted",
	attempts_remaining: attemptsRemaining,
});

describe.each(["required", "optional"] as const)("a TOTP login under %s", (mode) => {
	it("goes password, 403 mfa_required, the transaction, the challenge, the verification — and establishes the session with the second factor recorded, on a rotated session id, with a fresh CSRF token", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const audit = recordingAuditSink();
		const { app, handle, userSessionStore, transactionStore } = await boot({
			config: configFor(mode),
			factorStore,
			auditSink: audit,
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction, boundTo } = await beginLogin(app);

		const read = await readTransaction(agent, transaction);
		expect(read.body.factors).toEqual([{ id: record.id, kind: "totp" }]);
		const challenge = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: record.id,
		});
		expect(challenge.status).toBe(200);
		expect(challenge.body).toEqual({});
		const res = await verify(agent, transaction, record.id, totpCode(secret));

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ message: "Logged in successfully" });
		expect(res.headers["cache-control"]).toBe("no-store");
		// The session id rotates, and the page gets a token for the new session.
		const established = sessionIdSet(res);
		expect(established).toBeDefined();
		expect(established).not.toBe(boundTo);
		expect(setsCsrfToken(res, csrfGuardOf(handle))).toBe(true);
		// One session, recorded as a password login with a verified second factor.
		expect(create).toHaveBeenCalledTimes(1);
		expect(create.mock.calls[0]?.[0]).toMatchObject({
			sub: ALICE.id,
			amr: ["pwd", "otp", "mfa"],
			authentication: { primary: "pwd", mfaAt: new Date(T0) },
		});
		// The transaction is spent; the factor moved on to the step it matched.
		expect(await transactionStore.get(transaction)).toBeNull();
		const after = await storedData(factorStore, record);
		expect(after.data.lastUsedStep).toBe(STEP0);
		expect(after.record.version).toBe(1);
		expect(after.record.lastUsedAt).toEqual(new Date(T0));
		// Audited: the verification, and nothing refused.
		expect(audit.of("mfa.verified")).toEqual([
			expect.objectContaining({
				type: "mfa.verified",
				subject: ALICE.id,
				details: { kind: "totp", purpose: "login" },
			}),
		]);
		expect(audit.of("mfa.verify.failure")).toEqual([]);
		expect((await readTransaction(agent, transaction)).status).toBe(400);
	});
});

describe("the codes a verification accepts (RFC 6238)", () => {
	it("refuses the code that logged in, in the next login: its step is spent", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const audit = recordingAuditSink();
		const { app } = await boot({ config: configFor("required"), factorStore, auditSink: audit });
		const code = totpCode(secret);
		const first = await beginLogin(app);
		expect((await verify(first.agent, first.transaction, record.id, code)).status).toBe(200);

		const second = await beginLogin(app);
		const res = await verify(second.agent, second.transaction, record.id, code);

		expect(res.status).toBe(401);
		expect(res.body).toEqual(refused(4));
		expect(audit.of("mfa.verify.failure")).toEqual([
			expect.objectContaining({
				subject: ALICE.id,
				details: { kind: "totp", purpose: "login", reason: "replayed" },
			}),
		]);
	});

	it("refuses an older code once a newer one was accepted, though both are in the window", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const { app } = await boot({ config: configFor("required"), factorStore });
		const first = await beginLogin(app);
		expect(
			(await verify(first.agent, first.transaction, record.id, totpCode(secret, +1))).status,
		).toBe(200);

		const second = await beginLogin(app);
		const res = await verify(second.agent, second.transaction, record.id, totpCode(secret, 0));

		expect(res.status).toBe(401);
		expect((await storedData(factorStore, record)).data.lastUsedStep).toBe(STEP0 + 1);
	});

	it.each([
		[-1, 200],
		[+1, 200],
		[-2, 401],
		[+2, 401],
	] as const)(
		"at a window of 1, a code %i steps from now is answered %i",
		async (offset, status) => {
			const factorStore = createMemoryMfaFactorStore();
			const { record, secret } = await seedTotp(factorStore);
			const { app } = await boot({ config: configFor("required"), factorStore });
			const { agent, transaction } = await beginLogin(app);

			const res = await verify(agent, transaction, record.id, totpCode(secret, offset));

			expect(res.status).toBe(status);
		},
	);

	it("holds the window at the very first and the very last millisecond of the current step", async () => {
		for (const at of [STEP0 * 30_000, STEP0 * 30_000 + 29_999]) {
			freezeClock(at);
			const factorStore = createMemoryMfaFactorStore();
			const { record, secret } = await seedTotp(factorStore);
			const { app } = await boot({ config: configFor("required"), factorStore });
			for (const [offset, status] of [
				[-2, 401],
				[+2, 401],
				[-1, 200],
			] as const) {
				const { agent, transaction } = await beginLogin(app);
				const res = await verify(agent, transaction, record.id, totpCode(secret, offset, at));
				expect(res.status, `${at} ${offset}`).toBe(status);
			}
		}
	});

	it("takes mfa-totp-factor.window as the steps either side of now: at 0, only the current step's code", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const { app } = await boot({ config: configFor("required", {}, { window: 0 }), factorStore });
		const { agent, transaction } = await beginLogin(app);
		expect((await verify(agent, transaction, record.id, totpCode(secret, -1))).status).toBe(401);
		expect((await verify(agent, transaction, record.id, totpCode(secret, 0))).status).toBe(200);
	});
});

describe("a transaction's attempts (D21)", () => {
	it("answers a wrong code 401 mfa_invalid with the attempts left, and ends the transaction at mfa.maxAttemptsPerTransaction — a right code after that is not checked", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const audit = recordingAuditSink();
		const { app, userSessionStore, transactionStore } = await boot({
			config: configFor("required", { maxAttemptsPerTransaction: 3 }),
			factorStore,
			auditSink: audit,
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);

		const answers = [];
		for (let n = 0; n < 3; n++) {
			answers.push(await verify(agent, transaction, record.id, wrongCode(secret)));
		}
		const last = await verify(agent, transaction, record.id, totpCode(secret));

		expect(answers.map((res) => [res.status, res.body])).toEqual([
			[401, refused(2)],
			[401, refused(1)],
			[401, refused(0)],
		]);
		expect(last.status).toBe(401);
		expect(last.body).toEqual(refused(0));
		expect(await transactionStore.get(transaction)).toBeNull();
		expect(create).not.toHaveBeenCalled();
		expect((await storedData(factorStore, record)).record.version).toBe(0);
		expect(audit.of("mfa.verify.failure").map((event) => event.details?.reason)).toEqual([
			"invalid",
			"invalid",
			"invalid",
			"exhausted",
		]);
	});

	it("spends an attempt on a proof that is not a code, and answers it as any refused proof", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record } = await seedTotp(factorStore);
		const audit = recordingAuditSink();
		const { app, transactionStore } = await boot({
			config: configFor("required"),
			factorStore,
			auditSink: audit,
		});
		const { agent, transaction } = await beginLogin(app);

		const answers = [];
		for (const proof of [123456, "12345", " 123456", "1234567", null]) {
			answers.push(await verify(agent, transaction, record.id, proof));
		}

		expect(answers.map((res) => res.body)).toEqual([
			refused(4),
			refused(3),
			refused(2),
			refused(1),
			refused(0),
		]);
		expect((await transactionStore.get(transaction))?.attempts).toBe(5);
		expect(
			audit.of("mfa.verify.failure").every((event) => event.details?.reason === "malformed"),
		).toBe(true);
	});

	it("refuses a factor the subject does not hold, or one no installed factor verifies, 400 invalid_request, spending no attempt", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { secret } = await seedTotp(factorStore);
		const retired = await seedFactor(factorStore, "retired", { anything: true });
		const bobs = await seedTotp(factorStore, "u-bob");
		const { app, transactionStore } = await boot({ config: configFor("required"), factorStore });
		const { agent, transaction } = await beginLogin(app);

		for (const factorId of [retired.id, bobs.record.id, "no-such-factor", undefined, 7]) {
			const res = await verify(agent, transaction, factorId as string, totpCode(secret));
			expect(res.status, String(factorId)).toBe(400);
			expect(res.body, String(factorId)).toEqual(UNKNOWN_FACTOR);
		}
		expect((await transactionStore.get(transaction))?.attempts).toBe(0);
	});
});

describe("the binding (D27)", () => {
	it("answers a verification on a transaction bound to another browser exactly as on an unknown one, and spends none of its attempts", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const { app, transactionStore } = await boot({ config: configFor("required"), factorStore });
		const { transaction } = await beginLogin(app);
		const other = request.agent(app);
		await login(app, {}, other);

		const foreign = await verify(other, transaction, record.id, totpCode(secret));
		const unknown = await verify(other, "A".repeat(43), record.id, totpCode(secret));
		const challenge = await mfaPost(other, "/challenge", {
			transaction_id: transaction,
			factor_id: record.id,
		});

		for (const res of [foreign, unknown, challenge]) {
			expect(res.status).toBe(400);
			expect(res.body).toEqual(UNKNOWN);
		}
		expect((await transactionStore.get(transaction))?.attempts).toBe(0);
		expect((await storedData(factorStore, record)).record.version).toBe(0);
	});

	it("takes the id from the body or from the MFA-Transaction header, and refuses the two disagreeing", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const { app, transactionStore } = await boot({ config: configFor("required"), factorStore });
		const first = await beginLogin(app);
		const disagreeing = await mfaPost(
			first.agent,
			"/verify",
			{ transaction_id: first.transaction, factor_id: record.id, proof: totpCode(secret) },
			{ "MFA-Transaction": "B".repeat(43) },
		);
		expect(disagreeing.status).toBe(400);
		expect(disagreeing.body).toEqual(UNKNOWN);
		expect((await transactionStore.get(first.transaction))?.attempts).toBe(0);

		const res = await mfaPost(
			first.agent,
			"/verify",
			{ factor_id: record.id, proof: totpCode(secret) },
			{ "MFA-Transaction": first.transaction },
		);
		expect(res.status).toBe(200);
	});

	it("never takes the id from the URL", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const { app, transactionStore } = await boot({ config: configFor("required"), factorStore });
		const { agent, transaction } = await beginLogin(app);
		const { header, token } = await csrfOf(agent);

		const res = await agent
			.post(`/session/mfa/verify?transaction_id=${transaction}&transaction=${transaction}`)
			.set(header, token)
			.send({ factor_id: record.id, proof: totpCode(secret) });

		expect(res.status).toBe(400);
		expect(res.body).toEqual(UNKNOWN);
		expect((await transactionStore.get(transaction))?.attempts).toBe(0);
	});
});

describe("the guards every POST sits behind", () => {
	it("refuses a POST with neither a same-origin signal nor a CSRF token, before the transaction is read", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const transactionStore = createMemoryMfaTransactionStore();
		const get = vi.spyOn(transactionStore, "get");
		const { app } = await boot({ config: configFor("required"), factorStore, transactionStore });
		const { agent, transaction } = await beginLogin(app);
		get.mockClear();

		for (const path of ["/verify", "/challenge"]) {
			const res = await agent
				.post(`/session/mfa${path}`)
				.send({ transaction_id: transaction, factor_id: record.id, proof: totpCode(secret) });
			expect(res.status, path).toBe(403);
			expect(res.headers["cache-control"], path).toBe("no-store");
		}
		expect(get).not.toHaveBeenCalled();
	});

	it("limits every POST per client address under the mfa prefix, before the transaction is read, and leaves the GET unlimited", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const keys: string[] = [];
		const inner = createMemoryRateLimiter({
			limits: {},
			defaultLimit: { limit: 1000, windowSeconds: 60 },
		});
		let allow = true;
		const rateLimiter: RateLimiter = {
			kind: "test",
			check: async (key, ctx) => {
				keys.push(key);
				if (key.startsWith("mfa:") && !allow) return { allowed: false, reason: "slow down" };
				return inner.check(key, ctx);
			},
		};
		const transactionStore = createMemoryMfaTransactionStore();
		const get = vi.spyOn(transactionStore, "get");
		const { app } = await boot({
			config: configFor("required"),
			factorStore,
			transactionStore,
			rateLimiter,
		});
		const { agent, transaction } = await beginLogin(app);
		keys.length = 0;

		await readTransaction(agent, transaction);
		await mfaPost(agent, "/challenge", { transaction_id: transaction, factor_id: record.id });
		await verify(agent, transaction, record.id, wrongCode(secret));
		expect(keys.filter((key) => key.startsWith("mfa:"))).toEqual([
			expect.stringMatching(/^mfa:ip:/),
			expect.stringMatching(/^mfa:ip:/),
		]);

		allow = false;
		get.mockClear();
		const limited = await verify(agent, transaction, record.id, totpCode(secret));
		expect(limited.status).toBe(429);
		expect(limited.body.error).toBe("rate_limited");
		expect(limited.headers["cache-control"]).toBe("no-store");
		expect(get).not.toHaveBeenCalled();
	});

	it("answers every response no-store, a refusal's included", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const { app } = await boot({ config: configFor("required"), factorStore });
		const { agent, transaction } = await beginLogin(app);

		const answers = [
			await readTransaction(agent, transaction),
			await readTransaction(agent, "A".repeat(43)),
			await mfaPost(agent, "/challenge", { transaction_id: transaction, factor_id: "nope" }),
			await verify(agent, transaction, record.id, wrongCode(secret)),
			await verify(agent, transaction, record.id, totpCode(secret)),
		];

		expect(answers.map((res) => res.status)).toEqual([200, 400, 400, 401, 200]);
		for (const res of answers) expect(res.headers["cache-control"]).toBe("no-store");
	});

	it("answers POST /session/mfa/step-up 404: the step-up is not built", async () => {
		const { app } = await boot({ config: configFor("required") });
		const agent = request.agent(app);
		const { header, token } = await csrfOf(agent);
		const res = await agent.post("/session/mfa/step-up").set(header, token).send({});
		expect(res.status).toBe(404);
	});
});

describe("what the routes log", () => {
	it("never logs the transaction id, a code, a factor's secret or its sealed data — through a refused code, a replayed one and a login", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const { app, logger } = await boot({ config: configFor("required"), factorStore });
		const { agent, transaction } = await beginLogin(app);
		const wrong = wrongCode(secret);
		await verify(agent, transaction, record.id, wrong);
		const code = totpCode(secret);
		await verify(agent, transaction, record.id, code);
		const again = await beginLogin(app);
		await verify(again.agent, again.transaction, record.id, code);

		const text = loggedText(logger);
		for (const secretText of [
			transaction,
			again.transaction,
			wrong,
			code,
			record.data,
			encodeBase32(secret),
		]) {
			expect(text).not.toContain(secretText);
		}
		expect(events(logger, "error")).toEqual([]);
	});
});
