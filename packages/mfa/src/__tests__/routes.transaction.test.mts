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
 * `GET /session/mfa/transaction` through the composed application: what the
 * page reads of the login's transaction, to the browser it is bound to
 * alone. See ADR 2026-09-25-multi-factor-authentication, "The HTTP surface"
 * and F1.
 */

import { createMemoryMfaFactorStore, type MfaFactor } from "@o3co/auth-provider-core";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ALICE, BOB, boot, configFor, disposeAll, login } from "./moduleHarness.mjs";
import { stubFactor } from "./requirementHarness.mjs";
import {
	beginLogin,
	contributing,
	freezeClock,
	newFactorId,
	readTransaction,
	recoverySet,
	seedFactor,
	seedTotp,
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

/** What every read of a transaction that is not this browser's usable one is answered. */
const UNKNOWN = {
	error: "invalid_request",
	error_description: "Unknown or expired MFA transaction",
};

describe("GET /session/mfa/transaction", () => {
	it("answers the browser the transaction is bound to: its purpose, the usable factors, what follows, when it expires and the attempts left — never a factor's data", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record } = await seedTotp(factorStore, ALICE.id, { label: "Phone" });
		const { app } = await boot({ config: configFor("required"), factorStore });
		const { agent, transaction } = await beginLogin(app);

		const res = await readTransaction(agent, transaction);

		expect(res.status).toBe(200);
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.body).toEqual({
			purpose: "login",
			factors: [{ id: record.id, kind: "totp", label: "Phone" }],
			enrollment: "none",
			email_proof: false,
			expires_in: 600,
			attempts_remaining: 5,
		});
		expect(JSON.stringify(res.body)).not.toContain(record.data);
	});

	it("counts expires_in down on the clock and attempts_remaining down as verifications spend them", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const { app } = await boot({ config: configFor("required"), factorStore });
		const { agent, transaction } = await beginLogin(app);
		await verify(agent, transaction, record.id, wrongCode(secret));
		freezeClock(T0 + 90_500);

		const res = await readTransaction(agent, transaction);

		expect(res.body).toMatchObject({ expires_in: 510, attempts_remaining: 4 });
	});

	it("lists only the factors an installed factor verifies: a record of a kind nothing installs is not offered", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record } = await seedTotp(factorStore);
		await seedFactor(factorStore, "retired", { anything: true });
		const { app } = await boot({ config: configFor("required"), factorStore });
		const { agent, transaction } = await beginLogin(app);

		const res = await readTransaction(agent, transaction);

		expect(res.body.factors).toEqual([{ id: record.id, kind: "totp" }]);
	});

	it("leaves out a recovery set with no code left, and lists one with a code left", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record } = await seedTotp(factorStore);
		await seedFactor(factorStore, "recovery_code", recoverySet(0).data);
		const left = await seedFactor(factorStore, "recovery_code", recoverySet(1).data);
		const { app } = await boot({ config: configFor("required"), factorStore });
		const { agent, transaction } = await beginLogin(app);

		const res = await readTransaction(agent, transaction);

		const listed = (res.body.factors as { id: string }[]).map(({ id }) => id).sort();
		expect(listed).toEqual([record.id, left.id].sort());
	});

	it("lists a factor's hint when its data opens, and a factor whose data does not open without one — never leaving it out", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const hinted = await seedFactor(factorStore, "hinted", { address: "k***@example.com" });
		const sealedForBob = await seedFactor(
			factorStore,
			"hinted",
			{ address: "b***@example.com" },
			BOB.id,
		);
		const copied = { ...sealedForBob, subject: ALICE.id, id: newFactorId() };
		await factorStore.create(copied);
		const factor: MfaFactor = {
			...stubFactor("hinted", ["otp"]),
			describe: (data) => ({ hint: String(data.address) }),
		};
		const { app } = await boot({
			config: configFor("required"),
			factorStore,
			extraModules: [contributing(factor)],
		});
		const { agent, transaction } = await beginLogin(app);

		const res = await readTransaction(agent, transaction);

		expect(res.body.factors).toEqual(
			expect.arrayContaining([
				{ id: hinted.id, kind: "hinted", hint: "k***@example.com" },
				{ id: copied.id, kind: "hinted" },
			]),
		);
		expect(res.body.factors).toHaveLength(2);
	});

	it("answers a first binding's transaction with no factor, and the enrollment it requires", async () => {
		const { app } = await boot({ config: configFor("required") });
		const { agent, res: interrupted } = await login(app);
		expect(interrupted.body.error).toBe("mfa_enrollment_required");

		const res = await readTransaction(agent, interrupted.body.transaction as string);

		expect(res.body).toMatchObject({ factors: [], enrollment: "required", email_proof: false });
	});

	it("answers a transaction bound to another browser exactly as an unknown one, and as a missing or malformed id", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await seedTotp(factorStore);
		const { app } = await boot({ config: configFor("required"), factorStore });
		const { transaction } = await beginLogin(app);
		const other = request.agent(app);
		// The other browser holds a session of its own.
		await login(app, {}, other);

		const answers = [
			await readTransaction(other, transaction),
			await readTransaction(other, "A".repeat(43)),
			await readTransaction(other, "not an id"),
			await other.get("/session/mfa/transaction"),
		];

		for (const res of answers) {
			expect(res.status).toBe(400);
			expect(res.body).toEqual(UNKNOWN);
			expect(res.headers["cache-control"]).toBe("no-store");
		}
	});

	it("reads the id from the MFA-Transaction header alone, never from the URL", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await seedTotp(factorStore);
		const { app } = await boot({ config: configFor("required"), factorStore });
		const { agent, transaction } = await beginLogin(app);

		for (const query of [
			`transaction=${transaction}`,
			`transaction_id=${transaction}`,
			`mfa_transaction=${transaction}`,
		]) {
			const res = await agent.get(`/session/mfa/transaction?${query}`);
			expect(res.status, query).toBe(400);
			expect(res.body, query).toEqual(UNKNOWN);
		}
	});

	it("answers a transaction spent by its verification as an unknown one", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const { app } = await boot({ config: configFor("required"), factorStore });
		const { agent, transaction } = await beginLogin(app);
		expect((await verify(agent, transaction, record.id, totpCode(secret))).status).toBe(200);

		const res = await readTransaction(agent, transaction);

		expect(res.status).toBe(400);
		expect(res.body).toEqual(UNKNOWN);
	});

	it("answers a transaction past its life as an unknown one", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await seedTotp(factorStore);
		const { app } = await boot({ config: configFor("required"), factorStore });
		const { agent, transaction } = await beginLogin(app);
		freezeClock(T0 + 600_000);

		const res = await readTransaction(agent, transaction);

		expect(res.status).toBe(400);
		expect(res.body).toEqual(UNKNOWN);
	});
});
