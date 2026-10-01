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
 * A recovery code at a login (the MFA ADR's D21, D25), through the composed
 * application: it passes while the subject's guessable factors are held,
 * ends the consecutive run and refunds nothing of the week; the code is
 * spent, the answer says how many are left, and `mfa.recovery_code.used`
 * records it; no code reaches a log or an audit event.
 */

import {
	createMemoryMfaFactorStore,
	type MfaFactorStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readLongCode } from "#/codes.mjs";
import { createRecoveryCodeFactor, generateRecoveryCodes } from "#/recovery/factor.mjs";
import { boot, configFor, disposeAll } from "./moduleHarness.mjs";
import {
	beginLogin,
	freezeClock,
	loggedText,
	recordingAuditSink,
	type SeededTotp,
	seedFactor,
	seedTotp,
	storedData,
	suiteSealing,
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

/** A recovery-code set of `count` codes for alice, digested under the suite's ring and seeded: its record and its codes as shown. */
async function seedRecoveryCodes(factorStore: MfaFactorStore, count = 3) {
	const set = generateRecoveryCodes(
		createRecoveryCodeFactor({ count }),
		suiteSealing().digestsFor("recovery_code"),
	);
	if (set === undefined) throw new Error("no set");
	const record = await seedFactor(factorStore, "recovery_code", set.data);
	return { record, codes: set.codes };
}

/** Boots `mode` with `lockout`, an audit sink, and alice holding TOTP (unless `withoutTotp`) and a set of codes. */
async function withCodes(
	options: {
		readonly mode?: "optional" | "required";
		readonly lockout?: Record<string, number>;
		readonly count?: number;
		readonly withoutTotp?: boolean;
	} = {},
) {
	const factorStore = createMemoryMfaFactorStore();
	const totp: SeededTotp | undefined = options.withoutTotp
		? undefined
		: await seedTotp(factorStore);
	const set = await seedRecoveryCodes(factorStore, options.count);
	const audit = recordingAuditSink();
	const booted = await boot({
		config: configFor(options.mode ?? "required", { lockout: options.lockout ?? {} }),
		factorStore,
		auditSink: audit,
	});
	return { ...booted, factorStore, totp, set, audit };
}

/** The TOTP factor alice was seeded with. */
const totpOf = (seeded: SeededTotp | undefined): SeededTotp => {
	if (seeded === undefined) throw new Error("no TOTP factor seeded");
	return seeded;
};

describe("a recovery code while TOTP is held", () => {
	it("logs in during a weekly hold, and the next TOTP login is still held weekly", async () => {
		const { app, totp: seeded, set } = await withCodes({ lockout: { weeklyBudget: 2 } });
		const totp = totpOf(seeded);
		const { agent, transaction } = await beginLogin(app);
		for (let n = 0; n < 2; n++) {
			await verify(agent, transaction, totp.record.id, wrongCode(totp.secret));
		}
		const held = await verify(agent, transaction, totp.record.id, totpCode(totp.secret));
		expect(held.status).toBe(429);
		expect(held.body).toMatchObject({ hold: "weekly", usable_kinds: ["recovery_code"] });

		const res = await verify(agent, transaction, set.record.id, set.codes[0]);
		expect(res.status, JSON.stringify(res.body)).toBe(200);

		const next = await beginLogin(app);
		const after = await verify(next.agent, next.transaction, totp.record.id, totpCode(totp.secret));
		expect(after.status).toBe(429);
		expect(after.body).toMatchObject({ hold: "weekly" });
	});

	it("logs in during the hard hold, and lifts it", async () => {
		const {
			app,
			totp: seeded,
			set,
		} = await withCodes({
			lockout: { threshold: 2, hardLimit: 2 },
		});
		const totp = totpOf(seeded);
		const { agent, transaction } = await beginLogin(app);
		for (let n = 0; n < 2; n++) {
			await verify(agent, transaction, totp.record.id, wrongCode(totp.secret));
		}
		expect(
			(await verify(agent, transaction, totp.record.id, totpCode(totp.secret))).body,
		).toMatchObject({ hold: "hard" });

		const res = await verify(agent, transaction, set.record.id, set.codes[0]);
		expect(res.status, JSON.stringify(res.body)).toBe(200);

		const next = await beginLogin(app);
		const after = await verify(next.agent, next.transaction, totp.record.id, totpCode(totp.secret));
		expect(after.status, JSON.stringify(after.body)).toBe(200);
	});
});

describe("a recovery code at a login", () => {
	it("completes the login, answering how many codes are left, and records mfa.recovery_code.used beside mfa.verified", async () => {
		const { app, set, audit, userSessionStore } = await withCodes();
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, set.record.id, set.codes[1]);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body).toEqual({ message: "Logged in successfully", recovery_codes_remaining: 2 });
		expect(create).toHaveBeenCalledTimes(1);
		expect(audit.of("mfa.verified").map((event) => event.details)).toEqual([
			{ kind: "recovery_code", purpose: "login" },
		]);
		expect(audit.of("mfa.recovery_code.used")).toEqual([
			expect.objectContaining({
				subject: "u-alice",
				details: { kind: "recovery_code", purpose: "login", remaining: 2 },
			}),
		]);
	});

	it("completes under optional for a subject holding recovery codes alone", async () => {
		const { app, set } = await withCodes({ mode: "optional", withoutTotp: true });
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, set.record.id, set.codes[0]);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body.recovery_codes_remaining).toBe(2);
	});

	it("spends the code: it is refused at the next login, and the set keeps the others", async () => {
		const { app, set, factorStore } = await withCodes();
		const first = await beginLogin(app);
		expect((await verify(first.agent, first.transaction, set.record.id, set.codes[0])).status).toBe(
			200,
		);

		const next = await beginLogin(app);
		const res = await verify(next.agent, next.transaction, set.record.id, set.codes[0]);

		expect(res.status).toBe(401);
		expect(res.body).toMatchObject({ error: "mfa_invalid", attempts_remaining: 4 });
		const stored = await storedData(factorStore, set.record);
		expect(stored.record.version).toBe(1);
		expect(stored.data.codes).toHaveLength(2);
	});

	it("keeps the set once its last code is spent, answering none left and refusing every code after", async () => {
		const { app, set, audit, factorStore } = await withCodes({ count: 1 });
		const first = await beginLogin(app);

		const res = await verify(first.agent, first.transaction, set.record.id, set.codes[0]);

		expect(res.status).toBe(200);
		expect(res.body.recovery_codes_remaining).toBe(0);
		expect(audit.of("mfa.recovery_code.used")[0]?.details).toMatchObject({ remaining: 0 });
		expect((await storedData(factorStore, set.record)).data).toEqual({ codes: [] });
		const next = await beginLogin(app);
		expect((await verify(next.agent, next.transaction, set.record.id, set.codes[0])).status).toBe(
			401,
		);
	});

	it("puts no code in any log line or audit event, used or refused", async () => {
		const { app, set, audit, logger } = await withCodes();
		const { agent, transaction } = await beginLogin(app);
		const wrong = "ZZZZ-ZZZZ-ZZZZ-ZZZZ";
		await verify(agent, transaction, set.record.id, wrong);
		await verify(agent, transaction, set.record.id, set.codes[0]);

		const logged = loggedText(logger);
		const audited = JSON.stringify(audit.events);
		for (const code of [...set.codes, wrong]) {
			for (const spelling of [code, readLongCode(code) as string]) {
				expect(logged).not.toContain(spelling);
				expect(audited).not.toContain(spelling);
			}
		}
	});
});
