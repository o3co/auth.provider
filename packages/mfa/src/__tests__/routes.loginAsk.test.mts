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
 * Whether a password login asks for a second factor, through the composed
 * application: every record serves but a recovery set whose data opened and
 * holds no code (`factorState.mts`). A TOTP factor whose key left the ring
 * still asks under `optional`, and its verification is the outage it was;
 * a subject holding only an exhausted set is sent under `required` to its
 * first binding, through the one first-binding gate.
 */

import { createMemoryMfaFactorStore } from "@o3co/auth-provider-core";
import { createRecordingMailSender } from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { boot, configFor, disposeAll, login } from "./moduleHarness.mjs";
import {
	beginEnrollment,
	freezeClock,
	recoverySet,
	seedFactor,
	seedTotp,
	thawClock,
	totpCode,
	verify,
} from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
});

describe("a login over records the provider cannot read, or a set with no code left", () => {
	it("asks for a second factor under optional when the only factor is a TOTP whose key left the ring, establishing nothing, and its verification is 503", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const { app } = await boot({
			config: configFor("optional", {
				encryptionKeys: [{ key: Buffer.alloc(32, 7).toString("base64") }],
			}),
			factorStore,
		});

		const { agent, res } = await login(app);

		expect(res.status, JSON.stringify(res.body)).toBe(403);
		expect(res.body.error).toBe("mfa_required");
		const verified = await verify(
			agent,
			res.body.transaction as string,
			record.id,
			totpCode(secret),
		);
		expect(verified.status).toBe(503);
	});

	it("sends a subject holding only a set with no code left to its first binding under required, through the gate: the account-email proof asked before anything binds", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await seedFactor(factorStore, "recovery_code", recoverySet(0).data);
		const { app } = await boot({
			config: configFor("required"),
			factorStore,
			mailSender: createRecordingMailSender(),
		});

		const { agent, res } = await login(app);

		expect(res.status, JSON.stringify(res.body)).toBe(403);
		expect(res.body).toMatchObject({
			error: "mfa_enrollment_required",
			hints: { enrollable: ["totp"], email_proof: true },
		});
		const begun = await beginEnrollment(agent, res.body.transaction as string, "totp");
		expect(begun.status, JSON.stringify(begun.body)).toBe(403);
		expect(begun.body.error).toBe("mfa_email_proof_required");
	});
});
