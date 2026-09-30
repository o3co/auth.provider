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
 * The enrollment witness's writes at a login's verification (the MFA ADR's
 * D12): a verified counting factor marks a subject whose login's `User` does
 * not say it is enrolled, so a mark that failed heals at the next login; a
 * mark that fails is one warning and the login completes; and a directory
 * that cannot write the witness is said once at boot.
 */

import { createMemoryMfaFactorStore, InMemoryUserRepository } from "@o3co/auth-provider-core";
import { createTestMfaFactor } from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	ALICE,
	boot,
	configFor,
	directoryEntries,
	disposeAll,
	events,
	WitnessingUserRepository,
} from "./moduleHarness.mjs";
import {
	beginLogin,
	contributing,
	freezeClock,
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

/** The directory, alice's entry carrying `mfaEnrolled` when given. */
function directory(mfaEnrolled?: unknown): WitnessingUserRepository {
	const entries = directoryEntries();
	const alice = entries.get(ALICE.username);
	if (alice !== undefined && mfaEnrolled !== undefined) alice.mfaEnrolled = mfaEnrolled;
	return new WitnessingUserRepository(entries);
}

describe("a verified counting factor at a login", () => {
	it("marks the witness of a subject whose login's User does not say it is enrolled, and the login completes", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const userRepository = directory();
		const { app, logger } = await boot({
			config: configFor("required"),
			factorStore,
			userRepository,
		});
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, record.id, totpCode(secret));

		expect(res.status).toBe(200);
		expect(userRepository.marks).toEqual([{ subject: ALICE.id, enrolled: true }]);
		expect(events(logger, "warn")).not.toContain("mfa_enrollment_witness_unwritten");
	});

	it("marks nothing when the login's User says it is enrolled", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const userRepository = directory(true);
		const { app } = await boot({ config: configFor("required"), factorStore, userRepository });
		const { agent, transaction } = await beginLogin(app);

		expect((await verify(agent, transaction, record.id, totpCode(secret))).status).toBe(200);
		expect(userRepository.marks).toEqual([]);
	});

	it("heals a mark that failed at the next login: the first is one warning and the login completes, the second writes it", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const userRepository = directory();
		userRepository.failWith(new Error("Store unreachable"));
		const { app, logger } = await boot({
			config: configFor("required"),
			factorStore,
			userRepository,
		});

		const first = await beginLogin(app);
		expect((await verify(first.agent, first.transaction, record.id, totpCode(secret))).status).toBe(
			200,
		);
		expect(events(logger, "warn").filter((event) => event.startsWith("mfa_enrollment_"))).toEqual([
			"mfa_enrollment_witness_unwritten",
		]);
		const line = logger.warn.mock.calls.find(
			(call) => call[1] === "mfa_enrollment_witness_unwritten",
		)?.[0];
		expect(line).toMatchObject({ sub: ALICE.id, err: { name: "Error" } });
		expect(userRepository.marks).toEqual([]);

		userRepository.recover();
		freezeClock(Date.now() + 60_000);
		const second = await beginLogin(app);
		expect(
			(await verify(second.agent, second.transaction, record.id, totpCode(secret))).status,
		).toBe(200);
		expect(userRepository.marks).toEqual([{ subject: ALICE.id, enrolled: true }]);
	});
});

describe("a verified factor that does not count", () => {
	it("marks nothing: the witness says a counting factor was bound", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const record = await seedFactor(factorStore, "test", { secret: "s3cret" });
		const userRepository = directory();
		const { app } = await boot({
			config: configFor("optional"),
			factorStore,
			userRepository,
			extraModules: [contributing(createTestMfaFactor({ kind: "test", counting: false }))],
		});
		const { agent, transaction } = await beginLogin(app);

		expect((await verify(agent, transaction, record.id, "s3cret")).status).toBe(200);
		expect(userRepository.marks).toEqual([]);
	});
});

describe("a directory that cannot write the witness", () => {
	it("is said once at boot — mfa_enrollment_witness_unwritable — and a login's verification writes nothing and says nothing more", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const { app, logger } = await boot({
			config: configFor("required"),
			factorStore,
			userRepository: new InMemoryUserRepository(directoryEntries()),
		});
		expect(events(logger, "warn").filter((event) => event.startsWith("mfa_enrollment_"))).toEqual([
			"mfa_enrollment_witness_unwritable",
		]);
		expect(
			logger.warn.mock.calls.find((call) => call[1] === "mfa_enrollment_witness_unwritable")?.[0],
		).toEqual({ slot: "userRepository" });

		const { agent, transaction } = await beginLogin(app);
		expect((await verify(agent, transaction, record.id, totpCode(secret))).status).toBe(200);
		expect(events(logger, "warn").filter((event) => event.startsWith("mfa_enrollment_"))).toEqual([
			"mfa_enrollment_witness_unwritable",
		]);
	});

	it("is not said for a directory that writes it", async () => {
		const { logger } = await boot({ config: configFor("required"), userRepository: directory() });
		expect(events(logger, "warn")).not.toContain("mfa_enrollment_witness_unwritable");
	});
});
