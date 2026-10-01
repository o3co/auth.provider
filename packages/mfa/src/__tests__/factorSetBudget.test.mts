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
 * The subject lease's call budget (`factorSet.mts`): the lease is sized from
 * the most Store calls one writer makes under it, and each writer's longest
 * path — counted here as it runs, every store and directory call between the
 * acquire and the release — stays within that budget, so a writer that grows
 * cannot outrun its lease unseen.
 */

import {
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type SubjectRevocationReport,
} from "@o3co/auth-provider-core";
import { createRecordingMailSender } from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createMfaSubjectLeases, FACTOR_SET_STORE_CALLS } from "#/factorSet.mjs";
import { createMfaReset } from "#/reset.mjs";
import {
	ALICE,
	boot,
	configFor,
	directoryEntries,
	disposeAll,
	WitnessingUserRepository,
} from "./moduleHarness.mjs";
import {
	beginEnrollment,
	beginLogin,
	completeEnrollment,
	freezeClock,
	giveEmailProof,
	recoverySet,
	seedFactor,
	thawClock,
	totpProofOf,
	verify,
} from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
	vi.restoreAllMocks();
});

/** The lease's own calls: what the budget leaves out, the acquire being counted apart. */
const LEASE_CALLS = new Set(["acquireSubjectLease", "releaseSubjectLease", "subjectGeneration"]);

/** An object's methods, as a spy takes them. */
type Methods = Record<string, (...args: unknown[]) => unknown>;

/** `object`'s method names, its own and its classes', up to `Object.prototype`. */
function methodNames(object: object): Set<string> {
	const names = new Set<string>();
	for (
		let level: object | null = object;
		level !== null && level !== Object.prototype;
		level = Object.getPrototypeOf(level)
	) {
		for (const name of Object.getOwnPropertyNames(level)) {
			if (name !== "constructor") names.add(name);
		}
	}
	return names;
}

/**
 * Counts every call `objects` take while a subject lease is held on
 * `leases`; answers the most one lease saw.
 */
function countUnderLease(leases: object, ...objects: object[]): { readonly most: () => number } {
	let held = false;
	let calls = 0;
	let most = 0;
	const lease = leases as Methods;
	const acquire = (lease.acquireSubjectLease as (...args: unknown[]) => unknown).bind(leases);
	vi.spyOn(lease, "acquireSubjectLease").mockImplementation(async (...args: unknown[]) => {
		const answer = (await acquire(...args)) as { readonly outcome: string };
		if (answer.outcome === "acquired") {
			held = true;
			calls = 0;
		}
		return answer;
	});
	const release = (lease.releaseSubjectLease as (...args: unknown[]) => unknown).bind(leases);
	vi.spyOn(lease, "releaseSubjectLease").mockImplementation(async (...args: unknown[]) => {
		most = Math.max(most, calls);
		held = false;
		return release(...args);
	});
	for (const object of objects) {
		const methods = object as Methods;
		for (const key of methodNames(object)) {
			const value = methods[key];
			if (typeof value !== "function" || LEASE_CALLS.has(key)) continue;
			const original = value.bind(object);
			vi.spyOn(methods, key).mockImplementation((...args: unknown[]) => {
				if (held) calls += 1;
				return original(...args);
			});
		}
	}
	return { most: () => most };
}

const COMPLETE: SubjectRevocationReport = {
	sessionsRevoked: [],
	sessionsFailed: [],
	tokensRevoked: true,
	grantsRequested: false,
	grantsRevoked: [],
	grantsFailed: [],
	grantsRetired: [],
	grantsRetireFailed: [],
	unavailable: [],
	failures: [],
	complete: true,
	federationGrants: { requested: "revoke", applied: "revoke" },
};

describe("the subject lease's call budget", () => {
	it.each([1, 2])(
		"covers the longest binding: a first binding by the account-email proof, reopened after a recovery code, over %i standing set(s)",
		async (sets) => {
			const factorStore = createMemoryMfaFactorStore();
			const transactionStore = createMemoryMfaTransactionStore();
			const set = recoverySet(3);
			const record = await seedFactor(factorStore, "recovery_code", set.data);
			for (let more = 1; more < sets; more++) {
				await seedFactor(factorStore, "recovery_code", recoverySet(3).data);
			}
			const users = new WitnessingUserRepository(directoryEntries());
			const sender = createRecordingMailSender();
			const { app } = await boot({
				config: configFor("required"),
				factorStore,
				transactionStore,
				userRepository: users,
				mailSender: sender,
			});
			const counted = countUnderLease(transactionStore, transactionStore, factorStore, users);
			const { agent, transaction } = await beginLogin(app);
			const reopened = await verify(agent, transaction, record.id, set.codes[0]);
			expect(reopened.status, JSON.stringify(reopened.body)).toBe(403);
			const binding = reopened.body.transaction as string;
			expect((await giveEmailProof(agent, binding, sender)).status).toBe(200);
			const begun = await beginEnrollment(agent, binding, "totp");

			const done = await completeEnrollment(agent, binding, totpProofOf(begun.body.secret));

			expect(done.status, JSON.stringify(done.body)).toBe(200);
			expect((await factorStore.list(ALICE.id)).map((one) => one.binding).sort()).toEqual([
				"email_proof",
				"email_proof",
			]);
			expect(counted.most()).toBeGreaterThanOrEqual(8 + sets);
			expect(counted.most()).toBeLessThanOrEqual(FACTOR_SET_STORE_CALLS);
		},
	);

	it("covers the operator reset with D25's flag", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const transactionStore = createMemoryMfaTransactionStore();
		await seedFactor(factorStore, "recovery_code", recoverySet(3).data);
		const users = new WitnessingUserRepository(directoryEntries());
		const counted = countUnderLease(transactionStore, transactionStore, factorStore, users);
		const reset = createMfaReset({
			factorStore,
			transactionStore,
			subjectRevocationService: { revokeAllForSubject: async () => COMPLETE },
			userRepository: users,
			mailWired: true,
			leases: createMfaSubjectLeases({ store: transactionStore, storeTimeoutMs: 1_000 }),
		});

		expect((await reset.resetMfaForSubject(ALICE.id, { requireEmailProof: true })).complete).toBe(
			true,
		);

		expect(counted.most()).toBeGreaterThanOrEqual(7);
		expect(counted.most()).toBeLessThanOrEqual(FACTOR_SET_STORE_CALLS);
	});
});
