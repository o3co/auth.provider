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

import type { MfaTransactionStore } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";

/**
 * The `MfaTransactionStore` contract for the consume of the operator reset's
 * email-proof requirement (the MFA ADR's D25), for every adapter: consumed
 * only under the subject's lease held by the token given, the lease checked
 * and the requirement cleared in one atomic step. A consume under a lease
 * that ended — one that lands after a later reset set the requirement
 * again — clears nothing.
 *
 * A lease lapses on the store's own clock, read through
 * {@link MfaEmailProofRequirementExpiryClock}.
 */
export type MfaEmailProofRequirementContractFactory = () => Promise<MfaTransactionStore>;

/** How a test reaches a lease's end on the store's own terms. */
export interface MfaEmailProofRequirementExpiryClock {
	/** Epoch milliseconds on the clock the store ends a lease by. */
	now(): Promise<number>;
	/** Resolves once the store has let everything ending at `at` go. */
	passed(at: number): Promise<void>;
}

const hostExpiry: MfaEmailProofRequirementExpiryClock = {
	now: async () => Date.now(),
	passed: async (at) => {
		while (Date.now() <= at) {
			await new Promise((r) => setTimeout(r, at - Date.now() + 1));
		}
	},
};

export function runMfaEmailProofRequirementContract(
	factory: MfaEmailProofRequirementContractFactory,
	options: { readonly expiry?: MfaEmailProofRequirementExpiryClock } = {},
): void {
	const expiry = options.expiry ?? hostExpiry;

	let resets = 0;
	/**
	 * The operator reset of `subject` as it writes the requirement: under a
	 * lease of its own, the requirement set, the reset applied, and the
	 * requirement set again before the lease is released.
	 */
	async function resetRequiringEmailProof(
		store: MfaTransactionStore,
		subject: string,
	): Promise<void> {
		resets += 1;
		const lease = await store.acquireSubjectLease(subject, {
			ttlMs: 60_000,
			generation: await store.subjectGeneration(subject),
		});
		if (lease.outcome !== "acquired") throw new Error(`expected a lease: ${lease.outcome}`);
		await store.requireEmailProofAtNextBinding(subject);
		await store.authorizeSubjectRecovery(subject, {
			operation: "reset",
			sid: undefined,
			recoveryId: `reset-${resets}`,
			expiresAtMs: Date.now() + 10 * 60_000,
		});
		const answer = await store.applySubjectRecovery(subject, {
			operation: "reset",
			sid: undefined,
			nowMs: Date.now(),
			leaseToken: lease.token,
			sessionsBoundaryMs: undefined,
			guessableBoundSinceMs: undefined,
		});
		if (answer.outcome !== "applied") {
			throw new Error(`expected the reset applied: ${answer.outcome}`);
		}
		await store.requireEmailProofAtNextBinding(subject);
		await store.releaseSubjectLease(subject, lease.token);
	}

	describe("MfaTransactionStore contract: the email-proof requirement consumed under the subject's lease", () => {
		const consumed = { outcome: "consumed" };
		const absent = { outcome: "absent" };
		const refused = { outcome: "refused", reason: "lease_not_held" };

		/** The subject's lease, under the generation it is at. */
		async function leased(
			store: MfaTransactionStore,
			subject = "user-1",
			ttlMs = 60_000,
		): Promise<string> {
			const generation = await store.subjectGeneration(subject);
			const lease = await store.acquireSubjectLease(subject, { ttlMs, generation });
			if (lease.outcome !== "acquired") throw new Error(`expected a lease: ${lease.outcome}`);
			return lease.token;
		}

		it("consumes the requirement under the lease held, once, and answers absent when none stands", async () => {
			const store = await factory();
			await store.requireEmailProofAtNextBinding("user-1");
			const leaseToken = await leased(store);
			expect(await store.consumeEmailProofRequirement("user-1", { leaseToken })).toEqual(consumed);
			expect(await store.emailProofRequiredAtNextBinding("user-1")).toBe(false);
			expect(await store.consumeEmailProofRequirement("user-1", { leaseToken })).toEqual(absent);
		});

		it("is consumed once: of N consumes in flight under one lease one answers consumed", async () => {
			const store = await factory();
			await store.requireEmailProofAtNextBinding("user-1");
			await store.requireEmailProofAtNextBinding("user-2");
			const leaseToken = await leased(store);
			const answers = await Promise.all(
				Array.from({ length: 10 }, () =>
					store.consumeEmailProofRequirement("user-1", { leaseToken }),
				),
			);
			const outcomes = answers.map((a) => (typeof a === "object" ? a.outcome : a));
			expect(outcomes.filter((o) => o === "consumed")).toHaveLength(1);
			expect(outcomes.filter((o) => o === "absent")).toHaveLength(9);
			expect(await store.emailProofRequiredAtNextBinding("user-1")).toBe(false);
			expect(await store.emailProofRequiredAtNextBinding("user-2")).toBe(true);
		});

		it("leaves the requirement a later reset set when a consume under the earlier lease lands after it", async () => {
			const store = await factory();
			await store.requireEmailProofAtNextBinding("user-1");
			const binding = await leased(store);
			expect(await store.releaseSubjectLease("user-1", binding)).toBe(true);
			await resetRequiringEmailProof(store, "user-1");
			expect(await store.consumeEmailProofRequirement("user-1", { leaseToken: binding })).toEqual(
				refused,
			);
			expect(await store.emailProofRequiredAtNextBinding("user-1")).toBe(true);
		});

		it("refuses a consume under a lease that lapsed on the store's clock, clearing nothing", async () => {
			const store = await factory();
			await store.requireEmailProofAtNextBinding("user-1");
			const leaseToken = await leased(store, "user-1", 1_000);
			const after = await expiry.now();
			await expiry.passed(after + 1_000);
			expect(await store.consumeEmailProofRequirement("user-1", { leaseToken })).toEqual(refused);
			expect(await store.emailProofRequiredAtNextBinding("user-1")).toBe(true);
		});

		it("refuses a consume without the subject's lease, clearing nothing: none, another holder's token, or another subject's", async () => {
			const store = await factory();
			await store.requireEmailProofAtNextBinding("user-1");
			expect(
				await store.consumeEmailProofRequirement("user-1", { leaseToken: "no-such-lease" }),
			).toEqual(refused);
			const other = await leased(store, "user-2");
			expect(await store.consumeEmailProofRequirement("user-1", { leaseToken: other })).toEqual(
				refused,
			);
			const held = await leased(store);
			expect(
				await store.consumeEmailProofRequirement("user-1", { leaseToken: `${held}x` }),
			).toEqual(refused);
			expect(await store.emailProofRequiredAtNextBinding("user-1")).toBe(true);
			expect(await store.consumeEmailProofRequirement("user-1", { leaseToken: held })).toEqual(
				consumed,
			);
		});

		it("refuses without the lease even when nothing required the proof", async () => {
			const store = await factory();
			expect(
				await store.consumeEmailProofRequirement("user-1", { leaseToken: "no-such-lease" }),
			).toEqual(refused);
		});

		it("refuses, with a RangeError, a consume it cannot make, and clears nothing", async () => {
			const store = await factory();
			await store.requireEmailProofAtNextBinding("user-1");
			const leaseToken = await leased(store);
			for (const [label, subject, consume] of [
				["an empty subject", "", { leaseToken }],
				["a subject that is not a string", 7, { leaseToken }],
				["a consume that is not an object", "user-1", "token"],
				["an empty lease token", "user-1", { leaseToken: "" }],
				["a lease token that is not a string", "user-1", { leaseToken: 7 }],
			] as const) {
				await expect(
					store.consumeEmailProofRequirement(subject as never, consume as never),
					label,
				).rejects.toThrow(RangeError);
			}
			expect(await store.emailProofRequiredAtNextBinding("user-1")).toBe(true);
		});
	});
}
