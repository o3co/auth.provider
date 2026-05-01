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
 * Integration tests for the mfa-partial-wiring boot validator (issue #101).
 *
 * Rule: when mfaCoordinator is provided by any module, both mfaProviderFactory
 * AND mfaTransactionStore MUST also be provided. The validator fires in the
 * validate-manifests stage so misconfiguration surfaces at boot time rather
 * than crashing on the first MFA flow.
 *
 * mfaCoordinator / mfaProviderFactory / mfaTransactionStore are not declared
 * in the core ComponentMap (they live in a future/external package). Tests
 * cast `provides` objects to `never` to exercise the runtime path without
 * adding cross-package dependencies into core — the same pattern used by
 * federation-pairing.test.mts for federationRedirectPolicies.
 *
 * Per issue #101, A2-β §6.1 amendment 2026-05.
 */
import { describe, expect, it } from "vitest";
import { createApp, defineModule } from "../../index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { BootError } from "../types.mjs";

const minBoot = {
	config: makeValidCoreConfig(),
	pathResolver: (p: string) => p,
} as never;

describe("checkMfaPartialWiring", () => {
	it("throws when mfaCoordinator is provided but mfaProviderFactory is missing", async () => {
		const coordinatorOnly = defineModule({
			name: "test:mfa-coordinator-only",
			provides: { mfaCoordinator: () => ({ kind: "stub" }) } as never,
		});
		await expect(
			createApp({
				modules: [coordinatorOnly],
				bootstrapComponents: minBoot,
			}),
		).rejects.toThrow(BootError);
		await expect(
			createApp({
				modules: [coordinatorOnly],
				bootstrapComponents: minBoot,
			}),
		).rejects.toMatchObject({ details: { reason: "mfa-partial-wiring" } });
	});

	it("does not throw when mfaCoordinator is absent", async () => {
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: minBoot,
			}),
		).resolves.toBeDefined();
	});

	it("does not throw when all three MFA slots are wired", async () => {
		const allThree = defineModule({
			name: "test:mfa-complete",
			provides: {
				mfaCoordinator: () => ({ kind: "stub" }),
				mfaProviderFactory: () => ({ kind: "stub" }),
				mfaTransactionStore: () => ({ kind: "stub" }),
			} as never,
		});
		await expect(
			createApp({
				modules: [allThree],
				bootstrapComponents: minBoot,
			}),
		).resolves.toBeDefined();
	});

	// Multi-channel coverage (multi-agent-review I1+P2 fix): the validator
	// must consult `bootstrapComponents` and `overrideComponents` in addition
	// to module `provides`. Without this, composition roots that wire MFA
	// dependencies via bootstrap/override are falsely rejected.

	it("does not throw when MFA slots are supplied via bootstrapComponents", async () => {
		const bootstrapWithMfa = {
			...(minBoot as Record<string, unknown>),
			mfaCoordinator: { kind: "stub" },
			mfaProviderFactory: { kind: "stub" },
			mfaTransactionStore: { kind: "stub" },
		} as never;
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: bootstrapWithMfa,
			}),
		).resolves.toBeDefined();
	});

	it("does not throw when mfaCoordinator from a module is paired with companions from bootstrapComponents", async () => {
		const coordinatorOnly = defineModule({
			name: "test:mfa-coordinator-only",
			provides: { mfaCoordinator: () => ({ kind: "stub" }) } as never,
		});
		const bootstrapWithCompanions = {
			...(minBoot as Record<string, unknown>),
			mfaProviderFactory: { kind: "stub" },
			mfaTransactionStore: { kind: "stub" },
		} as never;
		await expect(
			createApp({
				modules: [coordinatorOnly],
				bootstrapComponents: bootstrapWithCompanions,
			}),
		).resolves.toBeDefined();
	});

	it("does not throw when MFA slots come via overrideComponents", async () => {
		const coordinatorOnly = defineModule({
			name: "test:mfa-coordinator-only-override",
			provides: { mfaCoordinator: () => ({ kind: "stub" }) } as never,
		});
		await expect(
			createApp({
				modules: [coordinatorOnly],
				bootstrapComponents: minBoot,
				overrideComponents: {
					mfaProviderFactory: { kind: "stub" },
					mfaTransactionStore: { kind: "stub" },
				} as never,
			}),
		).resolves.toBeDefined();
	});
});
