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
 * The `mfaCoordinator` slot and `MFA_ABSENCE_POLICY` (the MFA ADR's D8, D20).
 *
 * What `session` and `oauth` consult is declared in core and filled by the
 * MFA package, so neither imports an optional feature. "Off" is a
 * statement: a module that reads the slot attaches the policy, and an
 * unfilled slot then refuses boot unless `mfa.mode = "off"` is written. No
 * bundled module attaches it yet; these cases attach it in a test module and
 * boot it the way the declared-absence guard runs it.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import { createApp, defineModule } from "#/index.mjs";
import {
	MFA_ABSENCE_POLICY,
	type MfaCoordinator,
	type PrimaryAuthentication,
} from "#/mfa/coordinator.mjs";
import type { AbsencePolicy } from "#/modules/manifest/absence-policy.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

const consumer = defineModule({
	name: "test:mfa-consumer",
	optional: ["mfaCoordinator"] as const,
	absencePolicies: { mfaCoordinator: MFA_ABSENCE_POLICY },
	contributes: {
		routes: [
			{
				id: "test-mfa-consumer",
				mountPath: "/__test_mfa_consumer__",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			},
		],
	},
});

const coordinator: MfaCoordinator = {
	secondFactorMethods: new Set(["otp", "mfa"]),
	decideAfterPrimary: async () => "none",
	openLoginTransaction: async () => ({ id: "tx", expiresInSeconds: 600 }),
};

const boot = (config: Record<string, unknown>, modules = [consumer]) =>
	createApp({
		modules,
		bootstrapComponents: { config, pathResolver: (p: string) => p } as never,
	});

describe("MFA_ABSENCE_POLICY (D20)", () => {
	it('is declared by mfa.mode = "off", and says what is lost', () => {
		const policy: AbsencePolicy = MFA_ABSENCE_POLICY;
		expect(policy.configKey).toEqual(["mfa", "mode"]);
		expect(policy.absentValue).toBe("off");
		expect(policy.hint).toMatch(/second factor/);
	});

	it('boots a composition that reads the slot and leaves it empty on the schema\'s default mode, "off"', async () => {
		// Until the release that turns MFA on, `mfa.mode` defaults to "off" in
		// the schema createApp parses, so a hand-built configuration that never
		// wrote the key declares the absence. That release removes the default
		// (the ADR's O2), and an unwritten mode is then refused
		// (component-absence-undeclared); until a module honours another mode,
		// the schema refuses every value but "off" before this guard runs.
		const handle = await boot(makeValidCoreConfig());
		expect(handle.components.mfaCoordinator).toBeUndefined();
		await handle.dispose();
	});

	it('boots it once mfa.mode = "off" is written', async () => {
		const handle = await boot({ ...makeValidCoreConfig(), mfa: { mode: "off" } });
		expect(handle.components.mfaCoordinator).toBeUndefined();
		await handle.dispose();
	});

	it("boots it when a coordinator fills the slot", async () => {
		const provider = defineModule({
			name: "test:mfa-coordinator",
			provides: { mfaCoordinator: () => coordinator },
		});
		const handle = await boot(makeValidCoreConfig(), [provider, consumer]);
		expect(handle.components.mfaCoordinator).toBe(coordinator);
		await handle.dispose();
	});
});

describe("the mfaCoordinator slot (D8)", () => {
	it("is optional, and holds an MfaCoordinator", () => {
		expectTypeOf<ComponentMap["mfaCoordinator"]>().toEqualTypeOf<MfaCoordinator | undefined>();
		expect(true).toBe(true);
	});

	it("decides after the primary, then binds a transaction to the regenerated session", () => {
		// Two calls, because the express session is regenerated between them:
		// the factor read happens before anything is written, and the
		// transaction is bound to the id the browser will hold.
		expectTypeOf<ReturnType<MfaCoordinator["decideAfterPrimary"]>>().toEqualTypeOf<
			Promise<"none" | "challenge" | "enroll">
		>();
		expectTypeOf<Parameters<MfaCoordinator["openLoginTransaction"]>>().toEqualTypeOf<
			[PrimaryAuthentication, "challenge" | "enroll", string]
		>();
		expectTypeOf<PrimaryAuthentication>().toEqualTypeOf<{
			readonly subject: string;
			readonly method: string;
			readonly amr: readonly string[];
			readonly authTime: Date;
			readonly user: Readonly<Record<string, unknown>>;
			readonly redirectTo: string | undefined;
			readonly request: { readonly ip?: string; readonly userAgent?: string };
		}>();
		expect(true).toBe(true);
	});
});
