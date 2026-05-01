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
 * Integration tests for the composition-root invariants restored in Phase 9
 * boot-validator restoration (review fix #7).
 *
 * Restored:
 *   - Step 13.5: CP-20 grantPolicy / jwt.issuer invariant.
 *
 * Dropped during Phase 9 (does not apply to v0.5.0):
 *   - v0.4.x A4 four-store invariant. v0.5.0's package-level segregation
 *     splits the four user-session slots between sessionModule (consumes 2)
 *     and oauthModule (consumes 2); a blanket "all-or-none" check mis-fires
 *     on legitimate test fixtures and partial-subsystem composition roots.
 *     Step 4 (checkRequiresClosure) already enforces per-module wiring.
 *
 * Other v0.4.x guards (MFA partial-wiring, TODO-F-1 federation+stores) are
 * tracked as a follow-up in CHANGELOG; they require new BootErrorReason
 * literals and are out of scope for the publish-gate fix-up commit.
 */

import { describe, expect, it } from "vitest";
import { createApp, defineModule } from "../../index.mjs";
import type { GrantPolicyHookBase } from "../../policy/types.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { BootError } from "../types.mjs";

const noopGrantPolicy: GrantPolicyHookBase = {
	kind: "noop",
	async evaluate() {
		return { outcome: "allow" };
	},
};

// ---------------------------------------------------------------------------
// Step 13.5 — CP-20 grantPolicy / jwt.issuer invariant
// ---------------------------------------------------------------------------

describe("CP-20 grantPolicy/issuer invariant — step 13.5", () => {
	function configWithIssuer(issuer: string | undefined): ReturnType<typeof makeValidCoreConfig> {
		const base = makeValidCoreConfig();
		const oauth = base.oauth as Record<string, unknown>;
		const jwt = oauth.jwt as Record<string, unknown>;
		const newJwt: Record<string, unknown> = { ...jwt };
		if (issuer === undefined) {
			delete newJwt.issuer;
		} else {
			newJwt.issuer = issuer;
		}
		return {
			...base,
			oauth: { ...oauth, jwt: newJwt },
		} as ReturnType<typeof makeValidCoreConfig>;
	}

	const grantPolicyModule = defineModule({
		name: "test-grant-policy-provider",
		provides: {
			grantPolicy: () => noopGrantPolicy,
		},
	});

	it("rejects grantPolicy module when config.oauth.jwt.issuer is missing", async () => {
		await expect(
			createApp({
				modules: [grantPolicyModule],
				bootstrapComponents: {
					config: configWithIssuer(undefined),
					pathResolver: (p: string) => p,
				} as never,
			}),
		).rejects.toSatisfy((err: unknown) => {
			if (!(err instanceof BootError)) return false;
			if (err.reason !== "grant-policy-without-issuer") return false;
			const d = err.details as { providedBy?: string };
			return d.providedBy === "test-grant-policy-provider";
		});
	});

	it("rejects grantPolicy module when issuer is an empty string", async () => {
		await expect(
			createApp({
				modules: [grantPolicyModule],
				bootstrapComponents: {
					config: configWithIssuer(""),
					pathResolver: (p: string) => p,
				} as never,
			}),
		).rejects.toSatisfy(
			(err: unknown) => err instanceof BootError && err.reason === "grant-policy-without-issuer",
		);
	});

	it("accepts grantPolicy module when issuer is a non-empty string", async () => {
		const handle = await createApp({
			modules: [grantPolicyModule],
			bootstrapComponents: {
				config: configWithIssuer("https://auth.example"),
				pathResolver: (p: string) => p,
			} as never,
		});
		expect(handle).toBeDefined();
		await handle.dispose();
	});

	it("does NOT require issuer when no module provides grantPolicy", async () => {
		const handle = await createApp({
			modules: [],
			bootstrapComponents: {
				config: configWithIssuer(undefined),
				pathResolver: (p: string) => p,
			} as never,
		});
		expect(handle).toBeDefined();
		await handle.dispose();
	});
});
