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
import type { GrantPolicyHook } from "../../policy/types.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { BootError } from "../types.mjs";

const noopGrantPolicy: GrantPolicyHook = {
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

	// #266 made `oauth.jwt.issuer` required at the schema boundary, so config
	// validation (step 1) now rejects a missing or malformed issuer before the
	// CP-20 scan (step 13.5) can run. CP-20 remains as a backstop for a config
	// object that reaches the DI graph without passing the schema; what these
	// tests pin is that boot fails, not which of the two gates catches it.
	it("rejects grantPolicy module when config.oauth.jwt.issuer is missing", async () => {
		await expect(
			createApp({
				modules: [grantPolicyModule],
				bootstrapComponents: {
					config: configWithIssuer(undefined),
					pathResolver: (p: string) => p,
				} as never,
			}),
		).rejects.toSatisfy(
			(err: unknown) => err instanceof BootError && err.reason === "config-validation-failed",
		);
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
			(err: unknown) => err instanceof BootError && err.reason === "config-validation-failed",
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

	it("requires an issuer even when no module provides grantPolicy", async () => {
		// Before #266 the issuer was optional unless grantPolicy was wired. It is
		// now the identity every minted token is bound to, so it is unconditional.
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: {
					config: configWithIssuer(undefined),
					pathResolver: (p: string) => p,
				} as never,
			}),
		).rejects.toSatisfy(
			(err: unknown) => err instanceof BootError && err.reason === "config-validation-failed",
		);
	});

	// CP-20 must also fire when grantPolicy is wired via bootstrapComponents
	// or overrideComponents — those are the other two supported paths into
	// the typed DI graph (per A2-α §6.1 + A2-β §5.1 step 8). A module-only
	// scan would let an empty-issuer misconfig slip through whenever the
	// host pre-seeds grantPolicy directly. Multi-reviewer convergence in
	// Round 2: Claude (Important) + Codex (P2).
	it("rejects bootstrapComponents.grantPolicy when issuer is missing", async () => {
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: {
					config: configWithIssuer(undefined),
					pathResolver: (p: string) => p,
					grantPolicy: noopGrantPolicy,
				} as never,
			}),
		).rejects.toSatisfy(
			(err: unknown) => err instanceof BootError && err.reason === "config-validation-failed",
		);
	});

	it("rejects overrideComponents.grantPolicy when issuer is empty", async () => {
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: {
					config: configWithIssuer(""),
					pathResolver: (p: string) => p,
				} as never,
				overrideComponents: {
					grantPolicy: noopGrantPolicy,
				} as never,
			}),
		).rejects.toSatisfy(
			(err: unknown) => err instanceof BootError && err.reason === "config-validation-failed",
		);
	});

	it("accepts bootstrapComponents.grantPolicy when issuer is set", async () => {
		const handle = await createApp({
			modules: [],
			bootstrapComponents: {
				config: configWithIssuer("https://auth.example"),
				pathResolver: (p: string) => p,
				grantPolicy: noopGrantPolicy,
			} as never,
		});
		expect(handle).toBeDefined();
		await handle.dispose();
	});
});
