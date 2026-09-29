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
 * Integration tests for the composition-root grantPolicy / `oauth.jwt.issuer`
 * invariant: boot fails on a missing or empty issuer, however grantPolicy is
 * wired.
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
// grantPolicy / jwt.issuer invariant
// ---------------------------------------------------------------------------

describe("grantPolicy/issuer invariant", () => {
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

	// `oauth.jwt.issuer` is required at the schema boundary, so config
	// validation rejects a missing or malformed issuer before the grantPolicy
	// scan runs. The scan stays as a backstop for a config object that reaches
	// the DI graph without passing the schema; these tests pin that boot
	// fails, not which of the two gates catches it.
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
		// The issuer is the identity every minted token is bound to, so it is
		// required whether or not grantPolicy is wired.
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

	// The check must also fire when grantPolicy is wired via
	// bootstrapComponents or overrideComponents, the other two paths into the
	// typed DI graph: a module-only scan would let an empty issuer through
	// whenever the host pre-seeds grantPolicy directly.
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
