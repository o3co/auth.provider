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
 * The `mfaFactors` contribution kind and its read side, `mfaFactorResolver`,
 * booted through `createApp` (the ADR's D3 and D7).
 *
 * A factor reaches the coordinator from a package the MFA package does not
 * depend on, as a contribution keyed by kind. A factory may answer `null` —
 * the factor switched off by its configuration — and the kind is then
 * absent from the resolver, as a switched-off token-binding mechanism is
 * absent from the composed middleware. The resolver is a synthetic key: the
 * planner assembles it, and nothing else may supply it.
 */

import { describe, expect, it } from "vitest";
import { BootError } from "#/boot/types.mjs";
import { createApp, defineModule } from "#/index.mjs";
import type { MfaFactor } from "#/mfa/factor.mjs";
import type { MfaFactorResolver } from "#/modules/manifest/synthetic-keys.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

const bootstrapComponents = {
	config: makeValidCoreConfig(),
	pathResolver: (p: string) => p,
} as never;

const factor = (kind: string): MfaFactor => ({
	kind,
	addsMfa: true,
	counting: true,
	guessable: false,
	amrFor: () => [kind],
	describe: () => ({}),
	verify: async () => ({ ok: false, reason: "invalid" }),
	beginEnrollment: async () => ({ state: {}, response: {} }),
	completeEnrollment: async () => ({ ok: false, reason: "invalid" }),
});

/** Reads the resolver the way a coordinator module would: by requiring it. */
function reader(seen: { resolver?: MfaFactorResolver }) {
	return defineModule({
		name: "test:mfa-factor-reader",
		requires: ["mfaFactorResolver"] as const,
		provides: {
			"test.mfaFactorReader": (deps) => {
				seen.resolver = deps.mfaFactorResolver;
				return true;
			},
		} as never,
	});
}

describe("mfaFactorResolver (D3, D7)", () => {
	it("resolves every contributed factor by kind, and leaves a kind switched off by config absent", async () => {
		const totp = factor("totp");
		const webauthn = factor("webauthn");
		const contributing = defineModule({
			name: "test:mfa-factors",
			contributes: {
				mfaFactors: {
					totp: () => totp,
					// Switched off by its configuration, as a disabled token-binding
					// mechanism answers null.
					email: () => null,
				},
			},
		});
		const another = defineModule({
			name: "test:mfa-webauthn-factor",
			contributes: { mfaFactors: { webauthn: () => webauthn } },
		});
		const seen: { resolver?: MfaFactorResolver } = {};
		const handle = await createApp({
			modules: [contributing, another, reader(seen)],
			bootstrapComponents,
		});
		try {
			const resolver = seen.resolver;
			expect(resolver).toBeDefined();
			expect(resolver?.get("totp")).toBe(totp);
			expect(resolver?.get("webauthn")).toBe(webauthn);
			expect(resolver?.get("email")).toBeUndefined();
			expect(resolver?.get("recovery_code")).toBeUndefined();
			expect([...(resolver?.entries() ?? [])]).toEqual([
				["totp", totp],
				["webauthn", webauthn],
			]);
			expect(handle.components.mfaFactorResolver).toBe(resolver);
		} finally {
			await handle.dispose();
		}
	});

	it("refuses a second contribution of a kind even when the first answered null", async () => {
		// A kind switched off is still claimed: a second module contributing it
		// is a duplicate, not a replacement that happens to win.
		const off = defineModule({
			name: "test:mfa-totp-off",
			contributes: { mfaFactors: { totp: () => null } },
		});
		const on = defineModule({
			name: "test:mfa-totp-on",
			contributes: { mfaFactors: { totp: () => factor("totp") } },
		});
		await expect(createApp({ modules: [off, on], bootstrapComponents })).rejects.toSatisfy(
			(err: unknown) => err instanceof BootError && err.reason === "duplicate-contribute",
		);
	});

	it("is a synthetic key: a module providing it is refused", async () => {
		const providing = defineModule({
			name: "test:provides-mfa-factor-resolver",
			provides: {
				mfaFactorResolver: () => ({
					get: () => undefined,
					entries: () => new Map<string, MfaFactor>().entries(),
				}),
			},
		});
		await expect(createApp({ modules: [providing], bootstrapComponents })).rejects.toSatisfy(
			(err: unknown) => err instanceof BootError && err.reason === "synthetic-key-collision",
		);
	});

	it("is a synthetic key: a composition root supplying it is refused", async () => {
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: {
					...(bootstrapComponents as object),
					mfaFactorResolver: { get: () => undefined, entries: () => [].values() },
				} as never,
			}),
		).rejects.toSatisfy(
			(err: unknown) => err instanceof BootError && err.reason === "synthetic-key-collision",
		);
	});
});
