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

import { inspect } from "node:util";
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

/**
 * Reads the resolver by requiring it, from a contribution factory. A
 * `provides` factory may require it too (the case below): the projection is
 * in place before stage 3 and fills in stage 4.
 */
function reader(seen: { resolver?: MfaFactorResolver }) {
	return defineModule({
		name: "test:mfa-factor-reader",
		requires: ["mfaFactorResolver"] as const,
		contributes: {
			routes: [
				(deps) => {
					seen.resolver = deps.mfaFactorResolver;
					return {
						id: "test-mfa-factor-reader",
						mountPath: "/__test_mfa_factor_reader__",
						handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
					};
				},
			],
		},
	});
}

/** A module whose route reads `key`, so that the provider of `key` runs at boot. */
function readsTheSlot(key: "auditSink") {
	return defineModule({
		name: `test:reads-${key}`,
		requires: [key] as const,
		contributes: {
			routes: [
				() => ({
					id: `test-reads-${key}`,
					mountPath: `/__test_reads_${key}__`,
					handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
				}),
			],
		},
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

	it("reaches a provides factory that requires it, which reads it when a request comes", async () => {
		// The coordinator is a `provides` factory, and it is built before the
		// contributions are applied: the projection is in place from the
		// start and fills as the contributions register, so a provider holds
		// it and reads it at request time.
		const totp = factor("totp");
		const contributing = defineModule({
			name: "test:mfa-factors",
			contributes: { mfaFactors: { totp: () => totp } },
		});
		let held: MfaFactorResolver | undefined;
		const coordinatorLike = defineModule({
			name: "test:reads-the-resolver-from-provides",
			requires: ["mfaFactorResolver"] as const,
			provides: {
				auditSink: ({ mfaFactorResolver }) => {
					held = mfaFactorResolver;
					return { emit: async () => {} } as never;
				},
			},
		});
		const handle = await createApp({
			modules: [coordinatorLike, contributing, readsTheSlot("auditSink")],
			bootstrapComponents,
		});
		try {
			expect(held).toBeDefined();
			expect(held).toBe(handle.components.mfaFactorResolver);
			expect(held?.get("totp")).toBe(totp);
			expect([...(held?.entries() ?? [])]).toEqual([["totp", totp]]);
		} finally {
			await handle.dispose();
		}
	});

	it("lets a provides factory await, return or inspect a projection while it is built: only a read of its contents is refused", async () => {
		// An async factory that returns the projection, or a debug line that
		// prints its deps, touches `then`, `Symbol.toStringTag` and the like —
		// none of which reads what the contributions will fill.
		const seen: string[] = [];
		const holder = defineModule({
			name: "test:holds-the-resolver-while-built",
			requires: ["mfaFactorResolver"] as const,
			provides: {
				auditSink: async ({ mfaFactorResolver }) => {
					const awaited = await Promise.resolve(mfaFactorResolver);
					seen.push(awaited === mfaFactorResolver ? "awaited" : "replaced");
					seen.push(inspect(mfaFactorResolver).length > 0 ? "inspected" : "");
					seen.push(Object.prototype.toString.call(mfaFactorResolver));
					seen.push(String(mfaFactorResolver));
					expect(() => mfaFactorResolver.get("totp")).toThrow(/read it at request time/);
					return { emit: async () => {} } as never;
				},
			},
		});
		const handle = await createApp({
			modules: [holder, readsTheSlot("auditSink")],
			bootstrapComponents,
		});
		await handle.dispose();
		expect(seen).toEqual(["awaited", "inspected", "[object Object]", "[object Object]"]);
	});

	it("refuses the boot when a provides factory reads a projection while it is built", async () => {
		// Read then, it would be empty: the contributions register after the
		// provides factories run. A coordinator that computed its
		// `secondFactorMethods` from it at build time would offer no step-up;
		// the read fails the boot instead of answering an empty view.
		const contributing = defineModule({
			name: "test:mfa-factors",
			contributes: { mfaFactors: { totp: () => factor("totp") } },
		});
		const eager = defineModule({
			name: "test:reads-the-resolver-while-built",
			requires: ["mfaFactorResolver"] as const,
			provides: {
				auditSink: ({ mfaFactorResolver }) => {
					void [...mfaFactorResolver.entries()];
					return { emit: async () => {} } as never;
				},
			},
		});
		const err = await createApp({
			modules: [eager, contributing, readsTheSlot("auditSink")],
			bootstrapComponents,
		}).then(
			async (handle) => {
				await handle.dispose();
				return undefined;
			},
			(caught: unknown) => caught,
		);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).reason).toBe("provides-factory-failed");
		expect(((err as BootError).cause as Error).message).toBe(
			"mfaFactorResolver was read while the provides factories run: it fills as the contributions register, so read it at request time",
		);
	});

	it("gives a provides factory the same projection of every synthetic key the world holds", async () => {
		const seen: Record<string, unknown> = {};
		const keys = [
			"grantHandlerResolver",
			"tokenExchangeValidatorResolver",
			"federationProviders",
			"federationRedirectPolicyResolver",
			"mfaFactorResolver",
		];
		const provider = defineModule({
			name: "test:reads-every-projection",
			requires: keys as never,
			provides: {
				auditSink: (deps: Record<string, unknown>) => {
					for (const key of keys) seen[key] = deps[key];
					return { emit: async () => {} } as never;
				},
			},
		} as never);
		const handle = await createApp({
			modules: [provider, readsTheSlot("auditSink")],
			bootstrapComponents,
		});
		try {
			for (const key of keys) {
				expect(seen[key], key).toBeDefined();
				expect(seen[key], key).toBe((handle.components as Record<string, unknown>)[key]);
			}
		} finally {
			await handle.dispose();
		}
	});

	it("refuses at boot a factor contributed under a key that is not its kind", async () => {
		// The resolver answers by key, and the coordinator reads a record's kind
		// back through it: a factor filed under another kind would verify that
		// kind's records.
		for (const [name, modules] of [
			[
				"contributes",
				[
					defineModule({
						name: "test:mfa-misfiled",
						contributes: { mfaFactors: { totp: () => factor("email") } },
					}),
				],
			],
			[
				"overrides",
				[
					defineModule({
						name: "test:mfa-totp",
						contributes: { mfaFactors: { totp: () => factor("totp") } },
					}),
					defineModule({
						name: "test:mfa-totp-override",
						overrides: { mfaFactors: { totp: () => factor("webauthn") } },
					}),
				],
			],
		] as const) {
			const err = await createApp({ modules: [...modules], bootstrapComponents }).then(
				async (handle) => {
					await handle.dispose();
					return undefined;
				},
				(caught: unknown) => caught,
			);
			expect(err, name).toBeInstanceOf(BootError);
			expect((err as BootError).reason, name).toBe("contribute-factory-failed");
			expect((err as BootError).cause, name).toBeInstanceOf(RangeError);
			expect(((err as BootError).cause as Error).message, name).toBe(
				'mfaFactors "totp": the factor\'s kind must be the key it is contributed under',
			);
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
