/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it, vi } from "vitest";
import type { BootstrapMap } from "#/boot/types.mjs";
import { BootError } from "#/boot/types.mjs";
import { validateManifests } from "#/boot/validate-manifests.mjs";
import { defineModule } from "#/modules/manifest/define-module.mjs";
import type { RateLimiter } from "#/ratelimit/types.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { memoryRateLimiterModule } from "../module.mjs";
import { verifierLimitClaim, withVerifierLimitDeclarations } from "../verifierLimits.mjs";
import { shippedMemoryRateLimiterSection } from "./shippedSection.mjs";

/** The prefixes a verifier limits itself, and the setting each is made at. */
const VERIFIER_PREFIXES = [
	["login", "session.rateLimit.login"],
	["device_verification", "device-grant.rateLimit"],
] as const;

describe("memoryRateLimiterModule", () => {
	it("has the canonical name", () => {
		expect(memoryRateLimiterModule.name).toBe("core-rate-limiter-memory");
	});

	it("requires nothing: no contributed budget is read", () => {
		expect(memoryRateLimiterModule.requires ?? []).toEqual([]);
	});

	it("provides rateLimiter", () => {
		expect(typeof memoryRateLimiterModule.provides?.rateLimiter).toBe("function");
	});

	it("is read at its own section, core-rate-limiter-memory", () => {
		expect(memoryRateLimiterModule.name).toBe("core-rate-limiter-memory");
		expect(memoryRateLimiterModule.section).not.toHaveProperty("at");
		expect(memoryRateLimiterModule).not.toHaveProperty("configSchema");
	});

	it("reads maxBuckets 10000 as core's reference.conf ships it, and fills none itself", () => {
		const parsed = memoryRateLimiterModule.section?.schema.parse(shippedMemoryRateLimiterSection());
		expect(memoryRateLimiterModule.section?.schema.safeParse(undefined).success).toBe(false);
		expect(parsed).toMatchObject({ maxBuckets: 10_000 });
	});

	it("reads maxBuckets and a spec from the string an environment variable carries", () => {
		expect(
			memoryRateLimiterModule.section?.schema.parse(
				shippedMemoryRateLimiterSection({
					maxBuckets: "500",
					defaultLimit: { limit: "5", windowSeconds: "60" },
				}),
			),
		).toMatchObject({ maxBuckets: 500, defaultLimit: { limit: 5, windowSeconds: 60 } });
	});

	it("refuses a window longer than a year, and a key it does not declare, in its section's schema", () => {
		for (const section of [
			{ defaultLimit: { limit: 5, windowSeconds: 31_536_001 } },
			{ limits: { token: { limit: 5, windowSeconds: 1e13 } } },
			{ maxBucket: 5 },
			{ defaultLimit: { limit: 5, windowSeconds: 60, window: 1 } },
		]) {
			expect(
				memoryRateLimiterModule.section?.schema.safeParse(shippedMemoryRateLimiterSection(section))
					?.success,
				JSON.stringify(section),
			).toBe(false);
		}
	});

	it("limits requests per the configured spec", async () => {
		const cfg = {
			limits: { "test.ip": { limit: 2, windowSeconds: 60 } },
			defaultLimit: { limit: 60, windowSeconds: 60 },
			maxBuckets: 10_000,
		};
		const limiter = memoryRateLimiterModule.provides?.rateLimiter?.({ section: cfg } as never) as
			| RateLimiter
			| undefined;
		expect(limiter).toBeDefined();
		if (!limiter) throw new Error("rateLimiter provider missing");
		const a = await limiter.check("test.ip:1.2.3.4", { ip: "1.2.3.4" });
		expect(a.allowed).toBe(true);
		const b = await limiter.check("test.ip:1.2.3.4", { ip: "1.2.3.4" });
		expect(b.allowed).toBe(true);
		const c = await limiter.check("test.ip:1.2.3.4", { ip: "1.2.3.4" });
		expect(c.allowed).toBe(false);
	});

	it.each(VERIFIER_PREFIXES)(
		"refuses a limits entry for %s, a verifier's own limit, in its section's schema, naming the key and the setting",
		(prefix, setting) => {
			const parsed = withVerifierLimitDeclarations(new Map([[prefix, setting]]), () =>
				memoryRateLimiterModule.section?.schema.safeParse(
					shippedMemoryRateLimiterSection({
						limits: {
							[prefix]: { limit: 5, windowSeconds: 60 },
							token: { limit: 5, windowSeconds: 60 },
						},
					}),
				),
			);
			expect(parsed?.success).toBe(false);
			expect(parsed?.error?.issues).toEqual([
				expect.objectContaining({
					path: ["limits", prefix],
					message: expect.stringContaining(setting),
				}),
			]);
		},
	);

	it.each(VERIFIER_PREFIXES)(
		"refuses boot on core-rate-limiter-memory.limits.%s, naming its path and the setting its owner declared",
		(prefix, setting) => {
			const config = {
				...makeValidCoreConfig(),
				"core-rate-limiter-memory": shippedMemoryRateLimiterSection({
					limits: { [prefix]: { limit: 5, windowSeconds: 60 } },
				}),
			};
			let err: unknown;
			try {
				validateManifests({
					modules: [
						memoryRateLimiterModule,
						defineModule({
							name: "verifier-owner",
							contributes: { rateLimitBudgets: { [prefix]: verifierLimitClaim({ setting }) } },
						}),
					],
					bootstrapComponents: {
						config: config as never,
						pathResolver: (s: string) => s,
					} satisfies Record<string, unknown> as BootstrapMap,
				});
			} catch (caught) {
				err = caught;
			}
			expect(err).toBeInstanceOf(BootError);
			expect((err as BootError).reason).toBe("config-validation-failed");
			expect((err as BootError).message).toContain(`core-rate-limiter-memory.limits.${prefix}`);
			expect((err as BootError).message).toContain(setting);
		},
	);

	it.each(VERIFIER_PREFIXES)(
		"accepts a limits entry for %s in its section's schema when nothing declares it: only declarations count",
		(prefix) => {
			expect(
				memoryRateLimiterModule.section?.schema.safeParse(
					shippedMemoryRateLimiterSection({
						limits: { [prefix]: { limit: 5, windowSeconds: 60 } },
					}),
				)?.success,
			).toBe(true);
		},
	);

	it("limits a prefix by its own limits entry, else its defaultLimit, whatever a resolver answers", async () => {
		const asked: string[] = [];
		const limiter = memoryRateLimiterModule.provides?.rateLimiter?.({
			section: {
				limits: { token: { limit: 4, windowSeconds: 45 } },
				defaultLimit: { limit: 60, windowSeconds: 60 },
				maxBuckets: 10_000,
			},
			rateLimitBudgetResolver: {
				get: (prefix: string) => {
					asked.push(prefix);
					return { limit: 2, windowSeconds: 300 };
				},
				entries: () => new Map().entries(),
			},
		} as never) as RateLimiter | undefined;
		if (!limiter) throw new Error("rateLimiter provider missing");

		expect((await limiter.check("token:ip:1.2.3.4", { ip: "1.2.3.4" })).limit).toBe(4);
		expect((await limiter.check("mfa:ip:1.2.3.4", { ip: "1.2.3.4" })).limit).toBe(60);
		expect(asked).toEqual([]);
	});

	it("reads no owner's key: a prefix its own limits do not name falls to its defaultLimit", async () => {
		// The owners' keys are their modules' to read, and to refuse.
		const limiter = memoryRateLimiterModule.provides?.rateLimiter?.({
			section: { limits: {}, defaultLimit: { limit: 60, windowSeconds: 60 }, maxBuckets: 10_000 },
			config: {
				rateLimit: { login: { windowMs: 900_000, limit: 0 } },
				"device-grant": { rateLimit: { limit: 2, windowSeconds: 300 } },
				webauthn: { rateLimit: { authenticationOptions: { limit: "thirty", windowSeconds: 60 } } },
				mfa: {
					rateLimit: { routes: { limit: 2, windowSeconds: 300 } },
					factors: { email: { sendLimit: { limit: 1, windowSeconds: 3600 } } },
				},
			},
		} as never) as RateLimiter | undefined;
		if (!limiter) throw new Error("rateLimiter provider missing");
		for (const key of [
			"login:ip:1.2.3.4",
			"device_verification:user:u1",
			"webauthn-authentication-options:ip:1.2.3.4",
			"mfa:ip:1.2.3.4",
			"mfa-email:user:u1",
		]) {
			expect((await limiter.check(key, { ip: "1.2.3.4" })).limit, key).toBe(60);
		}
	});

	it("bounds bucket growth with core-rate-limiter-memory.maxBuckets", async () => {
		vi.useFakeTimers();
		try {
			vi.setSystemTime(new Date("2026-05-09T00:00:00Z"));

			const cfg = {
				limits: {},
				defaultLimit: { limit: 2, windowSeconds: 60 },
				maxBuckets: 2,
			};
			const limiter = memoryRateLimiterModule.provides?.rateLimiter?.({ section: cfg } as never) as
				| RateLimiter
				| undefined;
			expect(limiter).toBeDefined();
			if (!limiter) throw new Error("rateLimiter provider missing");

			await limiter.check("test:A", {});
			vi.advanceTimersByTime(1);
			await limiter.check("test:B", {});
			vi.advanceTimersByTime(1);
			await limiter.check("test:C", {});

			const existingB = await limiter.check("test:B", {});
			expect(existingB.remaining).toBe(0);

			const recreatedA = await limiter.check("test:A", {});
			expect(recreatedA.remaining).toBe(1);
		} finally {
			vi.useRealTimers();
		}
	});
});
