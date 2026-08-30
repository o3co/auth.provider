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
 * `deviceGrantModule` boot invariants (#298).
 *
 * Two settings have no default and fail boot instead, for two different
 * reasons — and both reasons are the point of the test.
 */

import type { BootstrapMap, ClientRepository } from "@o3co/auth-provider-core";
import {
	createApp,
	createMemoryDeviceCodeStore,
	createMemoryRateLimiter,
	createSymmetricKeyStore,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { deviceGrantModule } from "#/module.mjs";
import { DEVICE_CODE_GRANT_TYPE } from "#/types.mjs";

const clientRepository: ClientRepository = {
	findById: async () => null,
	authenticate: async () => null,
};

interface Overrides {
	readonly deviceAuthorization?: Record<string, unknown>;
	readonly withStore?: boolean;
	readonly withRateLimiter?: boolean;
}

const makeBoot = (overrides: Overrides): BootstrapMap => {
	const core = makeValidCoreConfig();
	return {
		config: {
			...core,
			oauth: {
				...core.oauth,
				deviceAuthorization: {
					enabled: false,
					"verification-uri-complete": false,
					"code-lifetime-seconds": 600,
					"polling-interval-seconds": 5,
					...(overrides.deviceAuthorization ?? {}),
				},
			},
		},
		pathResolver: (s: string) => s,
		clientRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!!"),
		...(overrides.withStore === false ? {} : { deviceCodeStore: createMemoryDeviceCodeStore() }),
		...(overrides.withRateLimiter === false
			? {}
			: {
					rateLimiter: createMemoryRateLimiter({
						limits: { device_verification: { limit: 5, windowSeconds: 300 } },
						defaultLimit: { limit: 60, windowSeconds: 60 },
					}),
				}),
	} as unknown as BootstrapMap;
};

const boot = (overrides: Overrides) =>
	createApp({ modules: [deviceGrantModule], bootstrapComponents: makeBoot(overrides) });

const ENABLED = {
	enabled: true,
	"verification-uri": "https://example.test/device",
};

describe("deviceGrantModule — boot", () => {
	it("boots disabled without any of the required settings", async () => {
		// Installing the package must not turn on a grant, and a deployment
		// that leaves it off must never trip settings it does not use.
		const handle = await boot({});
		await handle.dispose();
	});

	it("refuses to boot enabled without a verification-uri", async () => {
		// No default is possible: the page belongs to the deployment, and the
		// device displays this string verbatim to people who need to reach it.
		await expect(boot({ deviceAuthorization: { enabled: true } })).rejects.toThrow(
			/verification-uri/,
		);
	});

	it("refuses to boot enabled without a rate limiter", async () => {
		// RFC 8628 §5.1 sizes the user code's entropy AGAINST a rate limit:
		// ~34.5 bits is sufficient only where an attacker gets a handful of
		// attempts. Without a limiter that argument does not hold, so this is a
		// refusal rather than a degraded mode.
		await expect(boot({ deviceAuthorization: ENABLED, withRateLimiter: false })).rejects.toThrow(
			/§5\.1|rate/i,
		);
	});

	it("refuses to boot without a device code store, naming the config key", async () => {
		// #363's absence policy: optional to wire, not optional to decide. A
		// composition with no store cannot authorize any device at all, so the
		// failure belongs at boot rather than on the first request.
		await expect(boot({ deviceAuthorization: ENABLED, withStore: false })).rejects.toThrow(
			/oauth\.deviceAuthorization\.store/,
		);
	});

	it("boots when the operator declares the store absent on purpose", async () => {
		const handle = await boot({
			deviceAuthorization: { ...ENABLED, store: "unsupported" },
			withStore: false,
		});
		await handle.dispose();
	});

	it("boots with everything wired", async () => {
		const handle = await boot({ deviceAuthorization: ENABLED });
		await handle.dispose();
	});
});

describe("deviceGrantModule — discovery (RFC 8628 §4)", () => {
	it("advertises the endpoint and the grant type when enabled", async () => {
		// A client has no other way to find the endpoint, so the metadata is
		// the feature being reachable rather than a description of it.
		const handle = await boot({ deviceAuthorization: ENABLED });
		const contribution = deviceGrantModule.contributes?.discoveryMetadata?.[0] as (
			deps: unknown,
		) => { metadata?: Record<string, unknown>; grantTypes?: readonly string[] };
		const result = contribution({
			config: {
				oauth: {
					jwt: { issuer: "https://as.example.test" },
					deviceAuthorization: ENABLED,
				},
			},
		});
		expect(result.metadata?.device_authorization_endpoint).toBe(
			"https://as.example.test/oauth/device_authorization",
		);
		expect(result.grantTypes).toEqual([DEVICE_CODE_GRANT_TYPE]);
		await handle.dispose();
	});

	it("advertises nothing when disabled", async () => {
		// #283's rule: the document must not claim a capability the deployment
		// does not have.
		const contribution = deviceGrantModule.contributes?.discoveryMetadata?.[0] as (
			deps: unknown,
		) => Record<string, unknown>;
		expect(
			contribution({
				config: {
					oauth: {
						jwt: { issuer: "https://as.example.test" },
						deviceAuthorization: { enabled: false },
					},
				},
			}),
		).toEqual({});
	});
});

describe("deviceGrantModule — disabled surface", () => {
	it("answers unsupported_grant_type at the token endpoint when disabled", async () => {
		// Observable behaviour matches "not installed": the token endpoint
		// answers the same code it uses for an unregistered grant.
		const factory = deviceGrantModule.contributes?.grants?.[DEVICE_CODE_GRANT_TYPE] as (
			deps: unknown,
		) => { handle(ctx: unknown): Promise<{ result: { error?: string } }> };
		const handler = factory({ config: { oauth: { deviceAuthorization: { enabled: false } } } });
		const { result } = await handler.handle({});
		expect(result.error).toBe("unsupported_grant_type");
	});
});
