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

import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import { TransitionalConfigSchema } from "#/config/composed.mjs";
import { makeValidAppConfig } from "#/testing/fixtures/valid-config.mjs";

/**
 * The sections core's schema still mirrors, transitionally, for another
 * package's modules: `webauthn`, `federation-grants.enabled`, and the stores'
 * sections presence-only. Boot's composed parse applies each
 * mirror whenever the configuration carries the section, the module that
 * reads it loaded or not; a check here goes when its mirror leaves core.
 *
 * Nothing here is about a section surviving: boot lays every parse over what
 * was written, and a loaded module's section is written back at its path
 * (`boot/__tests__/composed-parse.test.mts`). What a mirror does is coerce an
 * environment variable's string, refuse a value by path, and stay absent
 * when the section is — the defaults live in each package's
 * `config/reference.conf`.
 */

const base = makeValidAppConfig();
const parse = (config: unknown) => TransitionalConfigSchema.parse(config);

describe("the stores' sections, and the paths they moved from", () => {
	// Each store module's section schema coerces and refuses; core keeps its
	// section and the path it moved from as written, for the module and for
	// the relocation refusal.
	const WRITTEN = { limits: { token: { limit: "0", windowSeconds: 1e13 } }, bogus: true };

	it.each([
		"core-rate-limiter-memory",
		"redis-rate-limiter",
		"redis-consent-store",
		"memoryRateLimiter",
		"redisRateLimiter",
		"redisConsentStore",
	])("keeps %s as written", (section) => {
		expect((parse({ ...base, [section]: WRITTEN }) as Record<string, unknown>)[section]).toEqual(
			WRITTEN,
		);
		expect(
			(AppConfigSchema.parse({ ...base, [section]: WRITTEN }) as Record<string, unknown>)[section],
		).toEqual(WRITTEN);
	});

	it("keeps rateLimit.failMode as written, beside the login budget", () => {
		expect(
			parse({ ...base, rateLimit: { ...base.rateLimit, failMode: "sometimes" } }).rateLimit,
		).toMatchObject({ failMode: "sometimes" });
	});
});

describe("the federation-grants sections, and the paths they moved from", () => {
	// Each module's section schema coerces and refuses; core keeps these as
	// written, for the modules and for the relocation refusal.
	const WRITTEN = { keyPrefix: "{x}", tombstoneRetention: "not-a-duration", bogus: true };

	it.each([
		"federationGrants",
		"redisFederationGrantStore",
		"core-federation-grant-store-memory",
		"redis-federation-grant-store",
		"redis-federation-grant-intent-store",
	])("keeps %s as written", (section) => {
		expect((parse({ ...base, [section]: WRITTEN }) as Record<string, unknown>)[section]).toEqual(
			WRITTEN,
		);
		expect(
			(AppConfigSchema.parse({ ...base, [section]: WRITTEN }) as Record<string, unknown>)[section],
		).toEqual(WRITTEN);
	});

	it("reads federation-grants.enabled from a variable's string, the one key read before modules, and keeps the rest as written", () => {
		const written = { enabled: "true", maxExpiresIn: "not-a-duration", connections: {} };
		const parsed = { ...written, enabled: true };
		expect(parse({ ...base, "federation-grants": written })["federation-grants"]).toEqual(parsed);
		expect(
			AppConfigSchema.parse({ ...base, "federation-grants": written })["federation-grants"],
		).toEqual(parsed);
		expect(() => parse({ ...base, "federation-grants": { enabled: "sometimes" } })).toThrow();
	});
});

describe("the paths the dpop, mtls, device-grant and oauth-token-exchange sections moved from", () => {
	// A root that parses with `AppConfigSchema` before boot hands what it kept
	// to the relocation refusal; the schema checks nothing under them.
	it.each([
		["dpop", { enabled: "not-a-boolean", "replay-store": "redis", nonce: { secret: "x" } }],
		["mtls", { mode: "pki-ish", "cert-header": "x-client-cert" }],
		["deviceAuthorization", { store: "memory", rateLimit: { limit: 5, windowSeconds: 1e13 } }],
		["tokenExchange", { maxActorChainDepth: "not-a-number" }],
	])("keeps oauth.%s as written", (key, written) => {
		const parsed = parse({ ...base, oauth: { ...base.oauth, [key]: written } });
		expect((parsed.oauth as Record<string, unknown>)[key]).toEqual(written);
		expect(
			(
				AppConfigSchema.parse({ ...base, oauth: { ...base.oauth, [key]: written } })
					.oauth as Record<string, unknown>
			)[key],
		).toEqual(written);
	});

	it.each(["dpop", "mtls", "deviceAuthorization", "tokenExchange"])(
		"is absent when oauth.%s is",
		(key) => {
			expect(parse(base).oauth).not.toHaveProperty(key);
		},
	);
});

describe("webauthn's mirror", () => {
	it("keeps the single-origin spelling an env substitution produces, for the package's schema to split", () => {
		const parsed = parse({
			...base,
			webauthn: { origin: "https://example.com", topOrigin: "https://embedder.example" },
		});
		expect(parsed.webauthn?.origin).toBe("https://example.com");
		expect(parsed.webauthn?.topOrigin).toBe("https://embedder.example");
	});

	it("refuses a user-verification requirement WebAuthn does not have", () => {
		expect(() => parse({ ...base, webauthn: { userVerification: "optional" } })).toThrow();
	});

	it("is absent when omitted — the defaults live in the webauthn reference.conf", () => {
		expect(parse(base).webauthn).toBeUndefined();
	});
});
