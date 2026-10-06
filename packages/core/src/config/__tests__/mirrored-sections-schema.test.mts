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
import { CoreConfigSchema } from "#/config/application.schema.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

/**
 * The one section core's schema still mirrors for another package: `oauth`,
 * the oauth module's. Its keys that moved to other modules' sections, and the
 * keys the oauth module's own schema declares, are presence-only in core's
 * copy: kept as written, nothing checked under them, and absent when they
 * are. Every other package's section is no part of core's schema
 * (`boot/__tests__/composed-parse.test.mts`).
 */

const base = makeValidCoreConfig();
const parse = (config: unknown) => CoreConfigSchema.parse(config);

describe("the paths the dpop, mtls, device-grant and oauth-token-exchange sections moved from", () => {
	it.each([
		["dpop", { enabled: "not-a-boolean", "replay-store": "redis", nonce: { secret: "x" } }],
		["mtls", { mode: "pki-ish", "cert-header": "x-client-cert" }],
		["deviceAuthorization", { store: "memory", rateLimit: { limit: 5, windowSeconds: 1e13 } }],
		["tokenExchange", { maxActorChainDepth: "not-a-number" }],
	])("keeps oauth.%s as written", (key, written) => {
		const parsed = parse({ ...base, oauth: { ...base.oauth, [key]: written } });
		expect((parsed.oauth as Record<string, unknown>)[key]).toEqual(written);
	});

	it.each(["dpop", "mtls", "deviceAuthorization", "tokenExchange"])(
		"is absent when oauth.%s is",
		(key) => {
			expect(parse(base).oauth).not.toHaveProperty(key);
		},
	);
});

describe("the oauth module's own keys, and the paths oauth's settings moved from", () => {
	it.each([
		["grants", { session: { enabled: "x" }, authorization_code: { pkce: { requireS256: 1 } } }],
		["tokenBinding", { "dispatch-policy": "x" }],
		["clientIdMetadataDocuments", { enabled: "x", maxBytes: -1 }],
		["consentPage", { url: 42 }],
	])("keeps oauth.%s as written", (key, written) => {
		const parsed = parse({ ...base, oauth: { ...base.oauth, [key]: written } });
		expect((parsed.oauth as Record<string, unknown>)[key]).toEqual(written);
	});
});
