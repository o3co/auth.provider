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
 * The file-backed entry schemas can represent every field of the domain type
 * they load. A test that stubs `ClientRepository` with an object literal
 * cannot see a field the schema lacks, so this parses fixtures with every
 * field populated through the schemas themselves: `ClientEntrySchema` is
 * `.strict()`, so a field `Client` has and the schema lacks surfaces as an
 * unrecognized key. `Required<...>` keeps each fixture in step with its type.
 */

import { describe, expect, it } from "vitest";
import { ClientEntrySchema } from "#/repositories/InMemoryClientRepository.mjs";
import { UserEntrySchema } from "#/repositories/InMemoryUserRepository.mjs";
import type { Client, User } from "#/repositories/types.mjs";

/**
 * A `Client` with every field set, including every optional one.
 *
 * `clientId` is excluded because it is the map key in a file-backed
 * registration, not a field inside the entry — `loadYamlMap` supplies it from
 * the YAML key.
 */
const FULLY_POPULATED_CLIENT = {
	tokenEndpointAuthMethod: "client_secret_basic",
	clientSecret: "a-client-secret-value",
	// The private_key_jwt key sources. Mutually exclusive with each other and
	// with clientSecret by method, so the runtime parse below registers the
	// fixture as variants; the type-level check stays whole.
	jwks: {
		keys: [
			{
				kty: "EC",
				crv: "P-256",
				kid: "k1",
				x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
				y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
			},
		],
	},
	jwksUri: "https://app.example.com/jwks.json",
	allowedRedirectUris: ["https://app.example.com/cb"],
	allowedScopes: ["read", "write"],
	defaultScopes: ["read"],
	allowedAudiences: ["https://api.example.com"],
	allowedGrantTypes: ["authorization_code", "refresh_token"],
	postLogoutRedirectUris: ["https://app.example.com/bye"],
	backchannelLogoutUri: "https://app.example.com/backchannel",
	backchannelLogoutSessionRequired: true,
	frontchannelLogoutUri: "https://app.example.com/frontchannel",
	frontchannelLogoutSessionRequired: true,
	clientName: "Example App",
	clientUri: "https://app.example.com",
	allowedAzpForFederationToken: true,
	allowedFederationGrantConnections: ["graph"],
	federationGrantRedirectUris: ["https://app.example.com/grants/cb"],
	senderConstrained: { required: true, methods: ["dpop"] },
	firstParty: true,
	allowPlainPkce: false,
	// `Required<...>`, not a bare `Omit<...>`: an omitted optional field is
	// assignable to the latter, so a new field on `Client` would silently stop
	// being covered here. This turns that into a compile error.
} satisfies Required<Omit<Client, "clientId">>;

/**
 * `clientSecret`, `jwks` and `jwksUri` cannot coexist on one registration —
 * the method selects exactly one credential — so the runtime check registers
 * three variants that together carry every field of the fixture.
 */
const { jwks, jwksUri, clientSecret, ...common } = FULLY_POPULATED_CLIENT;
const REGISTRABLE_VARIANTS: ReadonlyArray<Record<string, unknown>> = [
	{ ...common, tokenEndpointAuthMethod: "client_secret_basic", clientSecret },
	{ ...common, tokenEndpointAuthMethod: "private_key_jwt", jwks },
	{ ...common, tokenEndpointAuthMethod: "private_key_jwt", jwksUri },
];

describe("ClientEntrySchema conformance with Client (#343)", () => {
	it("registers every field of the fixture across the variants", () => {
		const covered = new Set(REGISTRABLE_VARIANTS.flatMap((v) => Object.keys(v)));
		expect([...covered].sort()).toEqual(Object.keys(FULLY_POPULATED_CLIENT).sort());
	});

	it("represents every field the domain type carries", () => {
		// `.strict()` throws on an unrecognized key, so a field on `Client` that
		// the schema lacks fails here.
		for (const variant of REGISTRABLE_VARIANTS) {
			expect(() => ClientEntrySchema.parse(variant)).not.toThrow();
		}
	});

	it("round-trips every field rather than quietly dropping any", () => {
		// Representable is not enough: a field the schema strips would leave the
		// repository returning a client the registration thought it configured.
		for (const variant of REGISTRABLE_VARIANTS) {
			const parsed = ClientEntrySchema.parse(variant) as Record<string, unknown>;
			for (const [key, value] of Object.entries(variant)) {
				expect(parsed).toHaveProperty(key);
				expect(parsed[key]).toEqual(value);
			}
		}
	});

	it("names the offending key when a registration carries one the schema does not know", () => {
		// Why `.strict()` stays: a typo'd key in a YAML registration must fail
		// boot rather than be silently ignored, leaving the operator believing
		// they configured something.
		expect(() => ClientEntrySchema.parse({ ...REGISTRABLE_VARIANTS[0], frstParty: true })).toThrow(
			/frstParty/,
		);
	});

	it("carries firstParty specifically — the #342 regression", () => {
		// Pinned on its own: without it `/authorize` answers
		// `unauthorized_client` for every file-backed registration.
		const parsed = ClientEntrySchema.parse(REGISTRABLE_VARIANTS[0]) as { firstParty?: boolean };
		expect(parsed.firstParty).toBe(true);
	});
});

/**
 * A `User` with every *declared* field set. `User` also has an index
 * signature for Store-specific claims, which no schema can enumerate, so
 * `UserEntrySchema` is `.catchall(z.unknown())` rather than `.strict()` and
 * the check here is the round-trip, not the refusal.
 *
 * `Required<User>` makes a new optional field on `User` break this line. The
 * index signature survives `Required` and forces nothing, which is correct.
 */
const FULLY_POPULATED_USER = {
	id: "u-1",
	username: "alice",
	email: "alice@example.com",
	emailVerified: true,
	name: "Alice Example",
	picture: "https://example.com/alice.png",
	groups: ["staff"],
	// The MFA enrollment witness a Store answers on `authenticate`
	// (ADR 2026-09-25-multi-factor-authentication).
	mfaEnrolled: true,
} satisfies Required<User>;

describe("UserEntrySchema conformance with User (#343)", () => {
	it("round-trips every declared field", () => {
		const parsed = UserEntrySchema.parse({
			...FULLY_POPULATED_USER,
			password: "a-password",
		}) as Record<string, unknown>;
		for (const [key, value] of Object.entries(FULLY_POPULATED_USER)) {
			expect(parsed[key]).toEqual(value);
		}
	});

	it("keeps Store-specific claims rather than stripping them", () => {
		// `User`'s index signature is a real part of the contract: a Store may
		// publish claims this library never names. `.catchall` is what honours
		// it, and a future tightening to `.strict()` would break every such
		// deployment silently at boot.
		const parsed = UserEntrySchema.parse({
			password: "a-password",
			username: "alice",
			department: "engineering",
		}) as Record<string, unknown>;
		expect(parsed.department).toBe("engineering");
	});
});
