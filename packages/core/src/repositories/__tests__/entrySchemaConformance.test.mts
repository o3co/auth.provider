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
 * Issue #343 — a coverage-*shape* problem, not a coverage-percentage one.
 *
 * #342 fixed a release blocker: `firstParty` could not be set on any
 * file-backed client registration, so `/authorize` was unusable with the
 * shipped template. CI was green throughout, because every in-repo test of the
 * #316 invariant hand-stubbed a `ClientRepository` returning an object literal
 * with `firstParty: true`. Nothing drove the invariant through
 * `InMemoryClientRepository` or the YAML loader — which is what every real
 * deployment uses. The stubs passed against a repository whose schema could not
 * represent the field at all.
 *
 * The issue asks for the mechanical form of the check rather than one more
 * instance of the bug, and `ClientEntrySchema` is `.strict()`, which makes it
 * cheap: parse a `Client` with **every** field populated, and any field the
 * domain type has but the schema does not becomes an unrecognized key. That is
 * precisely the #342 shape, caught by construction instead of by someone
 * noticing.
 *
 * Keeping this honest is the fixtures' job, and it has to be enforced rather
 * than asked for: when `Client` gains a field, `FULLY_POPULATED_CLIENT` below
 * must gain it too, or the guard silently stops covering the one thing it
 * exists to cover. A plain `satisfies Omit<Client, "clientId">` does not do
 * that — an omitted *optional* field is still assignable, so the fixture would
 * quietly fall behind the type. `Required<...>` is what makes the omission a
 * compile error, which is the same move as the runtime check below: catch the
 * class mechanically instead of trusting a comment.
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
	// #484: the private_key_jwt key sources. Mutually exclusive with each
	// other and with clientSecret by method, so the runtime parse below
	// registers the fixture as variants; the type-level check stays whole.
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
	senderConstrained: { required: true, methods: ["dpop"] },
	firstParty: true,
	allowPlainPkce: false,
	// `Required<...>`, not a bare `Omit<...>`: an omitted optional field is
	// assignable to the latter, so a new field on `Client` would silently stop
	// being covered here. This turns that into a compile error.
} satisfies Required<Omit<Client, "clientId">>;

/**
 * #484: `clientSecret`, `jwks` and `jwksUri` cannot coexist on one
 * registration — the method selects exactly one credential — so the runtime
 * check registers three variants that together carry every field of the
 * fixture. The union-of-keys assertion below is what keeps that honest.
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
		// The whole point. `.strict()` means an unrecognized key throws, so a
		// field on `Client` that the schema never learned about fails here —
		// which is exactly how #342 would have been caught before it shipped.
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
		// The other direction, and the reason `.strict()` is worth keeping: a
		// typo'd key in a YAML registration must fail boot rather than be
		// silently ignored, which would leave the operator believing they
		// configured something.
		expect(() => ClientEntrySchema.parse({ ...REGISTRABLE_VARIANTS[0], frstParty: true })).toThrow(
			/frstParty/,
		);
	});

	it("carries firstParty specifically — the #342 regression", () => {
		// Named on its own because this one was a release blocker: without it
		// `/authorize` answered `unauthorized_client` for every file-backed
		// registration, and no stub-based test could see it.
		const parsed = ClientEntrySchema.parse(REGISTRABLE_VARIANTS[0]) as { firstParty?: boolean };
		expect(parsed.firstParty).toBe(true);
	});
});

/**
 * A `User` with every *declared* field set. `User` also carries an index
 * signature for Store-specific claims, which no schema can enumerate — and
 * `UserEntrySchema` is `.catchall(z.unknown())` rather than `.strict()` for
 * that reason. So the check here is the round-trip, not the refusal.
 *
 * `Required<User>` for the same reason the client fixture uses it: a new
 * optional field on `User` must break this line rather than slip past it. The
 * index signature survives `Required` and forces nothing, which is correct —
 * there is no set of Store-specific claims to enumerate.
 */
const FULLY_POPULATED_USER = {
	id: "u-1",
	username: "alice",
	email: "alice@example.com",
	emailVerified: true,
	name: "Alice Example",
	picture: "https://example.com/alice.png",
	groups: ["staff"],
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
