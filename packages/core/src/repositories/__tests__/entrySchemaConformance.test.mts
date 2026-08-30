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
 * Keeping this honest is a maintenance obligation: when `Client` gains a field,
 * `FULLY_POPULATED_CLIENT` below has to gain it too, or the guard silently
 * stops covering it. The type annotation is what forces that — a missing
 * required field is a compile error, and `exactOptionalPropertyTypes` plus the
 * `satisfies` below turn a typo into one as well.
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
	allowedAzpForFederationToken: true,
	senderConstrained: { required: true, methods: ["dpop"] },
	firstParty: true,
	allowPlainPkce: false,
} satisfies Omit<Client, "clientId">;

describe("ClientEntrySchema conformance with Client (#343)", () => {
	it("represents every field the domain type carries", () => {
		// The whole point. `.strict()` means an unrecognized key throws, so a
		// field on `Client` that the schema never learned about fails here —
		// which is exactly how #342 would have been caught before it shipped.
		expect(() => ClientEntrySchema.parse(FULLY_POPULATED_CLIENT)).not.toThrow();
	});

	it("round-trips every field rather than quietly dropping any", () => {
		// Representable is not enough: a field the schema strips would leave the
		// repository returning a client the registration thought it configured.
		const parsed = ClientEntrySchema.parse(FULLY_POPULATED_CLIENT) as Record<string, unknown>;
		for (const [key, value] of Object.entries(FULLY_POPULATED_CLIENT)) {
			expect(parsed).toHaveProperty(key);
			expect(parsed[key]).toEqual(value);
		}
	});

	it("names the offending key when a registration carries one the schema does not know", () => {
		// The other direction, and the reason `.strict()` is worth keeping: a
		// typo'd key in a YAML registration must fail boot rather than be
		// silently ignored, which would leave the operator believing they
		// configured something.
		expect(() => ClientEntrySchema.parse({ ...FULLY_POPULATED_CLIENT, frstParty: true })).toThrow(
			/frstParty/,
		);
	});

	it("carries firstParty specifically — the #342 regression", () => {
		// Named on its own because this one was a release blocker: without it
		// `/authorize` answered `unauthorized_client` for every file-backed
		// registration, and no stub-based test could see it.
		const parsed = ClientEntrySchema.parse(FULLY_POPULATED_CLIENT) as { firstParty?: boolean };
		expect(parsed.firstParty).toBe(true);
	});
});

/**
 * A `User` with every *declared* field set. `User` also carries an index
 * signature for Store-specific claims, which no schema can enumerate — and
 * `UserEntrySchema` is `.catchall(z.unknown())` rather than `.strict()` for
 * that reason. So the check here is the round-trip, not the refusal.
 */
const FULLY_POPULATED_USER = {
	id: "u-1",
	username: "alice",
	email: "alice@example.com",
	emailVerified: true,
	name: "Alice Example",
	picture: "https://example.com/alice.png",
	groups: ["staff"],
} satisfies Omit<User, "password"> & Record<string, unknown>;

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
