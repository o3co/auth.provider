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
 * A grant store's copy of a grant cannot leave a field out and still compile,
 * for a copy built as an object literal of the record type; not for one
 * behind a cast, one that names a field with the wrong value, or a write that
 * spreads the old record and forgets to clear one.
 *
 * Both bundled stores copy these fields, and a forgotten field is dropped
 * silently. Three widen what the grant does when lost (see ADR
 * 2026-09-17-federation-grants-offline-delegation, D5 and D12):
 *
 * - `resource` gone: the upstream is asked for a token without the RFC 8707
 *   audience the connection narrows it to; whether it then issues a wider
 *   token, applies its own default or refuses is the upstream's call.
 * - `ineligible` gone: a grant whose upstream keeps issuing tokens that cannot
 *   be disclosed is refreshed whenever a refresh is otherwise due, instead of
 *   once the marker's interval has passed: a lock and a refresh-token
 *   rotation on each such request.
 * - `refreshFailure` gone: a failing upstream is asked again whenever a
 *   refresh is otherwise due, instead of after its backoff, and a stamp that
 *   says the user has to come back stops saying it. Its `retryAfterSeconds`
 *   alone gone, on a `rate_limited` stamp: the default backoff applies
 *   instead of the longer of it and the upstream's `Retry-After`, both held
 *   to the ceiling.
 *
 * So every field of the authorization, the usage, the failure stamp and the
 * credentials is a required key, holding `undefined` where there is none.
 * Asserted with conditional types rather than `@ts-expect-error`; this file
 * proves anything only under the TypeScript checker, so it is on both of
 * core's typecheck lists.
 */

import { describe, expectTypeOf, it } from "vitest";
import type { federationGrantAccessToken } from "#/federation-grants/held-token.mjs";
import type { FederationGrantStore } from "#/federation-grants/store.mjs";
import type {
	FederationGrantAuthorization,
	FederationGrantBase,
	FederationGrantConsent,
	FederationGrantCredentials,
	FederationGrantIneligibilityMarker,
	FederationGrantRefreshFailure,
	FederationGrantRefreshFailureInput,
	FederationGrantRotations,
	FederationGrantUsage,
} from "#/federation-grants/types.mjs";

/** `true` when `K` must be present on `T` — not merely declared. */
type IsRequiredKey<T, K extends keyof T> = Record<never, never> extends Pick<T, K> ? false : true;

/** The keys of `T` that may be left out of an object literal. */
type OptionalKeys<T> = { [K in keyof T]-?: IsRequiredKey<T, K> extends true ? never : K }[keyof T];

type AccessToken = Exclude<FederationGrantCredentials["accessToken"], undefined>;

describe("what a grant store answers with", () => {
	it("names every field of the authorization", () => {
		expectTypeOf<OptionalKeys<FederationGrantAuthorization>>().toEqualTypeOf<never>();
		expectTypeOf<IsRequiredKey<FederationGrantAuthorization, "resource">>().toEqualTypeOf<true>();
		expectTypeOf<FederationGrantAuthorization["resource"]>().toEqualTypeOf<string | undefined>();
	});

	it("names every usage field, the rotation budget included", () => {
		expectTypeOf<OptionalKeys<FederationGrantUsage>>().toEqualTypeOf<never>();
		expectTypeOf<OptionalKeys<FederationGrantRotations>>().toEqualTypeOf<never>();
		expectTypeOf<IsRequiredKey<FederationGrantUsage, "lastUsedAt">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<FederationGrantUsage, "ineligible">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<FederationGrantUsage, "refreshFailure">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<FederationGrantUsage, "rotations">>().toEqualTypeOf<true>();
		expectTypeOf<FederationGrantUsage["rotations"]>().toEqualTypeOf<
			FederationGrantRotations | undefined
		>();
	});

	it("names every field of the failure stamp", () => {
		expectTypeOf<OptionalKeys<FederationGrantRefreshFailure>>().toEqualTypeOf<never>();
		expectTypeOf<
			IsRequiredKey<FederationGrantRefreshFailure, "retryAfterSeconds">
		>().toEqualTypeOf<true>();
		expectTypeOf<
			IsRequiredKey<FederationGrantRefreshFailure, "upstreamCode">
		>().toEqualTypeOf<true>();
	});

	it("has no optional key anywhere else in the record either", () => {
		// None has one today; a `?:` added to any would be a field a copy could
		// drop without a sound.
		expectTypeOf<OptionalKeys<FederationGrantBase>>().toEqualTypeOf<never>();
		expectTypeOf<OptionalKeys<FederationGrantConsent>>().toEqualTypeOf<never>();
		expectTypeOf<OptionalKeys<FederationGrantIneligibilityMarker>>().toEqualTypeOf<never>();
	});

	it("names the access token, and every field of one", () => {
		expectTypeOf<OptionalKeys<FederationGrantCredentials>>().toEqualTypeOf<never>();
		expectTypeOf<IsRequiredKey<FederationGrantCredentials, "accessToken">>().toEqualTypeOf<true>();
		// The one optional key: a record from before it existed, or rewritten by
		// a release that does not keep it, has none, and reads as ending at
		// `obtainedAt` + `issuedLifetime`.
		expectTypeOf<OptionalKeys<AccessToken>>().toEqualTypeOf<"effectiveExpiresAt">();
	});
});

type Written<T extends { readonly credentials: { readonly accessToken: unknown } }> = Exclude<
	T["credentials"]["accessToken"],
	undefined
>;

describe("what a writer hands a grant store", () => {
	// Leaving `effectiveExpiresAt` out fails open, serving a token past its
	// adapter's stated end; every write states it.
	it("states when the access token ends, on an activation", () => {
		type Token = Written<Parameters<FederationGrantStore["activate"]>[0]>;
		expectTypeOf<OptionalKeys<Token>>().toEqualTypeOf<never>();
		expectTypeOf<Token["effectiveExpiresAt"]>().toEqualTypeOf<Date>();
	});

	it("states when the access token ends, on a refresh", () => {
		type Token = Written<Parameters<FederationGrantStore["replaceCredentials"]>[0]>;
		expectTypeOf<OptionalKeys<Token>>().toEqualTypeOf<never>();
		expectTypeOf<Token["effectiveExpiresAt"]>().toEqualTypeOf<Date>();
	});

	it("is what the access-token builder returns", () => {
		type Token = ReturnType<typeof federationGrantAccessToken>;
		expectTypeOf<OptionalKeys<Token>>().toEqualTypeOf<never>();
		expectTypeOf<Token["effectiveExpiresAt"]>().toEqualTypeOf<Date>();
	});
});

describe("what a grant store implements", () => {
	// A store without the take keeps no rotation budget, and one without the
	// give-back keeps every rotation it took: neither compiles as the port.
	it("takes and gives back a rotation", () => {
		expectTypeOf<IsRequiredKey<FederationGrantStore, "takeRotation">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<FederationGrantStore, "refundRotation">>().toEqualTypeOf<true>();
	});
});

describe("what a refresh reports of its failure", () => {
	it("keeps retryAfterSeconds and upstreamCode optional — a classifier writes it", () => {
		expectTypeOf<OptionalKeys<FederationGrantRefreshFailureInput>>().toEqualTypeOf<
			"retryAfterSeconds" | "upstreamCode"
		>();
	});

	it("names the same fields as the stamp, and the stamp adds only the count", () => {
		// A field added to the report and not to the stamp would be dropped by
		// every store that records it, and nothing would say so.
		expectTypeOf<keyof FederationGrantRefreshFailure>().toEqualTypeOf<
			keyof FederationGrantRefreshFailureInput | "count"
		>();
	});
});

describe("the helper's control", () => {
	it("tells an optional key from a required one", () => {
		// Without this, `IsRequiredKey` answering `true` for everything would
		// pass every assertion above.
		type Probe = { readonly a?: string; readonly b: string | undefined };
		expectTypeOf<IsRequiredKey<Probe, "a">>().toEqualTypeOf<false>();
		expectTypeOf<IsRequiredKey<Probe, "b">>().toEqualTypeOf<true>();
	});
});
