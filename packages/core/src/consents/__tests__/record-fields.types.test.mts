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
 * A consent store cannot hand back a record that has lost a field (#626).
 *
 * Both records are copied field by field wherever a store reads them back,
 * and a field a copy forgets is dropped without a sound:
 *
 * - `ConsentRecord.expiresAt` gone reads as "until revoked", so a consent
 *   that was meant to lapse never does — the one field whose absence WIDENS
 *   what the record grants.
 * - `PendingConsentRecord.state` gone takes `state` off the denial redirect,
 *   and the client's CSRF check refuses the user's own "no" (RFC 6749
 *   §4.1.2.1: `state` is REQUIRED there when the request carried one).
 *
 * So every field is a REQUIRED key, holding `undefined` where there is no
 * expiry or no `state`; a copy that forgets one fails to compile.
 *
 * Asserted with conditional types rather than `@ts-expect-error`. This file
 * only proves anything under the TypeScript checker, and is on BOTH of core's
 * typecheck lists for that reason.
 */

import { describe, expectTypeOf, it } from "vitest";
import type { ConsentRecord, PendingConsentRecord } from "#/consents/types.mjs";

/** `true` when `K` must be present on `T` — not merely declared. */
type IsRequiredKey<T, K extends keyof T> = Record<never, never> extends Pick<T, K> ? false : true;

/** The keys of `T` that may be left out of an object literal. */
type OptionalKeys<T> = { [K in keyof T]-?: IsRequiredKey<T, K> extends true ? never : K }[keyof T];

describe("ConsentRecord", () => {
	it("has no optional key", () => {
		expectTypeOf<OptionalKeys<ConsentRecord>>().toEqualTypeOf<never>();
	});

	it("names expiresAt, so a failure says which field regressed", () => {
		expectTypeOf<IsRequiredKey<ConsentRecord, "expiresAt">>().toEqualTypeOf<true>();
	});

	it("still records consent until revoked, as undefined", () => {
		expectTypeOf<ConsentRecord["expiresAt"]>().toEqualTypeOf<number | undefined>();
	});
});

describe("PendingConsentRecord", () => {
	it("has no optional key", () => {
		expectTypeOf<OptionalKeys<PendingConsentRecord>>().toEqualTypeOf<never>();
	});

	it("names state, so a failure says which field regressed", () => {
		expectTypeOf<IsRequiredKey<PendingConsentRecord, "state">>().toEqualTypeOf<true>();
	});

	it("still parks a request that carried no state, as undefined", () => {
		expectTypeOf<PendingConsentRecord["state"]>().toEqualTypeOf<string | undefined>();
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
