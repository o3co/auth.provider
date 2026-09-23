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
 * An intent store cannot hand back an intent that has lost a field (#626).
 *
 * The intent is what every later step of an acquisition is judged against
 * (D6), and both bundled stores copy it field by field — the memory one on
 * every write and read, the Redis one through its codec, and the transaction
 * carries a snapshot of it. Both optional fields widen the flow when lost:
 *
 * - `resource` gone: the upstream is asked, at authorization and at the code
 *   exchange, without the RFC 8707 audience the connection narrows it to, and
 *   the grant is activated without it.
 * - `upstreamSubject` gone: the callback no longer checks that the upstream
 *   account is the one the client said to expect, and links whichever one the
 *   user signed in with.
 *
 * So every field is a REQUIRED key, holding `undefined` where there is none; a
 * copy that forgets one fails to compile.
 *
 * Asserted with conditional types rather than `@ts-expect-error`. This file
 * only proves anything under the TypeScript checker, and is on BOTH of core's
 * typecheck lists for that reason.
 */

import { describe, expectTypeOf, it } from "vitest";
import type { FederationGrantIntent } from "#/federation-grants/intentStore.mjs";

/** `true` when `K` must be present on `T` — not merely declared. */
type IsRequiredKey<T, K extends keyof T> = Record<never, never> extends Pick<T, K> ? false : true;

/** The keys of `T` that may be left out of an object literal. */
type OptionalKeys<T> = { [K in keyof T]-?: IsRequiredKey<T, K> extends true ? never : K }[keyof T];

describe("FederationGrantIntent — what an intent store answers with", () => {
	it("has no optional key", () => {
		expectTypeOf<OptionalKeys<FederationGrantIntent>>().toEqualTypeOf<never>();
	});

	it("names each field, so a failure says which one regressed", () => {
		expectTypeOf<IsRequiredKey<FederationGrantIntent, "resource">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<FederationGrantIntent, "upstreamSubject">>().toEqualTypeOf<true>();
	});

	it("still lets a field be absent in value, as undefined", () => {
		expectTypeOf<FederationGrantIntent["resource"]>().toEqualTypeOf<string | undefined>();
		expectTypeOf<FederationGrantIntent["upstreamSubject"]>().toEqualTypeOf<string | undefined>();
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
