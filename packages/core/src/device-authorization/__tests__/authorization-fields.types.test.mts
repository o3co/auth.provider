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
 * A device-code store's copy of an authorization cannot leave a field out
 * and still compile (#626) — for a copy built as an object literal of the
 * record type; not for one behind a cast or one that names a field with the
 * wrong value.
 *
 * Both bundled stores copy the record field by field on `create` and on every
 * read, and a field a copy forgot was dropped with no error: `requestedScope`
 * gone from a read shows the user an empty scope, and gone from what `create`
 * stores it grants nothing; `subject` gone makes the grant
 * refuse an approval the user gave; `grantedScope` gone mints a token with no
 * scope, while the verification endpoint's audit event falls back to
 * `requestedScope` and records more than was granted.
 *
 * So what a store answers with names every field as a REQUIRED key, holding
 * `undefined` where there is none — `subject` and `grantedScope` until an
 * approval. What `/device_authorization` writes names `requestedScope` the
 * same way. The approval's own `grantedScope` stays optional: leaving it out
 * is the documented way to grant `requestedScope` whole.
 *
 * Asserted with conditional types rather than `@ts-expect-error`. This file
 * only proves anything under the TypeScript checker, and is on BOTH of core's
 * typecheck lists for that reason.
 */

import { describe, expectTypeOf, it } from "vitest";
import type {
	ApproveDeviceAuthorizationInput,
	CreateDeviceAuthorizationInput,
	DeviceAuthorization,
} from "#/device-authorization/types.mjs";

/** `true` when `K` must be present on `T` — not merely declared. */
type IsRequiredKey<T, K extends keyof T> = Record<never, never> extends Pick<T, K> ? false : true;

/** The keys of `T` that may be left out of an object literal. */
type OptionalKeys<T> = { [K in keyof T]-?: IsRequiredKey<T, K> extends true ? never : K }[keyof T];

describe("DeviceAuthorization — what a store answers with", () => {
	it("has no optional key", () => {
		expectTypeOf<OptionalKeys<DeviceAuthorization>>().toEqualTypeOf<never>();
	});

	it("names each field, so a failure says which one regressed", () => {
		expectTypeOf<IsRequiredKey<DeviceAuthorization, "requestedScope">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<DeviceAuthorization, "subject">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<DeviceAuthorization, "grantedScope">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<DeviceAuthorization, "approvedAtMs">>().toEqualTypeOf<true>();
	});

	it("still lets a field be absent in value, as undefined", () => {
		expectTypeOf<DeviceAuthorization["subject"]>().toEqualTypeOf<string | undefined>();
		expectTypeOf<DeviceAuthorization["grantedScope"]>().toEqualTypeOf<
			readonly string[] | undefined
		>();
		expectTypeOf<DeviceAuthorization["approvedAtMs"]>().toEqualTypeOf<number | undefined>();
	});
});

describe("the inputs", () => {
	it("create names requestedScope", () => {
		expectTypeOf<OptionalKeys<CreateDeviceAuthorizationInput>>().toEqualTypeOf<never>();
	});

	it("approve leaves grantedScope optional — omitted, requestedScope is granted whole", () => {
		expectTypeOf<OptionalKeys<ApproveDeviceAuthorizationInput>>().toEqualTypeOf<"grantedScope">();
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
