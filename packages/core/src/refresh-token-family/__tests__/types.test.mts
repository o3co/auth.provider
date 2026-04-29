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
import { expectTypeOf, test } from "vitest";
import type { ComponentMap } from "../../modules/manifest/component-map.mjs";
import type {
	RefreshTokenFamily,
	RefreshTokenFamilyRevocation,
	RefreshTokenFamilyStore,
	RefreshTokenFamilyUpdateResult,
	RefreshTokenRotation,
	RefreshTokenRotationOutcome,
} from "../types.mjs";

test("RefreshTokenFamily fields are readonly with correct types", () => {
	expectTypeOf<RefreshTokenFamily>().toEqualTypeOf<{
		readonly familyId: string;
		readonly activeJti: string;
		readonly revoked: boolean;
		readonly expiresAtMs: number;
	}>();
});

test("RefreshTokenFamilyUpdateResult is a 3-variant discriminated union", () => {
	expectTypeOf<RefreshTokenFamilyUpdateResult>().toEqualTypeOf<
		| { readonly outcome: "committed"; readonly family: RefreshTokenFamily }
		| { readonly outcome: "not-found" }
		| { readonly outcome: "aborted" }
	>();
});

test("RefreshTokenFamilyStore exposes 3 methods + readonly kind", () => {
	type StoreShape = {
		readonly kind: string;
		registerFamily(family: RefreshTokenFamily): Promise<void>;
		findFamily(familyId: string): Promise<RefreshTokenFamily | null>;
		updateFamily(
			familyId: string,
			updater: (current: RefreshTokenFamily) => RefreshTokenFamily | null,
		): Promise<RefreshTokenFamilyUpdateResult>;
	};
	expectTypeOf<RefreshTokenFamilyStore>().toEqualTypeOf<StoreShape>();
});

test("RefreshTokenFamilyUpdateResult committed variant carries family", () => {
	const r: RefreshTokenFamilyUpdateResult = {
		outcome: "committed",
		family: {
			familyId: "fam-1",
			activeJti: "jti-1",
			revoked: false,
			expiresAtMs: Date.now() + 60_000,
		},
	};
	if (r.outcome === "committed") {
		expectTypeOf(r.family).toEqualTypeOf<RefreshTokenFamily>();
	}
});

test("RefreshTokenRotationOutcome is a 4-variant discriminated union", () => {
	expectTypeOf<RefreshTokenRotationOutcome>().toEqualTypeOf<
		| { readonly outcome: "rotated" }
		| { readonly outcome: "replayed" }
		| { readonly outcome: "revoked" }
		| { readonly outcome: "unknown_family" }
	>();
});

test("RefreshTokenRotation exposes register and rotate methods", () => {
	type RotationShape = {
		register(newJti: string, familyId: string, expiresAtMs: number): Promise<void>;
		rotate(
			previousJti: string,
			newJti: string,
			familyId: string,
			expiresAtMs: number,
		): Promise<RefreshTokenRotationOutcome>;
	};
	expectTypeOf<RefreshTokenRotation>().toEqualTypeOf<RotationShape>();
});

test("RefreshTokenFamilyRevocation exposes revokeFamily + isFamilyRevoked", () => {
	type RevocationShape = {
		revokeFamily(familyId: string): Promise<void>;
		isFamilyRevoked(familyId: string): Promise<boolean>;
	};
	expectTypeOf<RefreshTokenFamilyRevocation>().toEqualTypeOf<RevocationShape>();
});

test("ComponentMap exposes the 3 A3 slots as readonly optional", () => {
	expectTypeOf<ComponentMap["refreshTokenFamilyStore"]>().toEqualTypeOf<
		RefreshTokenFamilyStore | undefined
	>();
	expectTypeOf<ComponentMap["refreshTokenRotation"]>().toEqualTypeOf<
		RefreshTokenRotation | undefined
	>();
	expectTypeOf<ComponentMap["refreshTokenFamilyRevocation"]>().toEqualTypeOf<
		RefreshTokenFamilyRevocation | undefined
	>();
});
