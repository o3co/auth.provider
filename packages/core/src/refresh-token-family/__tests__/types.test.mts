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
	RefreshTokenFamilyRotation,
	RefreshTokenFamilyRotationOutcome,
	RefreshTokenFamilyStore,
	RefreshTokenFamilyUpdateDecision,
	RefreshTokenFamilyUpdateResult,
} from "../types.mjs";

test("RefreshTokenFamily fields are readonly with correct types", () => {
	expectTypeOf<RefreshTokenFamily>().toEqualTypeOf<{
		readonly familyId: string;
		readonly activeJti: string;
		readonly revoked: boolean;
		readonly expiresAtMs: number;
	}>();
});

// #274: the updater's decision is a 2-variant union carrying an opaque
// `reason`, replacing the pre-#274 `RefreshTokenFamily | null`. `null` meant
// both "write nothing" and "the precondition failed", which left no way to
// describe a commit that is itself a rejection (a replay revocation).
test("RefreshTokenFamilyUpdateDecision is a 2-variant discriminated union carrying an opaque reason", () => {
	expectTypeOf<RefreshTokenFamilyUpdateDecision>().toEqualTypeOf<
		| {
				readonly action: "commit";
				readonly family: RefreshTokenFamily;
				readonly reason?: string;
		  }
		| { readonly action: "abort"; readonly reason?: string }
	>();
});

test("RefreshTokenFamilyUpdateResult is a 3-variant discriminated union", () => {
	// `reason` is echoed on both settleable outcomes. It is absent on
	// "not-found", where the updater was never invoked and so made no decision.
	expectTypeOf<RefreshTokenFamilyUpdateResult>().toEqualTypeOf<
		| {
				readonly outcome: "committed";
				readonly family: RefreshTokenFamily;
				readonly reason?: string;
		  }
		| { readonly outcome: "not-found" }
		| { readonly outcome: "aborted"; readonly reason?: string }
	>();
});

test("RefreshTokenFamilyStore exposes 3 methods + readonly kind", () => {
	type StoreShape = {
		readonly kind: string;
		registerFamily(family: RefreshTokenFamily): Promise<void>;
		findFamily(familyId: string): Promise<RefreshTokenFamily | null>;
		updateFamily(
			familyId: string,
			updater: (current: RefreshTokenFamily) => RefreshTokenFamilyUpdateDecision,
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

test("RefreshTokenFamilyRotationOutcome is a 4-variant discriminated union", () => {
	// IH-13 (v0.5.1): "rotated" variant carries optional `cappedExpiresAtMs`.
	// Optional, not required, so existing stubs returning `{ outcome: "rotated" }`
	// without the field continue to type-check (Codex Delta 2).
	//
	// #274: "replayed" carries optional `familyRevoked`, on the same
	// compatibility grounds — a custom rotation predating #274 reports a bare
	// `{ outcome: "replayed" }`, and the caller reads absence as "not revoked"
	// and revokes separately.
	expectTypeOf<RefreshTokenFamilyRotationOutcome>().toEqualTypeOf<
		| { readonly outcome: "rotated"; readonly cappedExpiresAtMs?: number }
		| { readonly outcome: "replayed"; readonly familyRevoked?: boolean }
		| { readonly outcome: "revoked" }
		| { readonly outcome: "unknown_family" }
	>();
});

test("RefreshTokenFamilyRotation exposes register and rotate methods", () => {
	type RotationShape = {
		register(newJti: string, familyId: string, expiresAtMs: number): Promise<void>;
		rotate(
			previousJti: string,
			newJti: string,
			familyId: string,
			expiresAtMs: number,
		): Promise<RefreshTokenFamilyRotationOutcome>;
	};
	expectTypeOf<RefreshTokenFamilyRotation>().toEqualTypeOf<RotationShape>();
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
	expectTypeOf<ComponentMap["refreshTokenFamilyRotation"]>().toEqualTypeOf<
		RefreshTokenFamilyRotation | undefined
	>();
	expectTypeOf<ComponentMap["refreshTokenFamilyRevocation"]>().toEqualTypeOf<
		RefreshTokenFamilyRevocation | undefined
	>();
});
