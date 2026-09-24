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

import { isVerificationUnavailable } from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import { createSelfIssuedAccessTokenValidator } from "#/validator/selfIssuedAccessToken.mjs";
import { ISSUER, keyStore, makeFamilyRevocation, signSelfIssuedAccessToken } from "./fixtures.mjs";

describe("createSelfIssuedAccessTokenValidator", () => {
	const validator = (overrides = {}) =>
		createSelfIssuedAccessTokenValidator({
			keyStore,
			issuer: ISSUER,
			...overrides,
		});

	it("throws when issuer is missing from validator options", () => {
		expect(() =>
			// @ts-expect-error — `issuer` is omitted on purpose: the runtime refusal
			// for a caller the types cannot reach is what this asserts.
			createSelfIssuedAccessTokenValidator({
				keyStore,
			}),
		).toThrow("issuer is required");
	});

	it("accepts a valid self-issued at+jwt and returns claims", async () => {
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const result = await validator().validate(token, { role: "subject" });
		expect(result).not.toBeNull();
		expect(result?.sub).toBe("user-1");
		expect(result?.scope).toBe("read");
		expect(result?.familyId).toBe("fam-1");
	});

	it("returns null for a tampered signature", async () => {
		const token = `${(await signSelfIssuedAccessToken({})).slice(0, -4)}AAAA`;
		const result = await validator().validate(token, { role: "subject" });
		expect(result).toBeNull();
	});

	it("returns null for an expired token", async () => {
		// SF-1: the central verifier defaults clockSkewMs to 300_000 (5 min)
		// per RFC 8725 §3.10, so a "-1s" past exp falls inside skew. Use a
		// past exp well beyond the default skew so the rejection is robust.
		const token = await signSelfIssuedAccessToken({}, { expiresIn: "-10m" });
		const result = await validator().validate(token, { role: "subject" });
		expect(result).toBeNull();
	});

	it("returns null when issuer does not match the configured issuer", async () => {
		const token = await signSelfIssuedAccessToken({ iss: "https://other.example" });
		const result = await validator().validate(token, { role: "subject" });
		expect(result).toBeNull();
	});

	it("refuses a refreshTokenFamilyRevocation option rather than ignoring it", () => {
		// The family rule is the grant's: were the validator to refuse a revoked
		// family, it would answer first with an opaque `null` and the grant's
		// `family_revoked` would never reach a client (`grant-integration.test.mts`
		// pins that answer through the booted module). So the option is gone —
		// and ignored silently, a caller that relied on it from JavaScript, an
		// options object built as a variable or a cast would lose the family
		// check with no signal. Its presence is refused at construction, even
		// with no value, since the caller still expected the check.
		const store = makeFamilyRevocation({
			isFamilyRevoked: vi.fn().mockResolvedValue(true),
		});
		expect(() =>
			createSelfIssuedAccessTokenValidator({
				keyStore,
				issuer: ISSUER,
				// @ts-expect-error — not an option: the grant owns the family check.
				refreshTokenFamilyRevocation: store,
			}),
		).toThrow(/refreshTokenFamilyRevocation is not an option/);

		const optionsBuiltElsewhere: Record<string, unknown> = {
			keyStore,
			issuer: ISSUER,
			refreshTokenFamilyRevocation: undefined,
		};
		expect(() =>
			createSelfIssuedAccessTokenValidator(
				optionsBuiltElsewhere as unknown as Parameters<
					typeof createSelfIssuedAccessTokenValidator
				>[0],
			),
		).toThrow(/refreshTokenFamilyRevocation is not an option/);
		expect(store.isFamilyRevoked).not.toHaveBeenCalled();
	});

	it("does not compile a deps bag carrying refreshTokenFamilyRevocation spread into its options", () => {
		// `refreshTokenFamilyRevocation?: never` in the options type: the likely
		// way to pass the removed option by accident — spreading a deps object
		// into the options — fails to compile, ahead of the runtime refusal a
		// JavaScript caller still gets.
		const deps: { keyStore: typeof keyStore; refreshTokenFamilyRevocation: unknown } = {
			keyStore,
			refreshTokenFamilyRevocation: makeFamilyRevocation(),
		};
		expect(() =>
			// @ts-expect-error — the spread carries `refreshTokenFamilyRevocation`, typed `never`.
			createSelfIssuedAccessTokenValidator({ ...deps, issuer: ISSUER }),
		).toThrow(/refreshTokenFamilyRevocation is not an option/);
	});

	it("accepts a token without a family_id claim, leaving familyId absent", async () => {
		const token = await signSelfIssuedAccessToken({});
		const result = await validator().validate(token, { role: "subject" });
		expect(result).not.toBeNull();
		expect(result?.familyId).toBeUndefined();
	});

	it("preserves existing act claim on the token", async () => {
		const token = await signSelfIssuedAccessToken({ act: { sub: "service-upstream" } });
		const result = await validator().validate(token, { role: "subject" });
		expect(result?.act).toEqual({ sub: "service-upstream" });
	});

	it("projects may_act only when every array entry is an object", async () => {
		const valid = await signSelfIssuedAccessToken({ may_act: [{ sub: "svc-a" }] });
		const validResult = await validator().validate(valid, { role: "subject" });
		expect(validResult?.may_act).toEqual([{ sub: "svc-a" }]);

		const mixed = await signSelfIssuedAccessToken({ may_act: [{ sub: "svc-a" }, "svc-b"] });
		const mixedResult = await validator().validate(mixed, { role: "subject" });
		expect(mixedResult).not.toBeNull();
		expect(mixedResult?.claims.may_act).toEqual([{ sub: "svc-a" }, "svc-b"]);
		expect(mixedResult?.may_act).toBeUndefined();
	});

	it("applies identical validation for role=actor (does not branch on role)", async () => {
		const token = await signSelfIssuedAccessToken({});
		const result = await validator().validate(token, { role: "actor" });
		expect(result).not.toBeNull();
		expect(result?.sub).toBe("user-1");
	});

	it("returns null when sub claim is missing", async () => {
		const token = await signSelfIssuedAccessToken({ sub: undefined });
		const result = await validator().validate(token, { role: "subject" });
		expect(result).toBeNull();
	});

	it("returns null when sub claim is empty string", async () => {
		const token = await signSelfIssuedAccessToken({ sub: "" });
		const result = await validator().validate(token, { role: "subject" });
		expect(result).toBeNull();
	});

	it("ignores payload.act when it is an array (non-plain-object guard)", async () => {
		const token = await signSelfIssuedAccessToken({ act: [{ sub: "svc-a" }] });
		const result = await validator().validate(token, { role: "subject" });
		expect(result).not.toBeNull();
		expect(result?.act).toBeUndefined();
	});

	it("returns null when typ header is not at+jwt (rejects id_token/logout_token/generic JWT)", async () => {
		// Token signed with the same KeyStore but with typ=JWT (would be a
		// generic id_token or developer-minted JWT). This scenario exists in
		// real deployments where the KeyStore is shared across at+jwt issuance
		// and id_token issuance.
		const generic = await signSelfIssuedAccessToken({}, { typ: "JWT" });
		expect(await validator().validate(generic, { role: "subject" })).toBeNull();

		const idToken = await signSelfIssuedAccessToken({}, { typ: "id+jwt" });
		expect(await validator().validate(idToken, { role: "subject" })).toBeNull();

		const logoutToken = await signSelfIssuedAccessToken({}, { typ: "logout+jwt" });
		expect(await validator().validate(logoutToken, { role: "subject" })).toBeNull();
	});

	it("returns null for a subject_token whose jti is on the denylist (#367)", async () => {
		// The laundering path: revoke an AT, exchange it, keep an equivalent.
		// A revoked subject_token must not mint a fresh token.
		const token = await signSelfIssuedAccessToken({ jti: "at-revoked" });
		const denylist = {
			kind: "stub",
			add: async () => {},
			has: async (jti: string) => jti === "at-revoked",
		};
		const v = validator({ accessTokenDenylist: denylist });
		expect(await v.validate(token, { role: "subject" })).toBeNull();

		// Same denylist, different jti: still exchangeable.
		const live = await signSelfIssuedAccessToken({ jti: "at-live" });
		expect(await v.validate(live, { role: "subject" })).not.toBeNull();
	});

	it("returns null for a subject_token issued before the subject watermark (#367)", async () => {
		const token = await signSelfIssuedAccessToken({ sub: "u-reset" });
		const subjectRevocation = {
			kind: "stub",
			revokeBefore: async () => {},
			// Watermark far in the future: every token this subject holds is out.
			revokedBefore: async (sub: string) =>
				sub === "u-reset" ? new Date(Date.now() + 86_400_000) : null,
		};
		const v = validator({ subjectRevocation });
		expect(await v.validate(token, { role: "subject" })).toBeNull();
	});

	it("throws, rather than returning null, when a revocation store cannot be read", async () => {
		// Core's contract: null is a verdict on the token (→ invalid_request), a
		// throw is an answer that is not knowable (→ 503). An outage is the
		// second — the verifier's `revocation_unavailable` — for either store.
		const token = await signSelfIssuedAccessToken({ jti: "at-1" });
		const unreachable = async () => {
			throw new Error("backend unreachable");
		};
		const denylist = { kind: "stub", add: async () => {}, has: unreachable };
		await expect(
			validator({ accessTokenDenylist: denylist }).validate(token, { role: "subject" }),
		).rejects.toSatisfy(isVerificationUnavailable);

		const subjectRevocation = {
			kind: "stub",
			revokeBefore: async () => {},
			revokedBefore: unreachable,
		};
		await expect(
			validator({ subjectRevocation }).validate(token, { role: "actor" }),
		).rejects.toSatisfy(isVerificationUnavailable);
	});
});
