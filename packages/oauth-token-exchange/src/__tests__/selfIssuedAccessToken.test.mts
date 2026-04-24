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

import { describe, expect, it, vi } from "vitest";
import { createSelfIssuedAccessTokenValidator } from "#/validator/selfIssuedAccessToken.mjs";
import { ISSUER, keyStore, makeRefreshStore, signSelfIssuedAccessToken } from "./fixtures.mjs";

describe("createSelfIssuedAccessTokenValidator", () => {
	const validator = (overrides = {}) =>
		createSelfIssuedAccessTokenValidator({
			keyStore,
			refreshTokenStore: makeRefreshStore(),
			issuer: ISSUER,
			...overrides,
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
		const token = await signSelfIssuedAccessToken({}, { expiresIn: "-1s" });
		const result = await validator().validate(token, { role: "subject" });
		expect(result).toBeNull();
	});

	it("returns null when issuer does not match the configured issuer", async () => {
		const token = await signSelfIssuedAccessToken({ iss: "https://other.example" });
		const result = await validator().validate(token, { role: "subject" });
		expect(result).toBeNull();
	});

	it("returns null when family is revoked", async () => {
		const token = await signSelfIssuedAccessToken({ family_id: "fam-revoked" });
		const store = makeRefreshStore({
			isFamilyRevoked: vi.fn().mockResolvedValue(true),
		});
		const v = validator({ refreshTokenStore: store });
		expect(await v.validate(token, { role: "subject" })).toBeNull();
		expect(store.isFamilyRevoked).toHaveBeenCalledWith("fam-revoked");
	});

	it("throws when isFamilyRevoked throws (runtime unavailable)", async () => {
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const store = makeRefreshStore({
			isFamilyRevoked: vi.fn().mockRejectedValue(new Error("redis down")),
		});
		const v = validator({ refreshTokenStore: store });
		await expect(v.validate(token, { role: "subject" })).rejects.toThrow("redis down");
	});

	it("accepts a token without family_id claim (legacy) when refreshTokenStore is present", async () => {
		const token = await signSelfIssuedAccessToken({});
		const store = makeRefreshStore();
		const v = validator({ refreshTokenStore: store });
		const result = await v.validate(token, { role: "subject" });
		expect(result).not.toBeNull();
		expect(result?.familyId).toBeUndefined();
	});

	it("preserves existing act claim on the token", async () => {
		const token = await signSelfIssuedAccessToken({ act: { sub: "service-upstream" } });
		const result = await validator().validate(token, { role: "subject" });
		expect(result?.act).toEqual({ sub: "service-upstream" });
	});
});
