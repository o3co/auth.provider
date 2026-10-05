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

import { decodeJwt, decodeProtectedHeader } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_CLOCK_SKEW_MS } from "#/jwt/verify.mjs";
import { createSymmetricKeyStore } from "#/keys/KeyStore.mjs";
import { generateIdToken } from "../idToken.mjs";

describe("generateIdToken", () => {
	const keyStore = createSymmetricKeyStore("test-secret-32-chars-xxxxxxxxxxxx");

	it("emits typ: JWT header (standard spelling, disjoint from at+jwt)", async () => {
		const { token } = await generateIdToken({
			sub: "u-1",
			aud: "client-1",
			authTime: new Date("2026-04-21T00:00:00Z"),
			sid: "sid-1",
			scopes: ["openid"],
			userClaims: {},
			keyStore,
			issuer: "https://auth.example.com",
		});
		expect(decodeProtectedHeader(token).typ).toBe("JWT");
	});

	it("carries the required OIDC claims (iss, sub, aud, exp, iat, auth_time, sid)", async () => {
		const { token } = await generateIdToken({
			sub: "u-1",
			aud: "client-1",
			authTime: new Date("2026-04-21T00:00:00Z"),
			sid: "sid-1",
			scopes: ["openid"],
			userClaims: {},
			keyStore,
			issuer: "https://auth.example.com",
		});
		const payload = decodeJwt(token);
		expect(payload.iss).toBe("https://auth.example.com");
		expect(payload.sub).toBe("u-1");
		expect(payload.aud).toBe("client-1");
		expect(typeof payload.exp).toBe("number");
		expect(typeof payload.iat).toBe("number");
		expect(payload.auth_time).toBe(Math.floor(new Date("2026-04-21T00:00:00Z").getTime() / 1000));
		expect(payload.sid).toBe("sid-1");
	});

	it("includes nonce when provided", async () => {
		const { token } = await generateIdToken({
			sub: "u",
			aud: "c",
			authTime: new Date(),
			sid: "s",
			scopes: ["openid"],
			userClaims: {},
			keyStore,
			issuer: "https://auth.example.com",
			nonce: "client-nonce-123",
		});
		expect(decodeJwt(token).nonce).toBe("client-nonce-123");
	});

	it("omits nonce when absent", async () => {
		const { token } = await generateIdToken({
			sub: "u",
			aud: "c",
			authTime: new Date(),
			sid: "s",
			scopes: ["openid"],
			userClaims: {},
			keyStore,
			issuer: "https://auth.example.com",
		});
		expect(decodeJwt(token).nonce).toBeUndefined();
	});

	it("filters userClaims by scope (profile → name/picture)", async () => {
		const { token } = await generateIdToken({
			sub: "u",
			aud: "c",
			authTime: new Date(),
			sid: "s",
			scopes: ["openid", "profile"],
			userClaims: { name: "Alice", picture: "https://p", email: "hidden@x.com" },
			keyStore,
			issuer: "iss",
		});
		const p = decodeJwt(token);
		expect(p.name).toBe("Alice");
		expect(p.picture).toBe("https://p");
		expect(p.email).toBeUndefined();
	});

	it("adds azp claim when provided (distinct from aud, per OIDC 1.0 §2)", async () => {
		const { token } = await generateIdToken({
			sub: "u",
			aud: "c",
			authTime: new Date(),
			sid: "s",
			scopes: ["openid"],
			userClaims: {},
			keyStore,
			issuer: "iss",
			azp: "c",
		});
		expect(decodeJwt(token).azp).toBe("c");
	});

	it("defaults expiresIn to 3600 seconds", async () => {
		const { token, expiresIn } = await generateIdToken({
			sub: "u",
			aud: "c",
			authTime: new Date(),
			sid: "s",
			scopes: ["openid"],
			userClaims: {},
			keyStore,
			issuer: "iss",
		});
		expect(expiresIn).toBe(3600);
		const p = decodeJwt(token);
		expect((p.exp as number) - (p.iat as number)).toBe(3600);
	});

	it("respects custom expiresIn", async () => {
		const { token, expiresIn } = await generateIdToken({
			sub: "u",
			aud: "c",
			authTime: new Date(),
			sid: "s",
			scopes: ["openid"],
			userClaims: {},
			keyStore,
			issuer: "iss",
			expiresIn: 600,
		});
		expect(expiresIn).toBe(600);
		const p = decodeJwt(token);
		expect((p.exp as number) - (p.iat as number)).toBe(600);
	});
});

describe("generateIdToken — auth_time", () => {
	const keyStore = createSymmetricKeyStore("test-secret-32-chars-xxxxxxxxxxxx");
	const nowMs = Date.UTC(2026, 9, 1, 12, 0, 0, 500);
	const mint = (authTime: Date) =>
		generateIdToken({
			sub: "u-1",
			aud: "client-1",
			authTime,
			sid: "sid-1",
			scopes: ["openid"],
			userClaims: {},
			keyStore,
			issuer: "https://auth.example.com",
		});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("stamps an authentication instant ahead of the clock by up to DEFAULT_CLOCK_SKEW_MS as iat, never later", async () => {
		vi.useFakeTimers({ toFake: ["Date"], now: nowMs });
		const { token } = await mint(new Date(nowMs + DEFAULT_CLOCK_SKEW_MS));
		const payload = decodeJwt(token);
		expect(payload.iat).toBe(Math.floor(nowMs / 1000));
		expect(payload.auth_time).toBe(payload.iat);
	});

	it("refuses with a RangeError an authentication instant ahead of the clock by more than DEFAULT_CLOCK_SKEW_MS", async () => {
		vi.useFakeTimers({ toFake: ["Date"], now: nowMs });
		await expect(mint(new Date(nowMs + DEFAULT_CLOCK_SKEW_MS + 1))).rejects.toThrow(RangeError);
	});

	it.each([
		["a Date that is not valid", new Date("not a date")],
		["an instant before the epoch", new Date(-1_500)],
	])(
		"refuses with a RangeError an authentication instant auth_time cannot say: %s",
		async (_label, authTime) => {
			// OIDC Core §2 requires `auth_time` when `max_age` was asked, and this
			// id_token always carries it: one it cannot say is not minted.
			await expect(
				generateIdToken({
					sub: "u-1",
					aud: "client-1",
					authTime,
					sid: "sid-1",
					scopes: ["openid"],
					userClaims: {},
					keyStore,
					issuer: "https://auth.example.com",
				}),
			).rejects.toThrow(RangeError);
		},
	);
});

describe("generateIdToken — amr / acr", () => {
	const keyStore = createSymmetricKeyStore("test-secret-32-chars-xxxxxxxxxxxx");
	const base = {
		sub: "u-1",
		aud: "client-1",
		authTime: new Date("2026-04-21T00:00:00Z"),
		sid: "sid-1",
		scopes: ["openid"],
		userClaims: {},
		keyStore,
		issuer: "https://auth.example.com",
	};
	const payload = (token: string): Record<string, unknown> =>
		JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"));

	it("carries amr and acr when the session recorded them", async () => {
		const { token } = await generateIdToken({
			...base,
			amr: ["pwd", "mfa"],
			acr: "urn:example:mfa",
		});
		expect(payload(token).amr).toEqual(["pwd", "mfa"]);
		expect(payload(token).acr).toBe("urn:example:mfa");
	});

	it("omits both when absent — an empty amr is absent, not []", async () => {
		const plain = payload((await generateIdToken(base)).token);
		expect(plain.amr).toBeUndefined();
		expect(plain.acr).toBeUndefined();
		expect(payload((await generateIdToken({ ...base, amr: [] })).token).amr).toBeUndefined();
	});
});

describe("generateIdToken — issuedAt", () => {
	const keyStore = createSymmetricKeyStore("test-secret-32-chars-xxxxxxxxxxxx");
	// The clock runs well past the issuance instant, so a claim read off the
	// clock instead of `issuedAt` shows.
	const issuedAt = 1_790_000_000;
	const clockMs = (issuedAt + 120) * 1000 + 500;
	const base = {
		sub: "u-1",
		aud: "client-1",
		authTime: new Date((issuedAt - 60) * 1000),
		sid: "sid-1",
		scopes: ["openid"],
		userClaims: {},
		keyStore,
		issuer: "https://auth.example.com",
	};

	afterEach(() => {
		vi.useRealTimers();
	});

	it("signs iat as issuedAt and measures exp from it", async () => {
		vi.useFakeTimers({ toFake: ["Date"], now: clockMs });
		const { token } = await generateIdToken({ ...base, issuedAt, expiresIn: 600 });
		const payload = decodeJwt(token);
		expect(payload.iat).toBe(issuedAt);
		expect(payload.exp).toBe(issuedAt + 600);
		expect(payload.auth_time).toBe(issuedAt - 60);
	});

	it("reads auth_time against issuedAt: an instant up to DEFAULT_CLOCK_SKEW_MS past it is issuedAt", async () => {
		vi.useFakeTimers({ toFake: ["Date"], now: clockMs });
		const { token } = await generateIdToken({
			...base,
			authTime: new Date(issuedAt * 1000 + DEFAULT_CLOCK_SKEW_MS),
			issuedAt,
		});
		const payload = decodeJwt(token);
		expect(payload.iat).toBe(issuedAt);
		expect(payload.auth_time).toBe(issuedAt);
	});

	it("reads auth_time against issuedAt: an instant further past it is a RangeError, though the clock is later", async () => {
		vi.useFakeTimers({ toFake: ["Date"], now: clockMs });
		const authTime = new Date(issuedAt * 1000 + DEFAULT_CLOCK_SKEW_MS + 1);
		// The same instant reads fine against the clock ...
		await expect(generateIdToken({ ...base, authTime })).resolves.toBeDefined();
		// ... and not against the issuance instant.
		await expect(generateIdToken({ ...base, authTime, issuedAt })).rejects.toThrow(RangeError);
	});

	it("refuses an issuedAt that is not a whole number of epoch seconds", async () => {
		const sign = vi.spyOn(keyStore, "sign");
		for (const bad of [Number.NaN, 1.5, -1, Number.POSITIVE_INFINITY]) {
			await expect(generateIdToken({ ...base, issuedAt: bad }), String(bad)).rejects.toThrow(
				/issuedAt/,
			);
		}
		expect(sign).not.toHaveBeenCalled();
		sign.mockRestore();
	});

	it("refuses an issuedAt whose exp would pass Number.MAX_SAFE_INTEGER", async () => {
		await expect(
			generateIdToken({
				...base,
				authTime: new Date(0),
				issuedAt: Number.MAX_SAFE_INTEGER - 10,
				expiresIn: 60,
			}),
		).rejects.toThrow(RangeError);
	});

	it("takes iat from the clock when issuedAt is omitted", async () => {
		vi.useFakeTimers({ toFake: ["Date"], now: clockMs });
		const { token } = await generateIdToken(base);
		const payload = decodeJwt(token);
		expect(payload.iat).toBe(Math.floor(clockMs / 1000));
		expect(payload.exp).toBe(Math.floor(clockMs / 1000) + 3600);
		expect(payload.auth_time).toBe(issuedAt - 60);
	});
});
