// packages/core/src/grants/__tests__/idToken.test.mts
import { describe, expect, it } from "vitest";
import { createSymmetricKeyStore } from "#/keys/KeyStore.mjs";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { generateIdToken } from "../idToken.mjs";

describe("generateIdToken", () => {
	const keyStore = createSymmetricKeyStore("test-secret-32-chars-xxxxxxxxxxxx");

	it("emits typ: id+jwt header", async () => {
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
		expect(decodeProtectedHeader(token).typ).toBe("id+jwt");
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
			sub: "u", aud: "c", authTime: new Date(), sid: "s", scopes: ["openid"],
			userClaims: {}, keyStore, issuer: "https://auth.example.com",
			nonce: "client-nonce-123",
		});
		expect(decodeJwt(token).nonce).toBe("client-nonce-123");
	});

	it("omits nonce when absent", async () => {
		const { token } = await generateIdToken({
			sub: "u", aud: "c", authTime: new Date(), sid: "s", scopes: ["openid"],
			userClaims: {}, keyStore, issuer: "https://auth.example.com",
		});
		expect(decodeJwt(token).nonce).toBeUndefined();
	});

	it("filters userClaims by scope (profile → name/picture)", async () => {
		const { token } = await generateIdToken({
			sub: "u", aud: "c", authTime: new Date(), sid: "s",
			scopes: ["openid", "profile"],
			userClaims: { name: "Alice", picture: "https://p", email: "hidden@x.com" },
			keyStore, issuer: "iss",
		});
		const p = decodeJwt(token);
		expect(p.name).toBe("Alice");
		expect(p.picture).toBe("https://p");
		expect(p.email).toBeUndefined();
	});

	it("adds azp claim when provided (distinct from aud, per OIDC 1.0 §2)", async () => {
		const { token } = await generateIdToken({
			sub: "u", aud: "c", authTime: new Date(), sid: "s", scopes: ["openid"],
			userClaims: {}, keyStore, issuer: "iss",
			azp: "c",
		});
		expect(decodeJwt(token).azp).toBe("c");
	});

	it("defaults expiresIn to 3600 seconds", async () => {
		const { token, expiresIn } = await generateIdToken({
			sub: "u", aud: "c", authTime: new Date(), sid: "s", scopes: ["openid"],
			userClaims: {}, keyStore, issuer: "iss",
		});
		expect(expiresIn).toBe(3600);
		const p = decodeJwt(token);
		expect((p.exp as number) - (p.iat as number)).toBe(3600);
	});

	it("respects custom expiresIn", async () => {
		const { token, expiresIn } = await generateIdToken({
			sub: "u", aud: "c", authTime: new Date(), sid: "s", scopes: ["openid"],
			userClaims: {}, keyStore, issuer: "iss",
			expiresIn: 600,
		});
		expect(expiresIn).toBe(600);
		const p = decodeJwt(token);
		expect((p.exp as number) - (p.iat as number)).toBe(600);
	});
});
