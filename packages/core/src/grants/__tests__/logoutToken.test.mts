import { decodeJwt, decodeProtectedHeader } from "jose";
import { describe, expect, it } from "vitest";
import { createSymmetricKeyStore } from "#/keys/KeyStore.mjs";
import { generateLogoutToken } from "../logoutToken.mjs";

describe("generateLogoutToken (OIDC Back-Channel Logout 1.0)", () => {
	const keyStore = createSymmetricKeyStore("test-secret-32-chars-xxxxxxxxxx");

	it("emits typ: logout+jwt header", async () => {
		const { token } = await generateLogoutToken({
			issuer: "iss",
			sub: "u",
			aud: "c",
			sid: "s",
			keyStore,
		});
		expect(decodeProtectedHeader(token).typ).toBe("logout+jwt");
	});

	it("includes required claims: iss, sub, aud, iat, jti, events, sid", async () => {
		const { token } = await generateLogoutToken({
			issuer: "https://auth",
			sub: "u-1",
			aud: "rp",
			sid: "sid-1",
			keyStore,
		});
		const p = decodeJwt(token);
		expect(p.iss).toBe("https://auth");
		expect(p.sub).toBe("u-1");
		expect(p.aud).toBe("rp");
		expect(p.sid).toBe("sid-1");
		expect(typeof p.iat).toBe("number");
		expect(typeof p.jti).toBe("string");
		expect(p.events).toEqual({ "http://schemas.openid.net/event/backchannel-logout": {} });
	});

	it("does NOT include nonce claim (spec §2.4 forbids nonce)", async () => {
		const { token } = await generateLogoutToken({
			issuer: "iss",
			sub: "u",
			aud: "c",
			sid: "s",
			keyStore,
		});
		expect((decodeJwt(token) as Record<string, unknown>).nonce).toBeUndefined();
	});

	it("omits sid when includeSid: false (honors backchannelLogoutSessionRequired=false)", async () => {
		const { token } = await generateLogoutToken({
			issuer: "iss",
			sub: "u",
			aud: "c",
			keyStore,
			includeSid: false,
		});
		expect((decodeJwt(token) as Record<string, unknown>).sid).toBeUndefined();
	});

	it("short TTL by default (5 minutes)", async () => {
		const { token } = await generateLogoutToken({
			issuer: "iss",
			sub: "u",
			aud: "c",
			sid: "s",
			keyStore,
		});
		const p = decodeJwt(token);
		expect((p.exp as number) - (p.iat as number)).toBe(300);
	});

	it("throws when sid is empty string and includeSid is true (default)", async () => {
		await expect(
			generateLogoutToken({ issuer: "iss", sub: "u", aud: "c", sid: "", keyStore }),
		).rejects.toThrow(/sid must not be empty/);
	});

	it("does not throw on empty sid when includeSid is false (sid omitted anyway)", async () => {
		const { token } = await generateLogoutToken({
			issuer: "iss",
			sub: "u",
			aud: "c",
			sid: "",
			keyStore,
			includeSid: false,
		});
		expect((decodeJwt(token) as Record<string, unknown>).sid).toBeUndefined();
	});

	it("accepts aud as array of strings", async () => {
		const { token } = await generateLogoutToken({
			issuer: "iss",
			sub: "u",
			aud: ["rp1", "rp2"],
			sid: "s",
			keyStore,
		});
		expect(decodeJwt(token).aud).toEqual(["rp1", "rp2"]);
	});
});
