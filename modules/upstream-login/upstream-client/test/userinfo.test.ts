import { UpstreamRefused } from "@mod/upstreams";
import { describe, expect, it } from "vitest";
import { userinfoProfileOf, withUserinfo } from "../src/id-token/userinfo.ts";

describe("upstream-client's UserInfo reading", () => {
	it("reads a UserInfo answer for the id_token's subject alone, as JSON, refusing any other [oidc-core-5.3.2-n]", () => {
		const answer = (
			status: number,
			body: unknown,
			contentType = "application/json; charset=utf-8",
		) => ({
			status,
			headers: new Map([["content-type", contentType]]),
			body: new TextEncoder().encode(typeof body === "string" ? body : JSON.stringify(body)),
		});
		const said = { sub: "u-1", email: "a@x.test", email_verified: true, name: "A", picture: "p" };
		expect(userinfoProfileOf(answer(200, said), "u-1")).toEqual({
			email: "a@x.test",
			emailVerified: true,
			name: "A",
			picture: "p",
		});
		// Verified by the boolean true alone; an empty text is no value.
		expect(
			userinfoProfileOf(
				answer(200, { sub: "u-1", email: "a@x.test", email_verified: "true" }),
				"u-1",
			),
		).toEqual({ email: "a@x.test", emailVerified: false });
		expect(
			userinfoProfileOf(answer(200, { sub: "u-1", name: "", email: "" }), "u-1"),
		).toBeUndefined();
		// Only the four claims a profile holds: nothing of who logged in, or how.
		const more = {
			...said,
			amr: ["mfa"],
			auth_time: 1,
			acr: "x",
			groups: ["g"],
			iss: "i",
			aud: "c",
		};
		expect(Object.keys(userinfoProfileOf(answer(200, more), "u-1") ?? {}).sort()).toEqual([
			"email",
			"emailVerified",
			"name",
			"picture",
		]);
		for (const refused of [
			answer(200, { ...said, sub: "u-2" }),
			answer(200, { ...said, sub: "U-1" }),
			answer(200, { email: "a@x.test" }),
			answer(200, { ...said, sub: 1 }),
			answer(200, said, "application/jwt"),
			answer(200, said, "text/plain"),
			answer(200, "eyJ.a.b", "application/jwt"),
			answer(200, "[1]"),
			answer(200, "not json"),
			answer(401, ""),
			answer(401, { error: "invalid_token" }),
			answer(403, said),
			answer(404, said),
			answer(503, said),
		]) {
			expect(() => userinfoProfileOf(refused, "u-1"), String(refused.status)).toThrow(
				UpstreamRefused,
			);
		}
	});

	it("takes what the id_token says first, by its claims as given, and from UserInfo only what it leaves out", () => {
		const info = { name: "Info", picture: "p", email: "i@x.test", emailVerified: true };
		const token = (claims: Record<string, unknown>) => ({
			claims,
			profile: {
				...(typeof claims.email === "string"
					? { email: claims.email, emailVerified: claims.email_verified === true }
					: {}),
				...(typeof claims.name === "string" ? { name: claims.name } : {}),
				...(typeof claims.picture === "string" ? { picture: claims.picture } : {}),
			},
		});
		expect(withUserinfo(token({ name: "Token", email: "t@x.test" }), info)).toEqual({
			name: "Token",
			email: "t@x.test",
			emailVerified: false,
			picture: "p",
		});
		// A claim the id_token gives, however it gives it, is never filled from UserInfo.
		for (const given of [null, 7, "", ["x"]]) {
			expect(withUserinfo(token({ name: given, email: given }), info), String(given)).toEqual({
				...(given === "" ? { name: "", email: "", emailVerified: false } : {}),
				picture: "p",
			});
		}
		// The email goes with its own answer's verification, either way.
		expect(
			withUserinfo(token({ email_verified: true }), { email: "i@x.test", emailVerified: false }),
		).toEqual({
			email: "i@x.test",
			emailVerified: false,
		});
		expect(withUserinfo(token({ email: "t@x.test" }), { emailVerified: true })).toEqual({
			email: "t@x.test",
			emailVerified: false,
		});
		expect(withUserinfo(token({}), info)).toEqual(info);
		expect(withUserinfo(token({ name: "Token" }), undefined)).toEqual({ name: "Token" });
		expect(withUserinfo(token({}), undefined)).toBeUndefined();
	});
});
