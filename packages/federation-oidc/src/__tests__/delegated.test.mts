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

import { codeChallenge, supportsDelegatedAuthorization } from "@o3co/auth-provider-session";
import { describe, expect, it } from "vitest";
import { createOidcProvider, type OidcProviderConfig } from "#/oidc.mjs";
import { createFakeIdp } from "./helpers.mjs";

const ISSUER = "https://idp-a.test";
const CALLBACK = "https://auth.test/oauth/federation-grants/okta-calendar/callback";
const VERIFIER = "v".repeat(43);
const SCOPES = ["openid", "offline_access", "calendar.read"] as const;

async function build(overrides: Partial<OidcProviderConfig> = {}) {
	const idp = await createFakeIdp({ issuer: ISSUER });
	const provider = await createOidcProvider("idp-a", {
		issuer: idp.issuer,
		clientId: idp.clientId,
		clientSecret: "s3cret",
		callbackURL: "https://auth.test/session/oauth/federation/idp-a/callback",
		fetch: idp.fetch,
		...overrides,
	});
	if (!supportsDelegatedAuthorization(provider)) throw new Error("fixture: no capability");
	return { idp, provider };
}

const authorize = (
	provider: Awaited<ReturnType<typeof build>>["provider"],
	over: Partial<Parameters<typeof provider.buildDelegatedAuthorizationUrl>[0]> = {},
) =>
	provider.buildDelegatedAuthorizationUrl({
		redirectUri: CALLBACK,
		state: "state-1",
		codeVerifier: VERIFIER,
		nonce: "nonce-1",
		scopes: [...SCOPES],
		...over,
	});

describe("the generic OIDC adapter's delegated authorization (#593, D17)", () => {
	describe("the authorization request", () => {
		it("carries the intent's scopes, the grant's callback, PKCE S256, state and nonce — and consent, since offline_access is asked for (OIDC Core §11)", async () => {
			const { idp, provider } = await build();
			const q = authorize(provider).searchParams;
			expect(q.get("response_type")).toBe("code");
			expect(q.get("client_id")).toBe(idp.clientId);
			expect(q.get("redirect_uri")).toBe(CALLBACK);
			expect(q.get("scope")).toBe("openid offline_access calendar.read");
			expect(q.get("state")).toBe("state-1");
			expect(q.get("nonce")).toBe("nonce-1");
			expect(q.get("code_challenge")).toBe(codeChallenge(VERIFIER));
			expect(q.get("code_challenge_method")).toBe("S256");
			expect(q.get("prompt")).toBe("consent");
			expect(q.get("resource")).toBeNull();
		});

		it("asks for no consent by default where offline_access is not asked for", async () => {
			const { provider } = await build();
			expect(
				authorize(provider, { scopes: ["openid", "calendar.read"] }).searchParams.get("prompt"),
			).toBeNull();
		});

		it("forwards the resource indicator (RFC 8707) and the operator's parameters, whose prompt wins over the default", async () => {
			const { provider } = await build();
			const q = authorize(provider, {
				resource: "https://calendar.example/",
				authorizationParams: { prompt: "select_account consent", access_type: "offline" },
			}).searchParams;
			expect(q.get("resource")).toBe("https://calendar.example/");
			expect(q.get("prompt")).toBe("select_account consent");
			expect(q.get("access_type")).toBe("offline");
		});

		it("refuses an operator parameter that would take over a parameter this provider owns", async () => {
			// openid-client sets client_id and response_type only when absent: a
			// copied parameter would send the consent to another registration.
			const { provider } = await build();
			for (const key of [
				"client_id",
				"response_type",
				"redirect_uri",
				"state",
				"code_challenge",
				"code_challenge_method",
				"nonce",
				"scope",
				"resource",
				"request",
				"request_uri",
				"response_mode",
			]) {
				expect(() => authorize(provider, { authorizationParams: { [key]: "x" } }), key).toThrow(
					new RegExp(key),
				);
			}
		});

		it('refuses an operator parameter whose value is not a string: a configuration fault, not a parameter named "undefined"', async () => {
			const { provider } = await build();
			for (const value of [undefined, 42, null, ["consent"]]) {
				expect(
					() =>
						authorize(provider, {
							authorizationParams: { prompt: value } as unknown as Record<string, string>,
						}),
					String(value),
				).toThrow(/prompt/);
			}
		});

		it("refuses scopes without openid, an empty list, and no nonce: configuration faults, not answers", async () => {
			const { provider } = await build();
			expect(() => authorize(provider, { scopes: ["offline_access"] })).toThrow(/openid/);
			expect(() => authorize(provider, { scopes: [] })).toThrow(/openid/);
			expect(() => authorize(provider, { nonce: "" })).toThrow(/nonce/);
		});

		it("is not held to the login flow's configured scopes: the connection's ceiling is core's rule", async () => {
			const { provider } = await build({ scopes: ["openid", "email"] });
			expect(authorize(provider).searchParams.get("scope")).toBe(
				"openid offline_access calendar.read",
			);
			expect(provider.scope).toEqual(["openid", "email"]);
		});
	});

	describe("the delegated code exchange (#593, D17 — the capability's third method)", () => {
		const exchange = (
			provider: Awaited<ReturnType<typeof build>>["provider"],
			over: Partial<Parameters<typeof provider.exchangeDelegatedCode>[0]> = {},
		) =>
			provider.exchangeDelegatedCode({
				code: "code-1",
				codeVerifier: VERIFIER,
				redirectUri: CALLBACK,
				nonce: "nonce-1",
				...over,
			});

		it("exchanges the code at the grant's callback with PKCE, and answers the verified upstream identity beside the raw token fields", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			idp.codeAnswer = { scope: "openid offline_access calendar.read" };
			const before = Date.now();
			const result = await exchange(provider);
			const req = idp.lastTokenRequest();
			expect(req?.body?.get("grant_type")).toBe("authorization_code");
			expect(req?.body?.get("code")).toBe("code-1");
			expect(req?.body?.get("code_verifier")).toBe(VERIFIER);
			// The grant's callback, not the login one the provider was built with.
			expect(req?.body?.get("redirect_uri")).toBe(CALLBACK);
			// No claim asked for, none carried.
			expect(result.upstream).toEqual({ issuer: idp.issuer, subject: idp.sub, claims: {} });
			expect(result.tokens).toMatchObject({
				accessToken: idp.accessToken,
				refreshToken: "rt-1",
				expiresIn: 3600,
				scope: "openid offline_access calendar.read",
				tokenType: "bearer",
			});
			expect(result.tokens.expiresAt?.getTime()).toBeGreaterThanOrEqual(before + 3_600_000);
			// The id_token is verified and not handed on: nothing downstream needs it.
			expect(result.tokens).not.toHaveProperty("idToken");
		});

		it("sends the resource indicator at the token endpoint too (RFC 8707 §2.2), and none when the connection names none", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			await exchange(provider, { resource: "https://calendar.example/" });
			expect(idp.lastTokenRequest()?.body?.get("resource")).toBe("https://calendar.example/");
			await exchange(provider);
			expect(idp.lastTokenRequest()?.body?.has("resource")).toBe(false);
		});

		it("carries the claims asked for from the verified id_token, and nothing else (#611)", async () => {
			// What a Store with its own directory matches a person on across
			// registrations — Entra's tenant and object id — where the `sub` is
			// pairwise. Copied from the id_token the library verified, never
			// from UserInfo or the callback, and only the names asked for.
			const { idp, provider } = await build({ userInfo: true });
			idp.nonce = "nonce-1";
			idp.idTokenClaims = { oid: "O-A", tid: "T-1", unrequested: "sentinel-claim" };
			const result = await exchange(provider, {
				identityClaims: ["oid", "tid"],
				callbackParams: { oid: "O-FROM-CALLBACK" },
			});
			expect(result.upstream).toEqual({
				issuer: idp.issuer,
				subject: idp.sub,
				claims: { oid: "O-A", tid: "T-1" },
			});
			expect(idp.requestsTo("/userinfo")).toHaveLength(0);
			// A local allowlist, not a request: nothing about it goes upstream.
			const body = idp.lastTokenRequest()?.body?.toString() ?? "";
			expect(body).not.toContain("oid");
			expect(body).not.toContain("tid");
		});

		it("leaves out a claim asked for that is absent, empty, or not a string — never coerced", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			idp.idTokenClaims = { tid: 42, oid: "", a: null, b: ["x"], c: { d: 1 }, e: true };
			const result = await exchange(provider, {
				identityClaims: ["tid", "oid", "a", "b", "c", "e", "missing"],
			});
			expect(result.upstream.claims).toEqual({});
			// A name the id_token has only by inheritance is not one it carries.
			idp.idTokenClaims = {};
			const inherited = await exchange(provider, { identityClaims: ["toString"] });
			expect(inherited.upstream.claims).toEqual({});
		});

		it("refuses a claim name the protocol already owns, a malformed one, or a repeat: configuration faults", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			for (const names of [
				["sub"],
				["iss"],
				["nonce"],
				["__proto__"],
				["a b"],
				[""],
				["oid", "oid"],
			]) {
				await expect(
					exchange(provider, { identityClaims: names }),
					JSON.stringify(names),
				).rejects.toThrow(/identityClaims/);
			}
			// Refused before the code is spent at the upstream.
			const before = idp.requestsTo("/token").length;
			await expect(exchange(provider, { identityClaims: ["sub"] })).rejects.toThrow();
			expect(idp.requestsTo("/token")).toHaveLength(before);
		});

		it("never calls UserInfo: a delegation needs the verified subject, not a login profile", async () => {
			const { idp, provider } = await build({ userInfo: true });
			idp.nonce = "nonce-1";
			await exchange(provider);
			expect(idp.requestsTo("/userinfo")).toHaveLength(0);
		});

		it("refuses an id_token bound to another nonce, and one missing altogether — and salvages nothing from either", async () => {
			const { idp, provider } = await build();
			idp.nonce = "someone-elses-nonce";
			await expect(exchange(provider)).rejects.toThrow();
			idp.nonce = "nonce-1";
			idp.omitIdToken = true;
			// Refused by the library itself (`idTokenExpected`), before this
			// adapter's own check — the message is the library's.
			await expect(exchange(provider)).rejects.toThrow();
			// And a nonce is required of the caller, as for the authorization URL.
			await expect(exchange(provider, { nonce: "" })).rejects.toThrow(/nonce/);
		});

		it("salvages no refresh token from an answer whose identity failed: there is no authorization to keep it under", async () => {
			// Unlike a refresh, which rotates a credential a grant already holds, an
			// acquisition that could not verify who the user is has nothing a
			// refresh token could belong to.
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			idp.atHash = "wrong";
			await expect(exchange(provider)).rejects.toThrow();
		});

		it("judges the lifetime the upstream sent: one the library would coerce withholds the access token, and absence is no finite lifetime", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			// oauth4webapi reads a non-number with parseFloat, so these arrive at
			// this adapter as 1000 and 3600 — lifetimes the upstream never sent.
			for (const garbage of ["1000seconds", [3600, 7200]]) {
				idp.codeAnswer = { expires_in: garbage };
				const garbled = await exchange(provider);
				expect(garbled.tokens, JSON.stringify(garbage)).toStrictEqual({ refreshToken: "rt-1" });
				// The identity was verified, so it is still reported; core refuses
				// the activation on the tokens.
				expect(garbled.upstream.subject).toBe(idp.sub);
			}
			// What the library cannot read at all it refuses whole, and an
			// acquisition salvages nothing from a refusal.
			idp.codeAnswer = { expires_in: "soon" };
			await expect(exchange(provider)).rejects.toThrow();

			idp.codeAnswer = { expires_in: undefined };
			const unbounded = await exchange(provider);
			expect(unbounded.tokens.expiresIn).toBeNull();
			expect(unbounded.tokens.expiresAt).toBeNull();
			expect(unbounded.tokens.accessToken).toBe(idp.accessToken);
		});

		it("keeps a scope the upstream answered as empty, so the callback can refuse it (Codex on slice 6)", async () => {
			// Dropped, an empty scope reads as omitted — "as requested" — and the
			// callback would grant every consented scope on an answer that named none.
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			idp.codeAnswer = { scope: "" };
			expect((await exchange(provider)).tokens.scope).toBe("");
		});

		it("answers no refresh token when the upstream issued none, and leaves the refusal to core", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			idp.codeAnswer = { refresh_token: undefined };
			const result = await exchange(provider);
			expect(result.tokens).not.toHaveProperty("refreshToken");
			expect(result.tokens.accessToken).toBe(idp.accessToken);
		});

		it("dates the token from when the answer arrived, not from when a slow JWKS let the verification finish", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			idp.codeAnswer = { expires_in: 2 };
			idp.jwksDelayMs = 1_500;
			const before = Date.now();
			const result = await exchange(provider);
			expect(Date.now() - before).toBeGreaterThanOrEqual(1_400);
			expect(result.tokens.expiresAt?.getTime()).toBeLessThanOrEqual(before + 2_000 + 200);
			expect(result.tokens.expiresAt?.getTime()).toBeGreaterThanOrEqual(before + 2_000 - 50);
		});

		it("forwards the callback's iss to the mix-up check (RFC 9207), and refuses another issuer's", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			idp.metadata.authorization_response_iss_parameter_supported = true;
			await expect(
				exchange(provider, { callbackParams: { iss: "https://attacker.test" } }),
			).rejects.toThrow();
			const ok = await exchange(provider, { callbackParams: { iss: idp.issuer } });
			expect(ok.upstream.issuer).toBe(idp.issuer);
		});

		it("is aborted by the caller's signal", async () => {
			const idp = await createFakeIdp({ issuer: ISSUER });
			const real = idp.fetch;
			const hanging: typeof fetch = (url, init) => {
				if (String(url).endsWith("/token")) {
					return new Promise((_, reject) => {
						init?.signal?.addEventListener("abort", () => reject(init?.signal?.reason));
					});
				}
				return real(url, init);
			};
			const provider = await createOidcProvider("idp-a", {
				issuer: idp.issuer,
				clientId: idp.clientId,
				clientSecret: "s3cret",
				callbackURL: "https://auth.test/session/oauth/federation/idp-a/callback",
				fetch: hanging,
			});
			if (!supportsDelegatedAuthorization(provider)) throw new Error("fixture: no capability");
			const controller = new AbortController();
			const pending = exchange(provider, { signal: controller.signal });
			await new Promise((resolve) => setTimeout(resolve, 20));
			controller.abort(new Error("the callback gave up"));
			await expect(pending).rejects.toSatisfy((error: unknown) => {
				const cause = (error as { cause?: unknown }).cause;
				return (
					/gave up/.test(String((error as Error).message)) ||
					(cause instanceof Error && /gave up/.test(cause.message))
				);
			});
		});
	});

	describe("the delegated refresh", () => {
		it("runs the refresh_token grant with the grant's scopes and resource, and answers the raw fields: expires_in as issued, scope as answered, token_type as the library reports it", async () => {
			const { idp, provider } = await build();
			idp.refreshAnswer = { scope: "openid offline_access calendar.read" };
			const before = Date.now();
			const tokens = await provider.refreshDelegatedToken({
				refreshToken: "rt-1",
				scopes: [...SCOPES],
				resource: "https://calendar.example/",
			});
			const req = idp.lastTokenRequest();
			expect(req?.body?.get("grant_type")).toBe("refresh_token");
			expect(req?.body?.get("refresh_token")).toBe("rt-1");
			expect(req?.body?.get("scope")).toBe("openid offline_access calendar.read");
			expect(req?.body?.get("resource")).toBe("https://calendar.example/");
			expect(tokens).toMatchObject({
				accessToken: "at-refreshed",
				refreshToken: "rt-2",
				expiresIn: 1800,
				scope: "openid offline_access calendar.read",
				tokenType: "bearer",
			});
			expect(tokens.expiresAt?.getTime()).toBeGreaterThanOrEqual(before + 1_800_000);
			expect(tokens.expiresAt?.getTime()).toBeLessThanOrEqual(Date.now() + 1_800_000);
		});

		it("sends no scope and no resource when the grant names none, and answers no scope when the upstream named none", async () => {
			const { idp, provider } = await build();
			const tokens = await provider.refreshDelegatedToken({ refreshToken: "rt-1" });
			const req = idp.lastTokenRequest();
			expect(req?.body?.has("scope")).toBe(false);
			expect(req?.body?.has("resource")).toBe(false);
			expect(tokens).not.toHaveProperty("scope");
			expect(tokens.expiresIn).toBe(1800);
		});

		it("answers null for a lifetime the upstream did not name, and no refresh token when it did not rotate", async () => {
			const { idp, provider } = await build();
			idp.refreshAnswer = { expires_in: undefined, refresh_token: undefined };
			const tokens = await provider.refreshDelegatedToken({ refreshToken: "rt-1" });
			expect(tokens.expiresIn).toBeNull();
			expect(tokens.expiresAt).toBeNull();
			expect(tokens).not.toHaveProperty("refreshToken");
		});

		it("is aborted by the caller's signal, which the fetch sees beside the library's own", async () => {
			// A token endpoint that never answers: only the signal ends the wait.
			const idp = await createFakeIdp({ issuer: ISSUER });
			const real = idp.fetch;
			let seen: AbortSignal | undefined | null;
			const hanging: typeof fetch = (url, init) => {
				if (String(url).endsWith("/token")) {
					seen = init?.signal;
					return new Promise((_, reject) => {
						seen?.addEventListener("abort", () => reject(seen?.reason));
					});
				}
				return real(url, init);
			};
			const provider = await createOidcProvider("idp-a", {
				issuer: idp.issuer,
				clientId: idp.clientId,
				clientSecret: "s3cret",
				callbackURL: "https://auth.test/session/oauth/federation/idp-a/callback",
				fetch: hanging,
			});
			if (!supportsDelegatedAuthorization(provider)) throw new Error("fixture: no capability");
			const controller = new AbortController();
			const pending = provider.refreshDelegatedToken({
				refreshToken: "rt-1",
				signal: controller.signal,
			});
			await new Promise((resolve) => setTimeout(resolve, 20));
			expect(seen).toBeInstanceOf(AbortSignal);
			controller.abort(new Error("the caller gave up"));
			// The library wraps what its fetch rejected with; the reason is the cause.
			await expect(pending).rejects.toSatisfy((error: unknown) => {
				const cause = (error as { cause?: unknown }).cause;
				return (
					/gave up/.test(String((error as Error).message)) ||
					(cause instanceof Error && /gave up/.test(cause.message))
				);
			});
		});

		it("salvages nothing that is not a refresh token: a malformed answer whose refresh_token is empty or not a string is thrown", async () => {
			const { idp, provider } = await build();
			for (const refreshToken of ["", 123, null]) {
				idp.refreshAnswer = { scope: ["openid"], refresh_token: refreshToken };
				await expect(
					provider.refreshDelegatedToken({ refreshToken: "rt-1" }),
					String(refreshToken),
				).rejects.toThrow();
			}
		});

		it("keeps the rotated refresh token out of an answer the library refuses to parse: what D5 persists is never lost to a parser", async () => {
			const { idp, provider } = await build();
			// A scope that is not a string: oauth4webapi throws before returning
			// the body, and the body carries the only valid credential.
			idp.refreshAnswer = { scope: ["openid"], refresh_token: "rt-rotated" };
			const tokens = await provider.refreshDelegatedToken({ refreshToken: "rt-1" });
			expect(tokens).toStrictEqual({ refreshToken: "rt-rotated" });
		});

		it("keeps the rotated refresh token however the token endpoint is spelled: a default port in the metadata is the same endpoint", async () => {
			// oauth4webapi normalizes the URL it fetches; the metadata's spelling
			// must not decide whether the body is captured.
			const { idp, provider } = await build({
				endpoints: { tokenEndpoint: `${ISSUER}:443/token` },
			});
			idp.refreshAnswer = { scope: ["openid"], refresh_token: "rt-rotated" };
			const tokens = await provider.refreshDelegatedToken({ refreshToken: "rt-1" });
			expect(tokens).toStrictEqual({ refreshToken: "rt-rotated" });
		});

		it("keeps the rotated refresh token when the metadata's host carries a trailing DNS dot (Copilot on #605)", async () => {
			// `URL.href` canonicalizes a default port but keeps a trailing dot, so
			// the two spellings of one host must be brought together by hand.
			const { idp, provider } = await build({
				endpoints: { tokenEndpoint: `${ISSUER.replace("://idp-a.test", "://idp-a.test.")}/token` },
			});
			idp.refreshAnswer = { scope: ["openid"], refresh_token: "rt-rotated" };
			const tokens = await provider.refreshDelegatedToken({ refreshToken: "rt-1" });
			expect(tokens).toStrictEqual({ refreshToken: "rt-rotated" });
		});

		it("dates the token from when the answer arrived, not from when the library was done verifying an id_token against a slow JWKS", async () => {
			const { idp, provider } = await build();
			idp.refreshWithIdToken = true;
			idp.refreshAnswer = { expires_in: 2 };
			idp.jwksDelayMs = 1_500;
			const before = Date.now();
			const tokens = await provider.refreshDelegatedToken({ refreshToken: "rt-1" });
			const after = Date.now();
			expect(after - before).toBeGreaterThanOrEqual(1_400);
			expect(tokens.expiresIn).toBe(2);
			// Anchored at receipt: at most two seconds past the start of the call,
			// and not two seconds past the end of the verification.
			expect(tokens.expiresAt?.getTime()).toBeLessThanOrEqual(before + 2_000 + 200);
			expect(tokens.expiresAt?.getTime()).toBeGreaterThanOrEqual(before + 2_000 - 50);
		});

		it("judges the lifetime the upstream sent, not what the library coerced it to: a lifetime that is not a number withholds the access token and keeps the rotated refresh token", async () => {
			const { idp, provider } = await build();
			for (const garbage of [[3600, 7200], "1000seconds", { seconds: 3600 }, true]) {
				idp.refreshAnswer = { expires_in: garbage, refresh_token: "rt-rotated" };
				expect(
					await provider.refreshDelegatedToken({ refreshToken: "rt-1" }),
					JSON.stringify(garbage),
				).toStrictEqual({ refreshToken: "rt-rotated" });
			}
			// A string of digits is unambiguous, and some IdPs send one.
			idp.refreshAnswer = { expires_in: "3600" };
			expect(await provider.refreshDelegatedToken({ refreshToken: "rt-1" })).toMatchObject({
				accessToken: "at-refreshed",
				expiresIn: 3600,
			});
		});

		it("rethrows what the IdP refused with, for the classifier — even when the refusal's body carries a refresh_token", async () => {
			const { idp, provider } = await build();
			idp.tokenStatus = 400;
			await expect(provider.refreshDelegatedToken({ refreshToken: "rt-1" })).rejects.toMatchObject({
				error: "invalid_client",
				status: 400,
			});
			// Nothing is salvaged from a refusal: a 4xx is the IdP saying no, and a
			// token in its body is not one it issued.
			idp.refusal = { error: "invalid_grant", refresh_token: "rt-planted" };
			await expect(provider.refreshDelegatedToken({ refreshToken: "rt-1" })).rejects.toMatchObject({
				error: "invalid_grant",
			});
		});

		it("verifies an id_token an IdP re-issues on refresh against the JWKS it already holds: one JWKS fetch for the provider's life", async () => {
			const { idp, provider } = await build();
			idp.refreshWithIdToken = true;
			await provider.refreshDelegatedToken({ refreshToken: "rt-1" });
			await provider.refreshDelegatedToken({ refreshToken: "rt-1" });
			expect(idp.requestsTo("/jwks").length).toBeLessThanOrEqual(1);
		});

		it("leaves the login flow's snapshot as it was, with the raw fields beside it", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			const profile = await provider.exchangeCode({
				code: "code-1",
				codeVerifier: VERIFIER,
				redirectUri: "https://auth.test/session/oauth/federation/idp-a/callback",
				nonce: "nonce-1",
			});
			expect(profile).toMatchObject({ accessToken: "at-1", expiresIn: 3600, tokenType: "bearer" });
			expect(profile.expiresAt).toBeInstanceOf(Date);
			const refreshed = await provider.refreshToken("rt-1");
			expect(refreshed).toMatchObject({ expiresIn: 1800, tokenType: "bearer" });
		});
	});
});
