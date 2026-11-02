import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { pkceShim } from "../pkce.ts";

const callback = "https://suite.test/test/a/o3co/callback";
const asked = (fields: Record<string, string>) =>
	new URLSearchParams({ client_id: "client", redirect_uri: callback, ...fields });
const s256 = (verifier: string) => createHash("sha256").update(verifier).digest("base64url");

/** A shim whose verifiers are told in turn, at a fixed time. */
const shim = () => {
	let n = 0;
	return pkceShim({
		verifier: () => `verifier-${++n}`.padEnd(43, "v"),
		now: () => new Date("2026-10-26T00:00:00Z"),
	});
};

describe("the PKCE shim in front of the provider", () => {
	it("adds an S256 challenge to an authorization request with none, and its verifier to the code's token request", () => {
		const s = shim();
		const sent = s.authorization(asked({ state: "a" }));
		const verifier = "verifier-1".padEnd(43, "v");
		expect(sent.get("code_challenge")).toBe(s256(verifier));
		expect(sent.get("code_challenge_method")).toBe("S256");
		s.redirected(`${callback}?code=c1&state=a`);
		const token = s.token(new URLSearchParams({ grant_type: "authorization_code", code: "c1" }));
		expect(token.get("code_verifier")).toBe(verifier);
	});

	it("adds the same verifier to a second token request for the same code", () => {
		const s = shim();
		s.authorization(asked({ state: "a" }));
		s.redirected(`${callback}?code=c1&state=a`);
		const body = () => new URLSearchParams({ grant_type: "authorization_code", code: "c1" });
		// The provider refuses the second and revokes what it gave; the shim keeps that path as it is.
		expect(s.token(body()).get("code_verifier")).toBe(s.token(body()).get("code_verifier"));
	});

	it("never gives one request's verifier to another's code", () => {
		const s = shim();
		const first = s.authorization(asked({ state: "a" }));
		const second = s.authorization(asked({ state: "b" }));
		expect(first.get("code_challenge")).not.toBe(second.get("code_challenge"));
		s.redirected(`${callback}?code=cb&state=b`);
		s.redirected(`${callback}?code=ca&state=a`);
		const verifierOf = (code: string) =>
			s.token(new URLSearchParams({ grant_type: "authorization_code", code })).get("code_verifier");
		expect(s256(verifierOf("ca") as string)).toBe(first.get("code_challenge"));
		expect(s256(verifierOf("cb") as string)).toBe(second.get("code_challenge"));
	});

	it("ties a code to the latest request with no state at its redirect URI", () => {
		const s = shim();
		s.authorization(asked({}));
		const latest = s.authorization(asked({}));
		s.redirected(`${callback}?code=c1`);
		const verifier = s
			.token(new URLSearchParams({ grant_type: "authorization_code", code: "c1" }))
			.get("code_verifier");
		expect(s256(verifier as string)).toBe(latest.get("code_challenge"));
	});

	it("leaves a request carrying PKCE of its own as it is, right or wrong", () => {
		const s = shim();
		for (const own of [
			{ code_challenge: "x".repeat(43), code_challenge_method: "S256" },
			{ code_challenge: "x".repeat(43), code_challenge_method: "plain" },
			{ code_challenge_method: "S256" },
		]) {
			const request = asked({ state: "own", ...own });
			expect(s.authorization(request).toString()).toBe(request.toString());
		}
		s.redirected(`${callback}?code=own&state=own`);
		const token = new URLSearchParams({ grant_type: "authorization_code", code: "own" });
		expect(s.token(token).has("code_verifier")).toBe(false);
		const wrong = new URLSearchParams({
			grant_type: "authorization_code",
			code: "own",
			code_verifier: "w",
		});
		expect(s.token(wrong).toString()).toBe(wrong.toString());
	});

	it("leaves a token request for a code it did not see, or of another grant, as it is", () => {
		const s = shim();
		s.authorization(asked({ state: "a" }));
		s.redirected(`${callback}?code=c1&state=a`);
		for (const body of [
			new URLSearchParams({ grant_type: "authorization_code", code: "unknown" }),
			new URLSearchParams({ grant_type: "refresh_token", code: "c1", refresh_token: "r" }),
		]) {
			expect(s.token(body).toString()).toBe(body.toString());
		}
	});

	it("takes no code from a redirect to another URI or with an error", () => {
		const s = shim();
		s.authorization(asked({ state: "a" }));
		s.redirected("https://elsewhere.test/callback?code=c1&state=a");
		s.redirected(`${callback}?error=access_denied&state=a`);
		const token = new URLSearchParams({ grant_type: "authorization_code", code: "c1" });
		expect(s.token(token).has("code_verifier")).toBe(false);
	});

	it("records each challenge and verifier it adds, with the client, the state and the time", () => {
		const s = shim();
		const sent = s.authorization(asked({ state: "a" }));
		s.redirected(`${callback}?code=c1&state=a`);
		s.token(new URLSearchParams({ grant_type: "authorization_code", code: "c1" }));
		expect(s.records()).toEqual([
			{
				at: "2026-10-26T00:00:00.000Z",
				added: "code_challenge",
				value: sent.get("code_challenge"),
				client: "client",
				state: "a",
			},
			{
				at: "2026-10-26T00:00:00.000Z",
				added: "code_verifier",
				value: "verifier-1".padEnd(43, "v"),
				client: "client",
				state: "a",
				code: "c1",
			},
		]);
	});

	it("gives no verifier to the code of a later request with PKCE of its own, at the same state and redirect URI", () => {
		const s = shim();
		s.authorization(asked({ state: "a" }));
		s.redirected(`${callback}?code=c1&state=a`);
		s.authorization(
			asked({ state: "a", code_challenge: "x".repeat(43), code_challenge_method: "S256" }),
		);
		s.redirected(`${callback}?code=own&state=a`);
		const token = new URLSearchParams({ grant_type: "authorization_code", code: "own" });
		expect(s.token(token).has("code_verifier")).toBe(false);
	});

	it("still gives the verifier where the login resumes the request with the shim's own challenge", () => {
		const s = shim();
		const sent = s.authorization(asked({ state: "a" }));
		// The provider sends the browser back to the request as it got it, the shim's challenge in it.
		const resumed = s.authorization(sent);
		expect(resumed.toString()).toBe(sent.toString());
		s.redirected(`${callback}?code=c1&state=a`);
		const token = s.token(new URLSearchParams({ grant_type: "authorization_code", code: "c1" }));
		expect(token.get("code_verifier")).toBe("verifier-1".padEnd(43, "v"));
	});
});
