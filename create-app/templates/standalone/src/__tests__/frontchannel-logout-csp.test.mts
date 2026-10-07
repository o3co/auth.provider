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

/**
 * The front-channel logout page, served through the template behind its
 * security headers, works under the one policy the response carries: its
 * relying party's frame and its redirect are allowed, and nothing else is.
 * Every other answer keeps the template's policy.
 */

import { createHash } from "node:crypto";
import request from "supertest";
import { describe, expect, it } from "vitest";
import {
	authorize,
	basic,
	codeFrom,
	compose,
	login,
	PKCE,
} from "./all-modules-composition.fixture.mjs";

const RP = {
	id: "rp-fc",
	secret: "rp-fc-secret-long-enough",
	redirectUri: "https://rp-fc.test/cb",
	frontchannelLogoutUri: "https://rp-fc.test:8443/frontchannel-logout",
	postLogoutRedirectUri: "https://rp-fc.test/signed-out",
} as const;

/** A serialized policy as directive name → sources; a directive named twice fails. */
const parsePolicy = (policy: string): Map<string, string[]> => {
	const directives = new Map<string, string[]>();
	for (const part of policy.split(";")) {
		const [name, ...sources] = part.trim().split(/\s+/);
		if (name === undefined || name === "") continue;
		if (directives.has(name)) throw new Error(`directive ${name} appears twice`);
		directives.set(name, sources);
	}
	return directives;
};

/** The sources a fetch directive resolves to: its own, else `default-src`'s. */
const effective = (policy: Map<string, string[]>, directive: string): string[] =>
	policy.get(directive) ?? policy.get("default-src") ?? [];

const decode = (value: string): string =>
	value
		.replace(/&quot;/g, '"')
		.replace(/&#39;/g, "'")
		.replace(/&lt;/g, "<")
		.replace(/&gt;/g, ">")
		.replace(/&amp;/g, "&");

/** How many `Content-Security-Policy` header lines the response carried, as sent. */
const policyHeaderCount = (response: object): number => {
	const raw = (response as { res?: { rawHeaders?: unknown } }).res?.rawHeaders;
	if (!Array.isArray(raw)) throw new Error("the response carries no raw headers");
	return raw.filter(
		(name, i) => i % 2 === 0 && String(name).toLowerCase() === "content-security-policy",
	).length;
};

describe("the front-channel logout page under the template's security headers", () => {
	it("is allowed its relying party's frame and its redirect by the one policy it is served with", async () => {
		const { app, handle } = await compose({
			extraClients: {
				[RP.id]: {
					tokenEndpointAuthMethod: "client_secret_basic",
					clientSecret: RP.secret,
					allowedRedirectUris: [RP.redirectUri],
					allowedScopes: ["openid"],
					allowedGrantTypes: ["authorization_code"],
					frontchannelLogoutUri: RP.frontchannelLogoutUri,
					postLogoutRedirectUris: [RP.postLogoutRedirectUri],
					firstParty: true,
				},
			},
		});
		try {
			// A session the relying party joined by exchanging a code.
			const { cookies } = await login(app);
			const exchanged = await request(app)
				.post("/oauth/token")
				.set("Authorization", basic(RP))
				.type("form")
				.send({
					grant_type: "authorization_code",
					code: codeFrom(await authorize(app, cookies, RP)),
					redirect_uri: RP.redirectUri,
					code_verifier: PKCE.verifier,
				});
			expect(exchanged.status).toBe(200);

			const res = await request(app)
				.get("/oauth/logout")
				.set("Accept", "text/html")
				.set("Cookie", cookies)
				.query({
					id_token_hint: exchanged.body.id_token as string,
					post_logout_redirect_uri: RP.postLogoutRedirectUri,
					state: "s-1",
				});

			expect(res.status).toBe(200);
			expect(res.headers["content-type"]).toBe("text/html; charset=utf-8");
			expect(policyHeaderCount(res)).toBe(1);
			const policy = parsePolicy(res.headers["content-security-policy"] as string);

			// The frame: the relying party's, from the one origin the policy allows.
			const srcs = [...res.text.matchAll(/<iframe src="([^"]*)"/g)].map((m) => decode(m[1] ?? ""));
			expect(srcs).toHaveLength(1);
			expect(new URL(srcs[0] ?? "").origin).toBe("https://rp-fc.test:8443");
			expect(effective(policy, "frame-src")).toEqual(["https://rp-fc.test:8443"]);

			// The redirect: one inline script, allowed by its hash, sending the
			// browser to the registered URI with the state.
			const scripts = [
				...res.text.matchAll(/<script data-target="([^"]*)" data-delay="(\d+)">([^<]*)<\/script>/g),
			];
			expect(scripts).toHaveLength(1);
			expect(res.text.match(/<script/g)).toHaveLength(1);
			const [, target, , text] = scripts[0] ?? [];
			expect(decode(target ?? "")).toBe(`${RP.postLogoutRedirectUri}?state=s-1`);
			const hash = createHash("sha256")
				.update(text ?? "", "utf8")
				.digest("base64");
			expect(effective(policy, "script-src")).toEqual([`'sha256-${hash}'`]);

			// Nothing else.
			expect(policy.get("default-src")).toEqual(["'none'"]);
			expect(effective(policy, "style-src")).toEqual(["'none'"]);
			expect(effective(policy, "connect-src")).toEqual(["'none'"]);
			expect(policy.get("frame-ancestors")).toEqual(["'none'"]);
			expect(res.headers["cache-control"]).toBe("no-store");
		} finally {
			await handle.dispose();
		}
	});

	it("leaves the template's policy on every other answer", async () => {
		const { app, handle } = await compose();
		try {
			const res = await request(app).get("/.well-known/openid-configuration");

			expect(policyHeaderCount(res)).toBe(1);
			const policy = parsePolicy(res.headers["content-security-policy"] as string);
			expect(policy.get("default-src")).toEqual(["'none'"]);
			expect(policy.get("frame-ancestors")).toEqual(["'none'"]);
			expect(effective(policy, "frame-src")).toEqual(["'none'"]);
		} finally {
			await handle.dispose();
		}
	});
});
