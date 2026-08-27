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
 * Issue #272 — the session routes' CSRF defence was a single `Origin` check
 * that called `next()` whenever the header was absent, so any caller able to
 * omit `Origin` walked straight past it. There was no anti-CSRF token to fall
 * back on, and the trust list was `cors.allowedOrigins` — a CORS policy doing
 * duty as a CSRF policy.
 *
 * These tests pin the replacement: a signed double-submit token, a strict
 * same-origin `Origin` / `Referer` check with its own trust list, and the
 * acceptance rule that composes them.
 */

import express, { type Request, type Response } from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import type { CsrfProtectionOptions } from "#/csrf.mjs";
import {
	checkRequestOrigin,
	createCsrfGuard,
	createCsrfIssueHandler,
	createCsrfProtection,
} from "#/csrf.mjs";

const SECRET = "test-session-secret-value";

const makeCsrf = (overrides: Partial<CsrfProtectionOptions> = {}) =>
	createCsrfProtection({ secret: SECRET, ...overrides });

/** Minimal `Request` stand-in — the module reads headers, body and host only. */
const fakeRequest = (init: {
	cookies?: Record<string, string>;
	headers?: Record<string, string>;
	body?: Record<string, unknown>;
	protocol?: string;
	host?: string;
}): Request => {
	const cookieHeader = Object.entries(init.cookies ?? {})
		.map(([name, value]) => `${name}=${encodeURIComponent(value)}`)
		.join("; ");
	const headers: Record<string, string> = {
		...(cookieHeader ? { cookie: cookieHeader } : {}),
		...Object.fromEntries(
			Object.entries(init.headers ?? {}).map(([name, value]) => [name.toLowerCase(), value]),
		),
	};
	return {
		headers,
		body: init.body,
		protocol: init.protocol ?? "https",
		host: init.host ?? "auth.example.com",
		get(name: string) {
			return headers[name.toLowerCase()];
		},
	} as unknown as Request;
};

/** Captures what `issue()` handed to `res.cookie(...)`. */
const fakeResponse = () => {
	const calls: Array<{ name: string; value: string; options: Record<string, unknown> }> = [];
	const res = {
		calls,
		cookie(name: string, value: string, options: Record<string, unknown>) {
			calls.push({ name, value, options });
			return res;
		},
	};
	return res as unknown as Response & { calls: typeof calls };
};

describe("csrf — signed double-submit token", () => {
	it("accepts a minted token presented in both the cookie and the header", () => {
		const csrf = makeCsrf();
		const token = csrf.mint();

		const verdict = csrf.verify(
			fakeRequest({
				cookies: { [csrf.cookieName]: token },
				headers: { [csrf.headerName]: token },
			}),
		);

		expect(verdict).toBe("valid");
	});

	it("accepts the token in the request body for form posts that cannot set headers", () => {
		const csrf = makeCsrf();
		const token = csrf.mint();

		const verdict = csrf.verify(
			fakeRequest({
				cookies: { [csrf.cookieName]: token },
				body: { [csrf.bodyField]: token },
			}),
		);

		expect(verdict).toBe("valid");
	});

	it("reports `absent` when neither half of the pair is present", () => {
		const csrf = makeCsrf();

		expect(csrf.verify(fakeRequest({}))).toBe("absent");
	});

	it("rejects a cookie with no submitted counterpart", () => {
		const csrf = makeCsrf();
		const token = csrf.mint();

		expect(csrf.verify(fakeRequest({ cookies: { [csrf.cookieName]: token } }))).toBe("invalid");
	});

	it("rejects a submitted token with no cookie counterpart", () => {
		const csrf = makeCsrf();
		const token = csrf.mint();

		expect(csrf.verify(fakeRequest({ headers: { [csrf.headerName]: token } }))).toBe("invalid");
	});

	it("rejects two individually valid tokens that are not the same token", () => {
		// The whole point of double-submit: the pair must match, not merely
		// each be well-formed. An attacker who can mint tokens for themselves
		// still cannot write the victim's cookie.
		const csrf = makeCsrf();

		const verdict = csrf.verify(
			fakeRequest({
				cookies: { [csrf.cookieName]: csrf.mint() },
				headers: { [csrf.headerName]: csrf.mint() },
			}),
		);

		expect(verdict).toBe("invalid");
	});

	it("rejects a token whose signature has been tampered with", () => {
		const csrf = makeCsrf();
		const token = csrf.mint();
		const tampered = `${token.slice(0, -2)}${token.endsWith("aa") ? "bb" : "aa"}`;

		const verdict = csrf.verify(
			fakeRequest({
				cookies: { [csrf.cookieName]: tampered },
				headers: { [csrf.headerName]: tampered },
			}),
		);

		expect(verdict).toBe("invalid");
	});

	it("rejects a well-formed token signed with a different secret", () => {
		// This is what separates a signed double-submit from a plain one: a
		// subdomain that can write the parent-domain cookie still cannot forge
		// material the provider will accept.
		const attacker = createCsrfProtection({ secret: "some-other-secret" });
		const csrf = makeCsrf();
		const forged = attacker.mint();

		const verdict = csrf.verify(
			fakeRequest({
				cookies: { [csrf.cookieName]: forged },
				headers: { [csrf.headerName]: forged },
			}),
		);

		expect(verdict).toBe("invalid");
	});

	it("rejects an expired token", () => {
		let now = 1_000_000_000_000;
		const csrf = createCsrfProtection({ secret: SECRET, ttlSeconds: 60, now: () => now });
		const token = csrf.mint();

		now += 61_000;

		const verdict = csrf.verify(
			fakeRequest({
				cookies: { [csrf.cookieName]: token },
				headers: { [csrf.headerName]: token },
			}),
		);

		expect(verdict).toBe("invalid");
	});

	it("rejects a syntactically broken token", () => {
		const csrf = makeCsrf();

		const verdict = csrf.verify(
			fakeRequest({
				cookies: { [csrf.cookieName]: "not-a-token" },
				headers: { [csrf.headerName]: "not-a-token" },
			}),
		);

		expect(verdict).toBe("invalid");
	});
});

describe("csrf — cookie issuance", () => {
	it("writes a JS-readable cookie mirroring the session cookie's transport attributes", () => {
		const csrf = createCsrfProtection({
			secret: SECRET,
			cookieName: "auth.session.csrf",
			ttlSeconds: 900,
			cookie: { secure: true, sameSite: "lax", domain: "example.com" },
		});
		const res = fakeResponse();

		const token = csrf.issue(res);

		expect(res.calls).toHaveLength(1);
		const [call] = res.calls;
		expect(call?.name).toBe("auth.session.csrf");
		expect(call?.value).toBe(token);
		// httpOnly:false is load-bearing — the browser has to read this one back
		// out to put it in the header. That is safe precisely because the value
		// is not a credential: it only proves same-site script wrote the header.
		expect(call?.options).toMatchObject({
			httpOnly: false,
			path: "/",
			secure: true,
			sameSite: "lax",
			domain: "example.com",
			maxAge: 900_000,
		});
	});

	it("omits the domain attribute when no cookie domain is configured", () => {
		const csrf = createCsrfProtection({
			secret: SECRET,
			cookie: { secure: false, sameSite: "lax" },
		});
		const res = fakeResponse();

		csrf.issue(res);

		expect(res.calls[0]?.options).not.toHaveProperty("domain");
		expect(res.calls[0]?.options).toMatchObject({ secure: false });
	});
});

describe("csrf — origin / referer check", () => {
	it("classifies a request whose Origin equals the server origin as same-origin", () => {
		const req = fakeRequest({
			protocol: "https",
			host: "auth.example.com",
			headers: { origin: "https://auth.example.com" },
		});

		expect(checkRequestOrigin(req, [])).toBe("same-origin");
	});

	it("classifies an unrelated Origin as foreign", () => {
		const req = fakeRequest({ headers: { origin: "https://evil.example.com" } });

		expect(checkRequestOrigin(req, [])).toBe("foreign");
	});

	it("classifies an explicitly trusted Origin as trusted", () => {
		const req = fakeRequest({ headers: { origin: "https://app.example.com" } });

		expect(checkRequestOrigin(req, ["https://app.example.com"])).toBe("trusted");
	});

	it("classifies a missing Origin and Referer as absent rather than allowed", () => {
		// The #272 bug in one assertion: absence is a verdict the caller must
		// decide about, never an implicit pass.
		expect(checkRequestOrigin(fakeRequest({}), [])).toBe("absent");
	});

	it("falls back to the Referer's origin when Origin is absent", () => {
		const req = fakeRequest({
			headers: { referer: "https://auth.example.com/login?next=%2F" },
		});

		expect(checkRequestOrigin(req, [])).toBe("same-origin");
	});

	it("treats an opaque `Origin: null` as foreign", () => {
		const req = fakeRequest({ headers: { origin: "null" } });

		expect(checkRequestOrigin(req, [])).toBe("foreign");
	});

	it("honours the forwarded protocol when the app trusts its proxy", () => {
		const req = fakeRequest({
			protocol: "https",
			host: "auth.example.com",
			headers: { origin: "http://auth.example.com" },
		});

		expect(checkRequestOrigin(req, [])).toBe("foreign");
	});
});

describe("csrf — guard acceptance rule", () => {
	const buildApp = (opts: { trustedOrigins?: string[] } = {}) => {
		const csrf = createCsrfProtection({
			secret: SECRET,
			cookie: { secure: false, sameSite: "lax" },
		});
		const app = express();
		app.use(express.json());
		app.get("/csrf", createCsrfIssueHandler(csrf));
		app.post(
			"/act",
			createCsrfGuard({ csrf, trustedOrigins: opts.trustedOrigins ?? [] }),
			(_req, res) => {
				res.status(200).json({ ok: true });
			},
		);
		return { app, csrf };
	};

	it("rejects a request carrying neither an origin signal nor a token", async () => {
		const { app } = buildApp();

		const res = await request(app).post("/act").send({});

		expect(res.status).toBe(403);
		expect(res.body).toMatchObject({
			error: "access_denied",
			error_description: expect.any(String),
		});
	});

	it("accepts a header-less API client that presents a valid double-submit token", async () => {
		const { app, csrf } = buildApp();
		const token = csrf.mint();

		const res = await request(app)
			.post("/act")
			.set("Cookie", `${csrf.cookieName}=${token}`)
			.set(csrf.headerName, token)
			.send({});

		expect(res.status).toBe(200);
	});

	it("accepts a same-origin browser request that carries no token", async () => {
		const { app } = buildApp();
		const server = app.listen(0);
		try {
			const address = server.address();
			const port = typeof address === "object" && address !== null ? address.port : 0;

			const res = await request(server)
				.post("/act")
				.set("Origin", `http://127.0.0.1:${port}`)
				.send({});

			expect(res.status).toBe(200);
		} finally {
			server.close();
		}
	});

	it("rejects a foreign Origin even when a valid token is presented", async () => {
		// Deliberately stricter than "either arm passes": a foreign `Origin` is
		// positive evidence that a browser made this request from another site,
		// and the pre-#272 code already rejected it. A security fix must not
		// hand that back.
		const { app, csrf } = buildApp();
		const token = csrf.mint();

		const res = await request(app)
			.post("/act")
			.set("Origin", "https://evil.example.com")
			.set("Cookie", `${csrf.cookieName}=${token}`)
			.set(csrf.headerName, token)
			.send({});

		expect(res.status).toBe(403);
	});

	it("accepts an explicitly trusted cross-origin request", async () => {
		const { app } = buildApp({ trustedOrigins: ["https://app.example.com"] });

		const res = await request(app).post("/act").set("Origin", "https://app.example.com").send({});

		expect(res.status).toBe(200);
	});

	it("rejects a request whose token cookie and header disagree", async () => {
		const { app, csrf } = buildApp();

		const res = await request(app)
			.post("/act")
			.set("Cookie", `${csrf.cookieName}=${csrf.mint()}`)
			.set(csrf.headerName, csrf.mint())
			.send({});

		expect(res.status).toBe(403);
	});
});

describe("csrf — issue endpoint", () => {
	it("hands out a token, sets the paired cookie, and forbids caching", async () => {
		const csrf = createCsrfProtection({
			secret: SECRET,
			cookie: { secure: false, sameSite: "lax" },
		});
		const app = express();
		app.get("/csrf", createCsrfIssueHandler(csrf));

		const res = await request(app).get("/csrf");

		expect(res.status).toBe(200);
		expect(res.body).toMatchObject({
			csrf_token: expect.any(String),
			cookie_name: csrf.cookieName,
			header_name: csrf.headerName,
			expires_in: csrf.ttlSeconds,
		});
		expect(res.headers["cache-control"]).toContain("no-store");

		const setCookie = res.headers["set-cookie"] as unknown as string[];
		expect(setCookie.some((c) => c.startsWith(`${csrf.cookieName}=`))).toBe(true);
		expect(setCookie.some((c) => /HttpOnly/i.test(c))).toBe(false);

		// The issued cookie and the returned token are the same value — that is
		// what makes the client's job "copy the cookie into the header".
		const issued = setCookie
			.find((c) => c.startsWith(`${csrf.cookieName}=`))
			?.split(";")[0]
			?.slice(csrf.cookieName.length + 1);
		expect(decodeURIComponent(issued ?? "")).toBe(res.body.csrf_token);
	});
});
