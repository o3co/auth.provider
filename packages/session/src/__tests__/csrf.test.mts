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
 * The session routes' CSRF defence: a signed double-submit token, a strict
 * same-origin `Origin` / `Referer` check with its own trust list (not
 * `cors.allowedOrigins`: a CORS policy is not a CSRF policy), and the
 * acceptance rule that composes them. A missing `Origin` and `Referer` is
 * never an implicit pass.
 */

import type { CsrfTokenSigner, Logger } from "@o3co/auth-provider-core";
import { createTestCsrfTokenSigner } from "@o3co/auth-provider-core/testing";
import express, { type NextFunction, type Request, type Response } from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import type { CsrfProtectionOptions } from "#/csrf.mjs";
import { sessionSectionSchema } from "#/module.mjs";
import {
	checkRequestOrigin,
	createCsrfGuard,
	createCsrfIssueHandler,
	createCsrfProtection,
	createCsrfProtectionFromConfig,
	createSessionCsrfGuard,
	MAX_CSRF_TTL_SECONDS,
} from "#/csrf.mjs";

/** What the tokens are signed with: the `csrfTokenSigner` slot's double. */
const SIGNER = createTestCsrfTokenSigner();

const makeCsrf = (overrides: Partial<CsrfProtectionOptions> = {}) =>
	createCsrfProtection({ signer: SIGNER, ...overrides });

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

	it("rejects a well-formed token signed by another signer", () => {
		// This is what separates a signed double-submit from a plain one: a
		// subdomain that can write the parent-domain cookie still cannot forge
		// material the provider will accept.
		const attacker = createCsrfProtection({ signer: createTestCsrfTokenSigner() });
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
		const csrf = createCsrfProtection({ signer: SIGNER, ttlSeconds: 60, now: () => now });
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

/** The refusal of a protection built without a signer, or with one that breaks the contract. */
const REFUSED = "pass the csrfTokenSigner slot's signer, or createSessionCsrfTokenSigner(secret)";

/** `signature` with its first character changed: every bit of it is signature, never padding. */
const tampered = (signature: string): string =>
	`${signature.startsWith("A") ? "B" : "A"}${signature.slice(1)}`;

/** A signer over the double's key whose signatures are `length` characters: its signatures joined, then cut. */
const signerOfLength = (length: number): CsrfTokenSigner => {
	const sign = (payload: string): string => {
		let joined = "";
		for (let block = 0; joined.length < length; block++) {
			joined += SIGNER.sign(`${block}:${payload}`);
		}
		return joined.slice(0, length);
	};
	return {
		sign,
		verify: (payload, signature) =>
			typeof payload === "string" && typeof signature === "string" && signature === sign(payload),
	};
};

describe("csrf — the signer at construction", () => {
	const session = { name: "auth.session", secure: true, sameSite: "lax" as const, domain: null };

	it.each([
		["no signer", {}],
		["a secret in place of a signer", { secret: "a-session-secret.at-least-32-bytes.ok" }],
		["a signer without verify", { signer: { sign: SIGNER.sign } }],
		["a signer without sign", { signer: { verify: SIGNER.verify } }],
	])("createCsrfProtection refuses %s, saying what to pass", (_what, options) => {
		expect(() => createCsrfProtection(options as never)).toThrow(
			`csrf: signer is required: ${REFUSED}`,
		);
	});

	it("createCsrfProtectionFromConfig refuses a call without a signer, saying what to pass", () => {
		expect(() => createCsrfProtectionFromConfig(session, undefined as never)).toThrow(
			`csrf: signer is required: ${REFUSED}`,
		);
		expect(() => createCsrfProtectionFromConfig(session, {} as never)).toThrow(
			`csrf: signer is required: ${REFUSED}`,
		);
	});

	/** A signer over the double's key whose `sign` and `verify` are replaced by `members`. */
	const breaking = (members: {
		sign?: (payload: string) => unknown;
		verify?: (payload: string, signature: string) => unknown;
	}): CsrfTokenSigner => ({ ...SIGNER, ...members }) as unknown as CsrfTokenSigner;

	it.each([
		["one signature for every payload", breaking({ sign: () => SIGNER.sign("constant") })],
		["a verify that accepts anything", breaking({ verify: () => true })],
		["a verify that ignores the payload", breaking({ verify: (_p, s) => s.length > 0 })],
		["a verify that refuses everything", breaking({ verify: () => false })],
		[
			"a verify that throws",
			breaking({
				verify: () => {
					throw new Error("verify failed");
				},
			}),
		],
		["an async verify", breaking({ verify: async (p, s) => SIGNER.verify(p, s) })],
		["an async sign", breaking({ sign: async (p) => SIGNER.sign(p) })],
		[
			"a sign that throws",
			breaking({
				sign: () => {
					throw new Error("sign failed");
				},
			}),
		],
		["a padded base64url signature", breaking({ sign: (p) => `${SIGNER.sign(p)}=` })],
		[
			"a standard base64 signature",
			breaking({ sign: (p) => Buffer.from(SIGNER.sign(p), "base64url").toString("base64") }),
		],
		["a signature of 21 characters, under core's bound", signerOfLength(21)],
		["a signature of 513 characters, over core's bound", signerOfLength(513)],
	])("createCsrfProtection refuses a signer with %s, naming the slot", (_what, signer) => {
		expect(() => createCsrfProtection({ signer })).toThrow(
			/^csrf: the signer does not keep the csrfTokenSigner contract \(.+\): pass the csrfTokenSigner slot's signer, or createSessionCsrfTokenSigner\(secret\)$/,
		);
	});

	it("builds over a signer that keeps the contract", () => {
		expect(() => createCsrfProtection({ signer: createTestCsrfTokenSigner() })).not.toThrow();
	});

	it.each([22, 512])(
		"builds over a signer whose signatures are %i characters, at core's bound, and its tokens verify",
		(length) => {
			const csrf = createCsrfProtection({ signer: signerOfLength(length) });
			const token = csrf.mint();
			expect(
				csrf.verify(
					fakeRequest({
						cookies: { [csrf.cookieName]: token },
						headers: { [csrf.headerName]: token },
					}),
				),
			).toBe("valid");
		},
	);

	it("mints <expiry>.<nonce>.<signature>, the signature the signer answers for <expiry>.<nonce>", () => {
		const token = createCsrfProtectionFromConfig(session, { signer: SIGNER }).mint();
		const [expiry, nonce, signature] = token.split(".");
		expect(SIGNER.verify(`${expiry}.${nonce}`, signature as string)).toBe(true);
	});
});

describe("csrf — what verify answers", () => {
	/**
	 * A signer that keeps the contract for every payload but a token's, where
	 * `verify` answers `answer` for a signature it did not make: what a signer
	 * past construction could still do.
	 */
	const answeringForTokens = (answer: () => unknown): CsrfTokenSigner =>
		({
			sign: SIGNER.sign,
			verify: (payload: string, signature: string) => {
				if (SIGNER.verify(payload, signature)) return true;
				return /^\d+\./.test(payload) ? answer() : false;
			},
		}) as unknown as CsrfTokenSigner;

	/** A well-formed token whose signature the signer did not make. */
	const forged = (csrf: ReturnType<typeof makeCsrf>): string => {
		const [expiry, nonce, signature] = csrf.mint().split(".");
		return `${expiry}.${nonce}.${tampered(signature as string)}`;
	};

	const pair = (csrf: ReturnType<typeof makeCsrf>, token: string) =>
		fakeRequest({
			cookies: { [csrf.cookieName]: token },
			headers: { [csrf.headerName]: token },
		});

	it.each([
		["a promise", () => Promise.resolve(false)],
		["a truthy string", () => "false"],
		["1", () => 1],
		["an object", () => ({})],
	])("accepts only true: a verify answering %s for a forged token refuses it", (_what, answer) => {
		const csrf = makeCsrf({ signer: answeringForTokens(answer) });
		expect(csrf.verify(pair(csrf, forged(csrf)))).toBe("invalid");
	});

	it("reads a verify that throws as a refusal: the check answers, and the guard's check never throws", () => {
		const signer = answeringForTokens(() => {
			throw new Error("the signing service is down");
		});
		const csrf = makeCsrf({ signer });
		const token = forged(csrf);
		expect(csrf.verify(pair(csrf, token))).toBe("invalid");
		const guard = createSessionCsrfGuard({ csrf });
		expect(guard.check(pair(csrf, token))).toEqual({
			outcome: "refused",
			reason: "token_invalid",
		});
	});
});

describe("csrf — the signer after construction", () => {
	const pair = (csrf: ReturnType<typeof makeCsrf>, token: string) =>
		fakeRequest({
			cookies: { [csrf.cookieName]: token },
			headers: { [csrf.headerName]: token },
		});

	/** A well-formed token whose signature the signer did not make. */
	const forged = (csrf: ReturnType<typeof makeCsrf>): string => {
		const [expiry, nonce, signature] = csrf.mint().split(".");
		return `${expiry}.${nonce}.${tampered(signature as string)}`;
	};

	it("checks with the verify it was built over: a verify replaced on the signer afterwards passes no forged token", () => {
		const signer: { sign: CsrfTokenSigner["sign"]; verify: CsrfTokenSigner["verify"] } = {
			sign: SIGNER.sign,
			verify: SIGNER.verify,
		};
		const csrf = makeCsrf({ signer });
		const token = forged(csrf);
		signer.verify = () => true;
		expect(csrf.verify(pair(csrf, token))).toBe("invalid");
		expect(createSessionCsrfGuard({ csrf }).check(pair(csrf, token))).toEqual({
			outcome: "refused",
			reason: "token_invalid",
		});
	});

	it("signs with the sign it was built over: a sign replaced on the signer afterwards changes no token it mints", () => {
		const signer: { sign: CsrfTokenSigner["sign"]; verify: CsrfTokenSigner["verify"] } = {
			sign: SIGNER.sign,
			verify: SIGNER.verify,
		};
		const csrf = makeCsrf({ signer });
		signer.sign = () => "A".repeat(43);
		const token = csrf.mint();
		const [expiry, nonce, signature] = token.split(".");
		expect(SIGNER.verify(`${expiry}.${nonce}`, signature as string)).toBe(true);
		expect(csrf.verify(pair(csrf, token))).toBe("valid");
	});

	it("reads sign and verify off the signer once, so accessors that answer other methods later change nothing", () => {
		let probed = false;
		const signer = {
			get sign() {
				return probed ? () => "A".repeat(43) : SIGNER.sign;
			},
			get verify() {
				return probed ? () => true : SIGNER.verify;
			},
		} as CsrfTokenSigner;
		const csrf = makeCsrf({ signer });
		probed = true;
		expect(csrf.verify(pair(csrf, forged(csrf)))).toBe("invalid");
		const [expiry, nonce, signature] = csrf.mint().split(".");
		expect(SIGNER.verify(`${expiry}.${nonce}`, signature as string)).toBe(true);
	});
});

describe("csrf — a token's expiry", () => {
	const NOW_MS = 1_800_000_000_000;
	const nowSeconds = NOW_MS / 1000;

	/** A token expiring at `expiry`, signed by the protection's signer. */
	const tokenExpiringAt = (expiry: number): string => {
		const payload = `${expiry}.ZXhwaXJ5LWJvdW5kLW5vbmNlLXRlc3Q`;
		return `${payload}.${SIGNER.sign(payload)}`;
	};

	const verdictFor = (token: string) => {
		const csrf = createCsrfProtection({ signer: SIGNER, ttlSeconds: 3600, now: () => NOW_MS });
		return csrf.verify(
			fakeRequest({
				cookies: { [csrf.cookieName]: token },
				headers: { [csrf.headerName]: token },
			}),
		);
	};

	it("accepts a token expiring up to ttlSeconds and 60 seconds of clock skew from now", () => {
		expect(verdictFor(tokenExpiringAt(nowSeconds + 3600))).toBe("valid");
		expect(verdictFor(tokenExpiringAt(nowSeconds + 3600 + 60))).toBe("valid");
	});

	it("refuses a well-signed token expiring later than that, which issue never mints", () => {
		expect(verdictFor(tokenExpiringAt(nowSeconds + 3600 + 61))).toBe("invalid");
		expect(verdictFor(tokenExpiringAt(4_102_444_800))).toBe("invalid");
	});
});

/**
 * `ttlSeconds` is used in arithmetic *and* stringified into the token, so a
 * value that is not a positive integer does not fail loudly — it silently
 * disables the token arm. The zod schema catches this for configs that go
 * through it; this is the guard for the ones that do not (hand-built objects
 * in tests and embedders, which the schema never sees).
 */
describe("csrf — ttlSeconds validation at construction", () => {
	it.each([
		["a decimal", 7200.5],
		["zero", 0],
		["a negative value", -1],
		["NaN", Number.NaN],
		["Infinity", Number.POSITIVE_INFINITY],
		["a value beyond the ceiling", MAX_CSRF_TTL_SECONDS + 1],
	])("throws on %s", (_label, ttlSeconds) => {
		expect(() => createCsrfProtection({ signer: SIGNER, ttlSeconds })).toThrow(/ttlSeconds/);
	});

	it("accepts the ceiling itself", () => {
		expect(() =>
			createCsrfProtection({ signer: SIGNER, ttlSeconds: MAX_CSRF_TTL_SECONDS }),
		).not.toThrow();
	});

	it("throws rather than silently flooring a decimal", () => {
		// Rounding would hide an operator's typo behind a working system, and
		// the value it silently picked would not be the one they wrote.
		expect(() => createCsrfProtection({ signer: SIGNER, ttlSeconds: 7200.5 })).toThrow();
	});

	it("agrees with the session section's schema about what is acceptable", () => {
		// Two guards, one rule. If either side's bounds drift this fails.
		const cases = [7200, MAX_CSRF_TTL_SECONDS, 1, 0, -1, 7200.5, MAX_CSRF_TTL_SECONDS + 1];
		for (const ttlSeconds of cases) {
			const schemaAccepts = sessionSectionSchema.shape.csrf.unwrap().safeParse({
				trustedOrigins: [],
				ttlSeconds,
			}).success;
			let constructorAccepts = true;
			try {
				createCsrfProtection({ signer: SIGNER, ttlSeconds });
			} catch {
				constructorAccepts = false;
			}
			expect({ ttlSeconds, schemaAccepts }).toEqual({
				ttlSeconds,
				schemaAccepts: constructorAccepts,
			});
		}
	});

	it("mints a token matching the wire shape for every accepted ttl", () => {
		// The failure mode this closes: a token whose expiry field does not
		// match the shape the verifier requires is unverifiable the instant it
		// is issued, so `GET /session/csrf` would hand out material that
		// `POST /session/login` then rejects.
		const wireShape = /^\d{1,15}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}$/;
		for (const ttlSeconds of [1, 60, 7200, MAX_CSRF_TTL_SECONDS]) {
			const csrf = createCsrfProtection({ signer: SIGNER, ttlSeconds });
			const token = csrf.mint();
			expect(token).toMatch(wireShape);
			// And it round-trips, which the shape alone does not prove.
			expect(
				csrf.verify(
					fakeRequest({
						cookies: { [csrf.cookieName]: token },
						headers: { [csrf.headerName]: token },
					}),
				),
			).toBe("valid");
		}
	});

	it("mints a verifiable token when the clock seam returns a fractional epoch", () => {
		// `Date.now()` is integral in practice, but a seam or a faked clock need
		// not be — and the expiry is floored, not the raw sum.
		const csrf = createCsrfProtection({
			signer: SIGNER,
			ttlSeconds: 7200,
			now: () => 1_000_000_000_123.7,
		});
		const token = csrf.mint();

		expect(token).toMatch(/^\d{1,15}\./);
		expect(
			csrf.verify(
				fakeRequest({
					cookies: { [csrf.cookieName]: token },
					headers: { [csrf.headerName]: token },
				}),
			),
		).toBe("valid");
	});
});

describe("csrf — cookie issuance", () => {
	it("writes a JS-readable cookie mirroring the session cookie's transport attributes", () => {
		const csrf = createCsrfProtection({
			signer: SIGNER,
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
			signer: SIGNER,
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
		// Absence is a verdict the caller must decide about, never an implicit
		// pass.
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
			signer: SIGNER,
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
		// Bound to the loopback address the request dials: a hostless listen
		// can share its port with another process's 127.0.0.1 socket.
		const server = await new Promise<ReturnType<typeof app.listen>>((resolve) => {
			const listening = app.listen(0, "127.0.0.1", () => resolve(listening));
		});
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
		// positive evidence that a browser made this request from another site.
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
			signer: SIGNER,
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

describe("csrf — what a rejection logs of the caller's request", () => {
	/** A line break, a terminal escape, a NUL and a bell, then 10 000 characters. */
	const HOSTILE = `/act\r\nFORGED csrf_token_rejected\u001b[31m\u0000\u0007${"a".repeat(10_000)}`;
	// biome-ignore lint/suspicious/noControlCharactersInRegex: a control character is what must not be logged.
	const CONTROL = /[\u0000-\u001f\u007f]/;
	/** What an assertion needs of a logged string: a failure prints this, not the string. */
	const shapeOf = (text: unknown) => ({
		string: typeof text === "string",
		control: CONTROL.test(String(text)),
		within200: String(text).length <= 200,
	});
	const BOUNDED = { string: true, control: false, within200: true };

	const spyLogger = () => {
		const logger = {
			trace: vi.fn(),
			debug: vi.fn(),
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
			fatal: vi.fn(),
			child: () => logger,
		};
		return logger;
	};

	/**
	 * The guard, called as Express calls it, on a request whose `path` is
	 * what a lenient parser or another server in front could hand it — a real
	 * HTTP client refuses to send a line break in a request target.
	 */
	const reject = (headers: Record<string, string>, path: string) => {
		const logger = spyLogger();
		const guard = createCsrfGuard({
			csrf: makeCsrf({ cookie: { secure: false, sameSite: "lax" } }),
			logger: logger as unknown as Logger,
		});
		const res = {
			statusCode: 0,
			status(code: number) {
				this.statusCode = code;
				return this;
			},
			json() {
				return this;
			},
		};
		const next = vi.fn();
		guard(
			Object.assign(fakeRequest({ headers }), { path }),
			res as unknown as Response,
			next as unknown as NextFunction,
		);
		expect(res.statusCode).toBe(403);
		expect(next).not.toHaveBeenCalled();
		return logger;
	};

	/** The one warn line, and nothing at another level. */
	const onlyWarn = (logger: ReturnType<typeof spyLogger>, event: string) => {
		expect(logger.warn).toHaveBeenCalledTimes(1);
		expect(logger.error).not.toHaveBeenCalled();
		expect(logger.info).not.toHaveBeenCalled();
		const [line, name] = logger.warn.mock.calls[0] as [Record<string, unknown>, string];
		expect(name).toBe(event);
		return line;
	};

	it("logs a foreign origin's rejection with the path and the origin sanitised and capped", () => {
		const line = onlyWarn(
			reject({ origin: `https://evil.example\r\n\u001b[31m${"e".repeat(10_000)}` }, HOSTILE),
			"csrf_origin_rejected",
		);
		expect(shapeOf(line.path)).toEqual(BOUNDED);
		expect(shapeOf(line.origin)).toEqual(BOUNDED);
		expect(String(line.path).startsWith("/act??FORGED")).toBe(true);
	});

	it("logs a token rejection with the path sanitised and capped", () => {
		const line = onlyWarn(reject({}, HOSTILE), "csrf_token_rejected");
		expect(line.verdict).toBe("absent");
		expect(shapeOf(line.path)).toEqual(BOUNDED);
	});

	it("caps a 10 000-character path a real request carries", async () => {
		const logger = spyLogger();
		const app = express();
		app.post(
			/^\/act/,
			createCsrfGuard({
				csrf: makeCsrf({ cookie: { secure: false, sameSite: "lax" } }),
				logger: logger as unknown as Logger,
			}),
			(_req, res) => {
				res.status(200).json({ ok: true });
			},
		);

		const res = await request(app)
			.post(`/act/${"a".repeat(10_000)}`)
			.send({});

		expect(res.status).toBe(403);
		const line = onlyWarn(logger, "csrf_token_rejected");
		expect(shapeOf(line.path)).toEqual(BOUNDED);
	});

	it("still logs an ordinary path and origin exactly", () => {
		const line = onlyWarn(
			reject({ origin: "https://evil.example" }, "/session/login"),
			"csrf_origin_rejected",
		);
		expect(line).toEqual({ origin: "https://evil.example", path: "/session/login" });
	});
});
