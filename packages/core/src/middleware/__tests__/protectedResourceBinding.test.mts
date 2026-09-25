/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import type { Request, Response } from "express";
import { SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import type { Confirmation } from "#/grants/confirmation.mjs";
import { protectedResourceBindingMw } from "#/middleware/protectedResourceBinding.mjs";
import type {
	TokenBindingExtractContext,
	TokenBindingMechanism,
} from "#/middleware/tokenBinding.mjs";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Mint an unsigned-but-well-formed JWT. The middleware reads claims without
 * verifying — the endpoint downstream owns verification — so a real signature
 * would only slow the tests down without exercising anything.
 */
const mintToken = async (claims: Record<string, unknown>): Promise<string> =>
	new SignJWT(claims).setProtectedHeader({ alg: "HS256", typ: "at+jwt" }).sign(new Uint8Array(32));

const fakeReq = (authorization?: string): Request =>
	({
		headers: authorization === undefined ? {} : { authorization },
	}) as Request;

const fakeRes = () => {
	const r: Partial<Response> & {
		statusCode?: number;
		body?: unknown;
		headers: Record<string, string>;
	} = { headers: {} };
	r.status = vi.fn((code: number) => {
		r.statusCode = code;
		return r as Response;
	}) as Response["status"];
	r.json = vi.fn((body: unknown) => {
		r.body = body;
		return r as Response;
	}) as Response["json"];
	r.setHeader = vi.fn((name: string, value: string | number | readonly string[]) => {
		r.headers[name] = String(value);
		return r as Response;
	}) as Response["setHeader"];
	return r as Response & { statusCode?: number; body?: unknown; headers: Record<string, string> };
};

/** A mechanism that always succeeds with `confirmation`, recording its ctx. */
const succeedingMechanism = (
	kind: string,
	confirmation: Confirmation,
	seen?: { ctx?: TokenBindingExtractContext | undefined },
): TokenBindingMechanism => ({
	kind,
	intentExplicit: kind === "dpop",
	extract: async (_req, ctx) => {
		if (seen) seen.ctx = ctx;
		return { kind, confirmation };
	},
});

const nullMechanism = (kind: string): TokenBindingMechanism => ({
	kind,
	intentExplicit: kind === "dpop",
	extract: async () => null,
});

const throwingMechanism = (kind: string, err: Error): TokenBindingMechanism => ({
	kind,
	intentExplicit: kind === "dpop",
	extract: async () => {
		throw err;
	},
});

const JKT = "L0AXB6c64d2QW3rhCLLADhOMLf_7u2eTGH-q9ZGja24";
const X5T = "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2";

const run = async (mw: ReturnType<typeof protectedResourceBindingMw>, authorization?: string) => {
	const req = fakeReq(authorization);
	const res = fakeRes();
	const next = vi.fn();
	await mw(req, res, next);
	return { req, res, next };
};

// ---------------------------------------------------------------------------
// Pass-through cases — nothing to enforce
// ---------------------------------------------------------------------------

describe("protectedResourceBindingMw — pass-through", () => {
	it("calls next when there is no Authorization header", async () => {
		const { next, res } = await run(protectedResourceBindingMw({ mechanisms: [] }));
		expect(next).toHaveBeenCalledOnce();
		expect(res.status).not.toHaveBeenCalled();
	});

	it("calls next for a non-token scheme (client-authenticated introspection)", async () => {
		const { next } = await run(
			protectedResourceBindingMw({ mechanisms: [] }),
			"Basic Y2xpZW50OnNlY3JldA==",
		);
		expect(next).toHaveBeenCalledOnce();
	});

	it("calls next for an undecodable token — the endpoint's verifyJwt rejects it", async () => {
		const { next } = await run(protectedResourceBindingMw({ mechanisms: [] }), "Bearer not-a-jwt");
		expect(next).toHaveBeenCalledOnce();
	});

	it("calls next for an unbound token (no cnf claim)", async () => {
		const token = await mintToken({ sub: "u1" });
		const { next, req } = await run(
			protectedResourceBindingMw({ mechanisms: [] }),
			`Bearer ${token}`,
		);
		expect(next).toHaveBeenCalledOnce();
		expect(req.tokenBinding).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// The bug in #264 — a bound token replayed as a plain Bearer
// ---------------------------------------------------------------------------

describe("protectedResourceBindingMw — enforcement", () => {
	it("rejects a DPoP-bound token presented with the Bearer scheme (RFC 9449 §7.1)", async () => {
		const token = await mintToken({ sub: "u1", cnf: { jkt: JKT } });
		const { next, res } = await run(
			protectedResourceBindingMw({
				mechanisms: [succeedingMechanism("dpop", { jkt: JKT })],
			}),
			`Bearer ${token}`,
		);
		expect(next).not.toHaveBeenCalled();
		expect(res.statusCode).toBe(401);
		expect(res.body).toMatchObject({ error: "invalid_token" });
		expect(res.headers["WWW-Authenticate"]).toContain("DPoP");
	});

	it("accepts a DPoP-bound token whose proof matches, under the DPoP scheme", async () => {
		const token = await mintToken({ sub: "u1", cnf: { jkt: JKT } });
		const { next, req, res } = await run(
			protectedResourceBindingMw({
				mechanisms: [succeedingMechanism("dpop", { jkt: JKT })],
			}),
			`DPoP ${token}`,
		);
		expect(res.status).not.toHaveBeenCalled();
		expect(next).toHaveBeenCalledOnce();
		expect(req.tokenBinding).toEqual({ kind: "dpop", confirmation: { jkt: JKT } });
	});

	it("hands the presented access token to the mechanism so it can check ath", async () => {
		const token = await mintToken({ sub: "u1", cnf: { jkt: JKT } });
		const seen: { ctx?: TokenBindingExtractContext | undefined } = {};
		await run(
			protectedResourceBindingMw({
				mechanisms: [succeedingMechanism("dpop", { jkt: JKT }, seen)],
			}),
			`DPoP ${token}`,
		);
		expect(seen.ctx).toEqual({ boundAccessToken: token });
	});

	it("rejects when the proof's jkt is not the one the token is bound to", async () => {
		const token = await mintToken({ sub: "u1", cnf: { jkt: JKT } });
		const { next, res } = await run(
			protectedResourceBindingMw({
				mechanisms: [succeedingMechanism("dpop", { jkt: "some-other-thumbprint" })],
			}),
			`DPoP ${token}`,
		);
		expect(next).not.toHaveBeenCalled();
		expect(res.statusCode).toBe(401);
	});

	it("rejects when no proof is presented at all for a bound token", async () => {
		const token = await mintToken({ sub: "u1", cnf: { jkt: JKT } });
		const { next, res } = await run(
			protectedResourceBindingMw({ mechanisms: [nullMechanism("dpop")] }),
			`DPoP ${token}`,
		);
		expect(next).not.toHaveBeenCalled();
		expect(res.statusCode).toBe(401);
	});

	it("rejects a bound token when the deployment has no mechanisms left (fail closed)", async () => {
		// A deployment that turns the DPoP module off still has live bound
		// tokens in the wild; those must stop working, not silently downgrade
		// to Bearer.
		const token = await mintToken({ sub: "u1", cnf: { jkt: JKT } });
		const { next, res } = await run(
			protectedResourceBindingMw({ mechanisms: [] }),
			`DPoP ${token}`,
		);
		expect(next).not.toHaveBeenCalled();
		expect(res.statusCode).toBe(401);
	});

	it("rejects when the mechanism throws on the presented material", async () => {
		const token = await mintToken({ sub: "u1", cnf: { jkt: JKT } });
		const { next, res } = await run(
			protectedResourceBindingMw({
				mechanisms: [throwingMechanism("dpop", new Error("bad proof"))],
			}),
			`DPoP ${token}`,
		);
		expect(next).not.toHaveBeenCalled();
		expect(res.statusCode).toBe(401);
	});
});

// ---------------------------------------------------------------------------
// mTLS — RFC 8705 §3 keeps the Bearer wire scheme
// ---------------------------------------------------------------------------

describe("protectedResourceBindingMw — mTLS", () => {
	it("accepts an mTLS-bound token under the Bearer scheme", async () => {
		const token = await mintToken({ sub: "u1", cnf: { "x5t#S256": X5T } });
		const { next, req } = await run(
			protectedResourceBindingMw({
				mechanisms: [succeedingMechanism("mtls", { "x5t#S256": X5T })],
			}),
			`Bearer ${token}`,
		);
		expect(next).toHaveBeenCalledOnce();
		expect(req.tokenBinding).toEqual({ kind: "mtls", confirmation: { "x5t#S256": X5T } });
	});

	it("rejects an mTLS-bound token whose presented certificate differs", async () => {
		const token = await mintToken({ sub: "u1", cnf: { "x5t#S256": X5T } });
		const { next, res } = await run(
			protectedResourceBindingMw({
				mechanisms: [succeedingMechanism("mtls", { "x5t#S256": "another-cert" })],
			}),
			`Bearer ${token}`,
		);
		expect(next).not.toHaveBeenCalled();
		expect(res.statusCode).toBe(401);
	});

	it("rejects an mTLS-bound token presented under the DPoP scheme", async () => {
		const token = await mintToken({ sub: "u1", cnf: { "x5t#S256": X5T } });
		const { next, res } = await run(
			protectedResourceBindingMw({
				mechanisms: [succeedingMechanism("mtls", { "x5t#S256": X5T })],
			}),
			`DPoP ${token}`,
		);
		expect(next).not.toHaveBeenCalled();
		expect(res.statusCode).toBe(401);
	});
});

// ---------------------------------------------------------------------------
// Mechanism identity — a confirmation is only honoured from its owning kind
// ---------------------------------------------------------------------------

describe("protectedResourceBindingMw — mechanism identity", () => {
	it("does not let a non-DPoP mechanism satisfy a cnf.jkt binding", async () => {
		// `Confirmation` is a mechanism-extensible union, so a third-party
		// mechanism could emit `{ jkt }` without ever validating a DPoP proof.
		// Matching on the confirmation shape alone would hand it the binding.
		// Same stance the refresh-token grant takes.
		const token = await mintToken({ sub: "u1", cnf: { jkt: JKT } });
		const { next, res } = await run(
			protectedResourceBindingMw({
				mechanisms: [succeedingMechanism("impostor", { jkt: JKT })],
			}),
			`DPoP ${token}`,
		);
		expect(next).not.toHaveBeenCalled();
		expect(res.statusCode).toBe(401);
	});

	it("does not let a non-mTLS mechanism satisfy a cnf.x5t#S256 binding", async () => {
		const token = await mintToken({ sub: "u1", cnf: { "x5t#S256": X5T } });
		const { next, res } = await run(
			protectedResourceBindingMw({
				mechanisms: [succeedingMechanism("impostor", { "x5t#S256": X5T })],
			}),
			`Bearer ${token}`,
		);
		expect(next).not.toHaveBeenCalled();
		expect(res.statusCode).toBe(401);
	});

	it("picks the mechanism that owns the cnf variant, not the first to succeed", async () => {
		// An ambient mTLS mechanism fires on every request behind a proxy that
		// injects a client cert. It must not shadow the DPoP binding the token
		// actually names.
		const token = await mintToken({ sub: "u1", cnf: { jkt: JKT } });
		const { next, req } = await run(
			protectedResourceBindingMw({
				mechanisms: [
					succeedingMechanism("mtls", { "x5t#S256": X5T }),
					succeedingMechanism("dpop", { jkt: JKT }),
				],
			}),
			`DPoP ${token}`,
		);
		expect(next).toHaveBeenCalledOnce();
		expect(req.tokenBinding).toEqual({ kind: "dpop", confirmation: { jkt: JKT } });
	});
});

// ---------------------------------------------------------------------------
// Compound cnf — the AS never mints one
// ---------------------------------------------------------------------------

describe("protectedResourceBindingMw — compound cnf", () => {
	it("rejects a token carrying both jkt and x5t#S256", async () => {
		const token = await mintToken({ sub: "u1", cnf: { jkt: JKT, "x5t#S256": X5T } });
		const { next, res } = await run(
			protectedResourceBindingMw({
				mechanisms: [succeedingMechanism("dpop", { jkt: JKT })],
			}),
			`DPoP ${token}`,
		);
		expect(next).not.toHaveBeenCalled();
		expect(res.statusCode).toBe(401);
	});
});

describe("protectedResourceBindingMw — a server-side outage", () => {
	// The mechanism could not reach a verdict: the credential is not at fault,
	// so the resource does not challenge it. `401 invalid_token` would tell the
	// client to replace a token that is fine — it would refresh, and meet the
	// same outage at the token endpoint. RFC 6750 §3.1's codes describe request
	// and token faults; a server that cannot answer says 503.
	it("answers 503 with the refusal's code and description, and no challenge", async () => {
		const token = await mintToken({ sub: "u1", cnf: { jkt: JKT } });
		const err = Object.assign(new Error("ECONNREFUSED"), {
			code: "temporarily_unavailable",
			unavailable: "the replay store cannot be read; retry later",
		});
		const logger = {
			trace: vi.fn(),
			debug: vi.fn(),
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
			fatal: vi.fn(),
			child() {
				return this;
			},
		};
		const { next, res } = await run(
			protectedResourceBindingMw({
				mechanisms: [throwingMechanism("dpop", err)],
				logger: logger as never,
			}),
			`DPoP ${token}`,
		);
		expect(next).not.toHaveBeenCalled();
		expect(res.statusCode).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "the replay store cannot be read; retry later",
		});
		expect(res.headers["WWW-Authenticate"]).toBeUndefined();
		// The layer that answers the 503 owns its one error-level line.
		expect(logger.warn).not.toHaveBeenCalled();
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{ mechanism: "dpop", code: "temporarily_unavailable" },
			"protected_resource_binding_unavailable",
		);
	});

	it("logs the refusal's cause and reason, projected, when the mechanism gives them", async () => {
		const token = await mintToken({ sub: "u1", cnf: { jkt: JKT } });
		const storeError = Object.assign(
			new Error("READONLY You can't write against a read only replica."),
			{
				name: "ReplyError",
				command: { name: "set", args: ["dpop-proof:jkt", "refused-command-marker"] },
			},
		);
		const err = Object.assign(new Error("replay store down", { cause: storeError }), {
			code: "temporarily_unavailable",
			unavailable: "the replay store cannot be read; retry later",
			reason: "replay_store_unavailable",
		});
		const logger = {
			trace: vi.fn(),
			debug: vi.fn(),
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
			fatal: vi.fn(),
			child() {
				return this;
			},
		};
		const { res } = await run(
			protectedResourceBindingMw({
				mechanisms: [throwingMechanism("dpop", err)],
				logger: logger as never,
			}),
			`DPoP ${token}`,
		);
		expect(res.statusCode).toBe(503);
		expect(logger.warn).not.toHaveBeenCalled();
		expect(logger.error).toHaveBeenCalledTimes(1);
		const [line, event] = logger.error.mock.calls[0] as [Record<string, unknown>, string];
		expect(event).toBe("protected_resource_binding_unavailable");
		expect(line).toMatchObject({
			mechanism: "dpop",
			code: "temporarily_unavailable",
			reason: "replay_store_unavailable",
			err: { name: "ReplyError", command: { name: "set" } },
		});
		expect(line.err).not.toBeInstanceOf(Error);
		expect(JSON.stringify(logger.error.mock.calls)).not.toContain("refused-command-marker");
	});

	it("logs a failed proof once at warn: its code, the refusal's reason, and its projection with the cause inside", async () => {
		const token = await mintToken({ sub: "u1", cnf: { "x5t#S256": X5T } });
		let parseError: unknown;
		try {
			JSON.parse('{"x5c":"refused-material-marker');
		} catch (err) {
			parseError = err;
		}
		const refusal = Object.assign(new Error("header parse failure", { cause: parseError }), {
			code: "invalid_certificate",
			reason: "malformed_header",
		});
		const logger = {
			trace: vi.fn(),
			debug: vi.fn(),
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
			fatal: vi.fn(),
			child() {
				return this;
			},
		};
		const { res } = await run(
			protectedResourceBindingMw({
				mechanisms: [throwingMechanism("mtls", refusal)],
				logger: logger as never,
			}),
			`Bearer ${token}`,
		);
		expect(res.statusCode).toBe(401);
		expect(logger.error).not.toHaveBeenCalled();
		// Beside it, the sender-constraint refusal's own line
		// (`sender_constraint_rejected`, reason `proof_invalid`).
		const proofLines = logger.warn.mock.calls.filter(
			([, event]) => event === "protected_resource_binding_proof_invalid",
		);
		expect(proofLines).toHaveLength(1);
		expect(logger.warn).toHaveBeenCalledWith(
			{
				mechanism: "mtls",
				code: "invalid_certificate",
				reason: "malformed_header",
				err: expect.objectContaining({
					name: "Error",
					detail: "header parse failure",
					reason: "malformed_header",
					cause: expect.objectContaining({ name: "SyntaxError" }),
				}),
			},
			"protected_resource_binding_proof_invalid",
		);
		expect(JSON.stringify(logger.warn.mock.calls)).not.toContain("refused-material-marker");
	});

	it("reads a bare code as a failed proof: only the mechanism can say it was an outage", async () => {
		const token = await mintToken({ sub: "u1", cnf: { jkt: JKT } });
		const bare = Object.assign(new Error("down"), { code: "temporarily_unavailable" });
		const { res } = await run(
			protectedResourceBindingMw({ mechanisms: [throwingMechanism("dpop", bare)] }),
			`DPoP ${token}`,
		);
		expect(res.statusCode).toBe(401);
		expect(res.body).toMatchObject({ error: "invalid_token" });
	});
});

describe("protectedResourceBindingMw — the nonce challenge (#530, RFC 9449 §9)", () => {
	it("answers 401 use_dpop_nonce with the challenge naming it and the DPoP-Nonce header", async () => {
		const token = await mintToken({ sub: "u1", cnf: { jkt: JKT } });
		const err = Object.assign(new Error("no nonce"), {
			code: "use_dpop_nonce",
			retryInstruction:
				"a server-provided nonce is required; retry with the value of the DPoP-Nonce header",
			responseHeaders: { "DPoP-Nonce": "n1" },
		});
		const { next, res } = await run(
			protectedResourceBindingMw({ mechanisms: [throwingMechanism("dpop", err)] }),
			`DPoP ${token}`,
		);
		expect(next).not.toHaveBeenCalled();
		expect(res.statusCode).toBe(401);
		expect(res.body).toMatchObject({ error: "use_dpop_nonce" });
		expect(res.headers["WWW-Authenticate"]).toBe('DPoP error="use_dpop_nonce"');
		expect(res.headers["DPoP-Nonce"]).toBe("n1");
	});

	it("challenges with whatever code a retry instruction carries, and treats a bare code as a failed proof (v0.13.0 audit)", async () => {
		const token = await mintToken({ sub: "u1", cnf: { jkt: JKT } });
		const retry = Object.assign(new Error("nonce"), {
			code: "use_fresh_nonce",
			retryInstruction: "retry with the value of the Fresh-Nonce header",
		});
		const asked = await run(
			protectedResourceBindingMw({ mechanisms: [throwingMechanism("dpop", retry)] }),
			`DPoP ${token}`,
		);
		expect(asked.res.statusCode).toBe(401);
		expect(asked.res.headers["WWW-Authenticate"]).toBe('DPoP error="use_fresh_nonce"');
		expect(asked.res.body).toMatchObject({
			error: "use_fresh_nonce",
			error_description: "retry with the value of the Fresh-Nonce header",
		});

		// The code alone is not an instruction: the mechanism did not say retry.
		const bare = Object.assign(new Error("nonce"), { code: "use_dpop_nonce" });
		const refused = await run(
			protectedResourceBindingMw({ mechanisms: [throwingMechanism("dpop", bare)] }),
			`DPoP ${token}`,
		);
		expect(refused.res.statusCode).toBe(401);
		expect(refused.res.headers["WWW-Authenticate"]).not.toContain("use_dpop_nonce");
	});

	it("sets the headers a succeeding binding carries, then continues", async () => {
		const token = await mintToken({ sub: "u1", cnf: { jkt: JKT } });
		const mechanism: TokenBindingMechanism = {
			kind: "dpop",
			intentExplicit: true,
			extract: async () => ({
				kind: "dpop",
				confirmation: { jkt: JKT },
				responseHeaders: { "DPoP-Nonce": "n2" },
			}),
		};
		const { next, res } = await run(
			protectedResourceBindingMw({ mechanisms: [mechanism] }),
			`DPoP ${token}`,
		);
		expect(next).toHaveBeenCalledOnce();
		expect(res.headers["DPoP-Nonce"]).toBe("n2");
	});
});
