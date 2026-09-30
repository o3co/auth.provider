/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import { readFileSync } from "node:fs";
import type { Request, Response } from "express";
import { describe, expect, it, vi } from "vitest";
import type { TokenBinding } from "#/grants/tokenBinding.mjs";
import {
	resolveTokenBindingSettings,
	type TokenBindingMechanism,
	tokenBindingMw,
} from "#/middleware/tokenBinding.mjs";

const fakeReq = () => ({}) as Request;
const fakeRes = () => {
	const r: Partial<Response> = {};
	r.status = vi.fn(() => r as Response);
	r.json = vi.fn(() => r as Response);
	r.setHeader = vi.fn(() => r as Response);
	return r as Response;
};

const fakeDPoP: TokenBinding = { kind: "dpop", confirmation: { jkt: "AAA" } };
const fakeMtls: TokenBinding = {
	kind: "mtls",
	confirmation: { "x5t#S256": "BBB" },
};

const dpopMechanism = (result: TokenBinding | null | Error): TokenBindingMechanism => ({
	kind: "dpop",
	intentExplicit: true,
	extract: async () => {
		if (result instanceof Error) throw result;
		return result;
	},
});

const mtlsMechanism = (result: TokenBinding | null | Error): TokenBindingMechanism => ({
	kind: "mtls",
	intentExplicit: false,
	extract: async () => {
		if (result instanceof Error) throw result;
		return result;
	},
});

/** A second ambient mechanism beside mTLS, always succeeding. */
const secondAmbient: TokenBindingMechanism = {
	kind: "mtls-secondary",
	intentExplicit: false,
	extract: async () => ({
		kind: "mtls-secondary",
		confirmation: { "x5t#S256": "CCC" },
	}),
};

/** A second explicit-intent mechanism beside DPoP, always succeeding. */
const secondExplicit: TokenBindingMechanism = {
	kind: "http-sig",
	intentExplicit: true,
	extract: async () => ({
		kind: "http-sig",
		confirmation: { jkt: "OTHER" },
	}),
};

const spyLogger = () => ({
	trace: vi.fn(),
	debug: vi.fn(),
	info: vi.fn(),
	warn: vi.fn(),
	error: vi.fn(),
	fatal: vi.fn(),
	child() {
		return this;
	},
});

describe("tokenBindingMw", () => {
	it("is a no-op when mechanisms is empty", async () => {
		const mw = tokenBindingMw({ mechanisms: [], dispatchPolicy: "intent-explicit" });
		const req = fakeReq();
		const res = fakeRes();
		const next = vi.fn();
		await mw(req, res, next);
		expect(next).toHaveBeenCalledOnce();
		expect(req.tokenBinding).toBeUndefined();
	});

	it("writes the binding from a single succeeding mechanism", async () => {
		const mw = tokenBindingMw({
			mechanisms: [dpopMechanism(fakeDPoP)],
			dispatchPolicy: "intent-explicit",
		});
		const req = fakeReq();
		const res = fakeRes();
		const next = vi.fn();
		await mw(req, res, next);
		expect(next).toHaveBeenCalledOnce();
		expect(req.tokenBinding).toEqual(fakeDPoP);
	});

	it("leaves req.tokenBinding undefined when all mechanisms return null", async () => {
		const mw = tokenBindingMw({
			mechanisms: [dpopMechanism(null), mtlsMechanism(null)],
			dispatchPolicy: "intent-explicit",
		});
		const req = fakeReq();
		const res = fakeRes();
		const next = vi.fn();
		await mw(req, res, next);
		expect(next).toHaveBeenCalledOnce();
		expect(req.tokenBinding).toBeUndefined();
	});

	it("emits 400 invalid_dpop_proof when a mechanism throws with a snake_case code", async () => {
		const err = Object.assign(new Error("bad sig"), { code: "invalid_dpop_proof" });
		const mw = tokenBindingMw({
			mechanisms: [dpopMechanism(err)],
			dispatchPolicy: "intent-explicit",
		});
		const req = fakeReq();
		const res = fakeRes();
		const next = vi.fn();
		await mw(req, res, next);
		expect(next).not.toHaveBeenCalled();
		expect(res.status).toHaveBeenCalledWith(400);
		expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "invalid_dpop_proof" }));
	});

	it("hard-fails (no downgrade) when an earlier mechanism succeeded and a later one throws", async () => {
		// Pins the no-downgrade rule under mixed success/failure:
		// a successful explicit mechanism must NOT survive a subsequent
		// mechanism's invalid material — the entire request is rejected
		// rather than silently downgraded to the partial binding.
		const err = Object.assign(new Error("bad cert"), { code: "invalid_mtls_cert" });
		const mw = tokenBindingMw({
			mechanisms: [dpopMechanism(fakeDPoP), mtlsMechanism(err)],
			dispatchPolicy: "intent-explicit",
		});
		const req = fakeReq();
		const res = fakeRes();
		const next = vi.fn();
		await mw(req, res, next);
		expect(next).not.toHaveBeenCalled();
		expect(req.tokenBinding).toBeUndefined();
		expect(res.status).toHaveBeenCalledWith(400);
		expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "invalid_mtls_cert" }));
	});

	it("hard-fails (no downgrade) when an earlier ambient mechanism throws before a later explicit could succeed", async () => {
		// Pins the no-downgrade rule from the opposite direction: an earlier failure
		// short-circuits — the middleware never reaches the later (would-
		// succeed) mechanism. The downstream observable is identical to
		// the "later throws" case but the implementation invariant is the
		// for-loop's early return.
		const err = Object.assign(new Error("bad cert"), { code: "invalid_mtls_cert" });
		const mw = tokenBindingMw({
			mechanisms: [mtlsMechanism(err), dpopMechanism(fakeDPoP)],
			dispatchPolicy: "intent-explicit",
		});
		const req = fakeReq();
		const res = fakeRes();
		const next = vi.fn();
		await mw(req, res, next);
		expect(next).not.toHaveBeenCalled();
		expect(req.tokenBinding).toBeUndefined();
		expect(res.status).toHaveBeenCalledWith(400);
		expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "invalid_mtls_cert" }));
	});

	it("falls back to invalid_<kind>_proof when the thrown error code is not snake_case OAuth-shaped", async () => {
		// Pins the safety guard against forwarding non-OAuth error codes
		// (e.g. Node system errors like ECONNREFUSED) into the public
		// `error` field. Without this guard, a transport-layer failure
		// inside `extract` would leak the system code to the client.
		const err = Object.assign(new Error("network down"), { code: "ECONNREFUSED" });
		const mw = tokenBindingMw({
			mechanisms: [dpopMechanism(err)],
			dispatchPolicy: "intent-explicit",
		});
		const req = fakeReq();
		const res = fakeRes();
		const next = vi.fn();
		await mw(req, res, next);
		expect(res.status).toHaveBeenCalledWith(400);
		expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "invalid_dpop_proof" }));
	});

	it("intent-explicit: DPoP wins over ambient mTLS when both succeed", async () => {
		const mw = tokenBindingMw({
			mechanisms: [dpopMechanism(fakeDPoP), mtlsMechanism(fakeMtls)],
			dispatchPolicy: "intent-explicit",
		});
		const req = fakeReq();
		const res = fakeRes();
		const next = vi.fn();
		await mw(req, res, next);
		expect(req.tokenBinding).toEqual(fakeDPoP);
	});

	it("intent-explicit: two explicit successes → 400 invalid_request naming both kinds", async () => {
		const mw = tokenBindingMw({
			mechanisms: [dpopMechanism(fakeDPoP), secondExplicit],
			dispatchPolicy: "intent-explicit",
		});
		const req = fakeReq();
		const res = fakeRes();
		const next = vi.fn();
		await mw(req, res, next);
		expect(next).not.toHaveBeenCalled();
		expect(res.status).toHaveBeenCalledWith(400);
		expect(res.json).toHaveBeenCalledWith({
			error: "invalid_request",
			error_description:
				"multiple explicit-intent token-binding mechanisms succeeded (dpop, http-sig)",
		});
	});

	it("intent-explicit: two explicit successes beside an ambient one → 400 naming the explicit kinds alone", async () => {
		const mw = tokenBindingMw({
			mechanisms: [dpopMechanism(fakeDPoP), mtlsMechanism(fakeMtls), secondExplicit],
			dispatchPolicy: "intent-explicit",
		});
		const req = fakeReq();
		const res = fakeRes();
		const next = vi.fn();
		await mw(req, res, next);
		expect(next).not.toHaveBeenCalled();
		expect(req.tokenBinding).toBeUndefined();
		expect(res.status).toHaveBeenCalledWith(400);
		expect(res.json).toHaveBeenCalledWith({
			error: "invalid_request",
			error_description:
				"multiple explicit-intent token-binding mechanisms succeeded (dpop, http-sig)",
		});
	});

	it("intent-explicit: ambient-only succeeds with ambient binding", async () => {
		const mw = tokenBindingMw({
			mechanisms: [dpopMechanism(null), mtlsMechanism(fakeMtls)],
			dispatchPolicy: "intent-explicit",
		});
		const req = fakeReq();
		const res = fakeRes();
		const next = vi.fn();
		await mw(req, res, next);
		expect(req.tokenBinding).toEqual(fakeMtls);
	});

	it("intent-explicit: two ambient successes and no explicit one → 400 invalid_request naming both kinds", async () => {
		const mw = tokenBindingMw({
			mechanisms: [mtlsMechanism(fakeMtls), secondAmbient],
			dispatchPolicy: "intent-explicit",
		});
		const req = fakeReq();
		const res = fakeRes();
		const next = vi.fn();
		await mw(req, res, next);

		expect(next).not.toHaveBeenCalled();
		expect(req.tokenBinding).toBeUndefined();
		expect(res.status).toHaveBeenCalledWith(400);
		expect(res.json).toHaveBeenCalledWith({
			error: "invalid_request",
			error_description:
				"multiple ambient token-binding mechanisms succeeded (mtls, mtls-secondary)",
		});
	});

	it.each([
		{
			tier: "explicit-intent",
			mechanisms: [dpopMechanism(fakeDPoP), mtlsMechanism(fakeMtls), secondExplicit],
			kinds: ["dpop", "http-sig"],
		},
		{
			tier: "ambient",
			mechanisms: [mtlsMechanism(fakeMtls), secondAmbient],
			kinds: ["mtls", "mtls-secondary"],
		},
	])(
		"intent-explicit: a refusal at the $tier tier is one warn line, token_binding_ambiguous, with the tier and the kinds",
		async ({ tier, mechanisms, kinds }) => {
			const logger = spyLogger();
			const mw = tokenBindingMw({
				mechanisms,
				dispatchPolicy: "intent-explicit",
				logger: logger as never,
			});
			await mw(fakeReq(), fakeRes(), vi.fn());
			expect(logger.warn).toHaveBeenCalledTimes(1);
			expect(logger.warn).toHaveBeenCalledWith(
				{ tier, mechanisms: kinds },
				"token_binding_ambiguous",
			);
			expect(logger.error).not.toHaveBeenCalled();
			expect(logger.info).not.toHaveBeenCalled();
		},
	);

	it("intent-explicit: one explicit success wins over two ambient successes", async () => {
		const mw = tokenBindingMw({
			mechanisms: [mtlsMechanism(fakeMtls), secondAmbient, dpopMechanism(fakeDPoP)],
			dispatchPolicy: "intent-explicit",
		});
		const req = fakeReq();
		const res = fakeRes();
		const next = vi.fn();
		await mw(req, res, next);

		expect(next).toHaveBeenCalledOnce();
		expect(req.tokenBinding).toEqual(fakeDPoP);
		expect(res.status).not.toHaveBeenCalled();
	});

	it("strict-mutual-exclusion: two ambient mechanisms succeeding → rejected", async () => {
		const mw = tokenBindingMw({
			mechanisms: [mtlsMechanism(fakeMtls), secondAmbient],
			dispatchPolicy: "strict-mutual-exclusion",
		});
		const req = fakeReq();
		const res = fakeRes();
		const next = vi.fn();
		await mw(req, res, next);

		expect(next).not.toHaveBeenCalled();
		expect(res.status).toHaveBeenCalledWith(400);
		expect(req.tokenBinding).toBeUndefined();
	});

	it("strict-mutual-exclusion: single succeeding mechanism assigns binding and calls next()", async () => {
		// Happy-path coverage for the strict-mutex branch — guards against
		// a regression that turns the policy into a hard-reject for ALL
		// requests instead of just multi-success requests.
		const mw = tokenBindingMw({
			mechanisms: [dpopMechanism(fakeDPoP)],
			dispatchPolicy: "strict-mutual-exclusion",
		});
		const req = fakeReq();
		const res = fakeRes();
		const next = vi.fn();
		await mw(req, res, next);
		expect(next).toHaveBeenCalledOnce();
		expect(req.tokenBinding).toEqual(fakeDPoP);
	});

	it("strict-mutual-exclusion: rejects when any 2+ mechanisms succeed", async () => {
		const mw = tokenBindingMw({
			mechanisms: [dpopMechanism(fakeDPoP), mtlsMechanism(fakeMtls)],
			dispatchPolicy: "strict-mutual-exclusion",
		});
		const req = fakeReq();
		const res = fakeRes();
		const next = vi.fn();
		await mw(req, res, next);
		expect(next).not.toHaveBeenCalled();
		expect(res.status).toHaveBeenCalledWith(400);
		expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "invalid_request" }));
	});
});

describe("a retry instruction is the mechanism's to state, not core's to know", () => {
	// The dispatcher is deliberately vendor-neutral: string-matching DPoP's
	// `use_dpop_nonce` to decide the description (here) and the challenge (at
	// a protected resource) would leave a second mechanism with a retry of its
	// own unable to get either without editing core.
	it("answers with the instruction a refusal carries, whatever its code", async () => {
		const err = Object.assign(new Error("nonce"), {
			code: "use_fresh_nonce",
			retryInstruction: "retry with the value of the Fresh-Nonce header",
			responseHeaders: { "Fresh-Nonce": "f1" },
		});
		const mw = tokenBindingMw({
			mechanisms: [dpopMechanism(err)],
			dispatchPolicy: "intent-explicit",
		});
		const res = fakeRes();
		await mw(fakeReq(), res, vi.fn());
		expect(res.status).toHaveBeenCalledWith(400);
		expect(res.setHeader).toHaveBeenCalledWith("Fresh-Nonce", "f1");
		expect(res.json).toHaveBeenCalledWith({
			error: "use_fresh_nonce",
			error_description: "retry with the value of the Fresh-Nonce header",
		});
	});

	it("names no mechanism's error code in the dispatchers", () => {
		for (const file of ["../tokenBinding.mts", "../protectedResourceBinding.mts"]) {
			const source = readFileSync(new URL(file, import.meta.url), "utf8")
				.replace(/\/\*[\s\S]*?\*\//g, "")
				.replace(/(^|[^:])\/\/.*$/gm, "$1");
			expect(source, file).not.toMatch(/["'`]use_dpop_nonce["'`]/);
			expect(source, file).not.toMatch(/["'`]temporarily_unavailable["'`]/);
		}
	});
});

describe("a server-side outage is the mechanism's to state, and answers 503", () => {
	// A mechanism that cannot reach a verdict (a replay store it cannot read)
	// has not found the material invalid. A 400 with its proof error would tell
	// the client its proof was bad, and a client that treats a 400 from the
	// token endpoint as final would give up on a request that would succeed a
	// moment later. So: 503, with the code and description the mechanism states.
	const outage = () =>
		Object.assign(new Error("ECONNREFUSED"), {
			code: "temporarily_unavailable",
			unavailable: "the replay store cannot be read; retry later",
		});
	it("answers 503 with the code and description the refusal carries", async () => {
		const logger = spyLogger();
		const mw = tokenBindingMw({
			mechanisms: [dpopMechanism(outage())],
			dispatchPolicy: "intent-explicit",
			logger: logger as never,
		});
		const res = fakeRes();
		const next = vi.fn();
		await mw(fakeReq(), res, next);
		expect(next).not.toHaveBeenCalled();
		expect(res.status).toHaveBeenCalledWith(503);
		expect(res.json).toHaveBeenCalledWith({
			error: "temporarily_unavailable",
			error_description: "the replay store cannot be read; retry later",
		});
		// Logged apart from proof failures: a dashboard counting bad proofs must
		// not count an outage, and the reverse. The layer that answers the 503
		// owns its one error-level line, so a mechanism that logs nothing of
		// its own is still covered.
		expect(logger.warn).not.toHaveBeenCalled();
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{ mechanism: "dpop", code: "temporarily_unavailable" },
			"token_binding_unavailable",
		);
	});

	it("logs the refusal's cause and reason, projected, when the mechanism gives them", async () => {
		const logger = spyLogger();
		const storeError = Object.assign(
			new Error("READONLY You can't write against a read only replica."),
			{
				name: "ReplyError",
				command: { name: "set", args: ["dpop-proof:jkt", "refused-command-marker"] },
			},
		);
		const refusal = Object.assign(new Error("replay store down", { cause: storeError }), {
			code: "temporarily_unavailable",
			unavailable: "the replay store cannot be read; retry later",
			reason: "replay_store_unavailable",
		});
		const mw = tokenBindingMw({
			mechanisms: [dpopMechanism(refusal)],
			dispatchPolicy: "intent-explicit",
			logger: logger as never,
		});
		const res = fakeRes();
		await mw(fakeReq(), res, vi.fn());
		expect(res.status).toHaveBeenCalledWith(503);
		expect(logger.warn).not.toHaveBeenCalled();
		expect(logger.error).toHaveBeenCalledTimes(1);
		const [line, event] = logger.error.mock.calls[0] as [Record<string, unknown>, string];
		expect(event).toBe("token_binding_unavailable");
		expect(line).toMatchObject({
			mechanism: "dpop",
			code: "temporarily_unavailable",
			reason: "replay_store_unavailable",
			err: { name: "ReplyError", command: { name: "set" } },
		});
		expect(line.err).not.toBeInstanceOf(Error);
		expect(JSON.stringify(logger.error.mock.calls)).not.toContain("refused-command-marker");
	});

	it("leaves out an outage's reason that is not a code, as the verdict line does", async () => {
		// `reason` is the mechanism's name for the refusal: a code. Free text a
		// mechanism wrote there (the store's reply, a key it read) must not reach
		// the outage line, just as the verdict line keeps only a code.
		const logger = spyLogger();
		for (const reason of [
			"replay store at 10.0.0.7 refused SET dpop-proof:free-text-marker",
			"Replay_Store_Unavailable",
			"replay_store_unavailable\nforged-line-marker",
			`${"a".repeat(65)}`,
		]) {
			const refusal = Object.assign(new Error("replay store down"), {
				code: "temporarily_unavailable",
				unavailable: "the replay store cannot be read; retry later",
				reason,
			});
			const mw = tokenBindingMw({
				mechanisms: [dpopMechanism(refusal)],
				dispatchPolicy: "intent-explicit",
				logger: logger as never,
			});
			const res = fakeRes();
			await mw(fakeReq(), res, vi.fn());
			expect(res.status).toHaveBeenCalledWith(503);
		}
		expect(logger.warn).not.toHaveBeenCalled();
		expect(logger.error).toHaveBeenCalledTimes(4);
		for (const [line, event] of logger.error.mock.calls as [Record<string, unknown>, string][]) {
			expect(event).toBe("token_binding_unavailable");
			expect(line).toEqual({ mechanism: "dpop", code: "temporarily_unavailable" });
		}
	});

	it("logs a verdict once at warn: the refusal's reason, and its projection with the cause inside", async () => {
		// A mechanism states why it refused (`reason`) and, when a parser
		// refused the material, that parser's error (`cause`). The verdict line
		// carries both, not only the mechanism and the code.
		const logger = spyLogger();
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
		const mw = tokenBindingMw({
			mechanisms: [mtlsMechanism(refusal)],
			dispatchPolicy: "intent-explicit",
			logger: logger as never,
		});
		const res = fakeRes();
		await mw(fakeReq(), res, vi.fn());
		expect(res.status).toHaveBeenCalledWith(400);
		expect(logger.error).not.toHaveBeenCalled();
		expect(logger.warn).toHaveBeenCalledTimes(1);
		expect(logger.warn).toHaveBeenCalledWith(
			{
				mechanism: "mtls",
				code: "invalid_certificate",
				reason: "malformed_header",
				err: {
					name: "Error",
					detail: "header parse failure",
					code: "invalid_certificate",
					reason: "malformed_header",
					stack: expect.stringMatching(/^ {4}at /),
					cause: { name: "SyntaxError", position: expect.any(Number), stack: expect.any(String) },
				},
			},
			"token_binding_proof_invalid",
		);
		expect(JSON.stringify(logger.warn.mock.calls)).not.toContain("refused-material-marker");
	});

	it("logs a refusal with no reason of its own — a mechanism's bug — by its projection alone", async () => {
		const logger = spyLogger();
		const mw = tokenBindingMw({
			mechanisms: [dpopMechanism(new TypeError("cannot read properties of undefined"))],
			dispatchPolicy: "intent-explicit",
			logger: logger as never,
		});
		await mw(fakeReq(), fakeRes(), vi.fn());
		expect(logger.warn).toHaveBeenCalledWith(
			{
				mechanism: "dpop",
				code: "invalid_dpop_proof",
				err: expect.objectContaining({ name: "TypeError" }),
			},
			"token_binding_proof_invalid",
		);
	});

	it("reads a bare code as a verdict: only the mechanism can say it was an outage", async () => {
		const bare = Object.assign(new Error("down"), { code: "temporarily_unavailable" });
		const mw = tokenBindingMw({
			mechanisms: [dpopMechanism(bare)],
			dispatchPolicy: "intent-explicit",
		});
		const res = fakeRes();
		await mw(fakeReq(), res, vi.fn());
		expect(res.status).toHaveBeenCalledWith(400);
	});
});

describe("tokenBindingMw — response headers a mechanism asks for", () => {
	it("sets the headers a refusal carries and answers use_dpop_nonce with its own description", async () => {
		const err = Object.assign(new Error("no nonce"), {
			code: "use_dpop_nonce",
			retryInstruction:
				"a server-provided nonce is required; retry with the value of the DPoP-Nonce header",
			responseHeaders: { "DPoP-Nonce": "n1" },
		});
		const mw = tokenBindingMw({
			mechanisms: [dpopMechanism(err)],
			dispatchPolicy: "intent-explicit",
		});
		const req = fakeReq();
		const res = fakeRes();
		const next = vi.fn();
		await mw(req, res, next);
		expect(next).not.toHaveBeenCalled();
		expect(res.setHeader).toHaveBeenCalledWith("DPoP-Nonce", "n1");
		expect(res.status).toHaveBeenCalledWith(400);
		expect(res.json).toHaveBeenCalledWith(
			expect.objectContaining({
				error: "use_dpop_nonce",
				error_description: expect.stringContaining("DPoP-Nonce"),
			}),
		);
	});

	it("sets the headers a succeeding binding carries, then continues", async () => {
		const binding: TokenBinding = {
			kind: "dpop",
			confirmation: { jkt: "AAA" },
			responseHeaders: { "DPoP-Nonce": "n2" },
		};
		for (const dispatchPolicy of ["intent-explicit", "strict-mutual-exclusion"] as const) {
			const mw = tokenBindingMw({ mechanisms: [dpopMechanism(binding)], dispatchPolicy });
			const req = fakeReq();
			const res = fakeRes();
			const next = vi.fn();
			await mw(req, res, next);
			expect(next).toHaveBeenCalledOnce();
			expect(req.tokenBinding).toBe(binding);
			expect(res.setHeader).toHaveBeenCalledWith("DPoP-Nonce", "n2");
		}
	});
});

describe("resolveTokenBindingSettings", () => {
	// The one reading of `core.tokenBinding`: the settings that apply across
	// every mechanism installed at core's token-binding extension point, and so
	// core's, as the point is. Boot reads the dispatch policy through this and
	// the grants the refresh-token rule; no slot carries either.
	const settingsOf = (tokenBinding: unknown) =>
		resolveTokenBindingSettings({ core: { tokenBinding } });

	it("reads strict-mutual-exclusion when the configuration says so", () => {
		expect(settingsOf({ dispatchPolicy: "strict-mutual-exclusion" }).dispatchPolicy).toBe(
			"strict-mutual-exclusion",
		);
	});

	it("reads intent-explicit otherwise: when it says so, says something else, or says nothing", () => {
		for (const config of [
			{ core: { tokenBinding: { dispatchPolicy: "intent-explicit" } } },
			{ core: { tokenBinding: { dispatchPolicy: "STRICT-MUTUAL-EXCLUSION" } } },
			{ core: { tokenBinding: {} } },
			{ core: {} },
			// The path the settings moved from, which boot refuses: never read.
			{ oauth: { tokenBinding: { "dispatch-policy": "strict-mutual-exclusion" } } },
			{},
			undefined,
			null,
		]) {
			expect(resolveTokenBindingSettings(config).dispatchPolicy, JSON.stringify(config)).toBe(
				"intent-explicit",
			);
		}
	});

	it("binds a confidential client's refresh tokens only when the configuration says true", () => {
		expect(
			settingsOf({ bindConfidentialClientRefreshTokens: true }).bindConfidentialClientRefreshTokens,
		).toBe(true);
		for (const tokenBinding of [
			{ bindConfidentialClientRefreshTokens: false },
			// What an environment variable carries, which the schema coerces and
			// a configuration built by hand does not.
			{ bindConfidentialClientRefreshTokens: "true" },
			{ bindConfidentialClientRefreshTokens: 1 },
			{},
			undefined,
		]) {
			expect(
				settingsOf(tokenBinding).bindConfidentialClientRefreshTokens,
				JSON.stringify(tokenBinding),
			).toBe(false);
		}
	});

	it("answers the two settings and nothing else, frozen", () => {
		const settings = settingsOf({
			dispatchPolicy: "strict-mutual-exclusion",
			bindConfidentialClientRefreshTokens: true,
			unknown: "ignored",
		});
		expect(settings).toStrictEqual({
			dispatchPolicy: "strict-mutual-exclusion",
			bindConfidentialClientRefreshTokens: true,
		});
		expect(Object.isFrozen(settings)).toBe(true);
	});
});
