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
import { describe, expect, it, vi } from "vitest";
import type { TokenBinding } from "#/grants/tokenBinding.mjs";
import { type TokenBindingMechanism, tokenBindingMw } from "#/middleware/tokenBinding.mjs";

const fakeReq = () => ({}) as Request;
const fakeRes = () => {
	const r: Partial<Response> = {};
	r.status = vi.fn(() => r as Response);
	r.json = vi.fn(() => r as Response);
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

	it("intent-explicit: rejects when ≥2 explicit mechanisms succeed", async () => {
		const otherExplicit: TokenBindingMechanism = {
			kind: "http-sig",
			intentExplicit: true,
			extract: async () => ({
				kind: "http-sig",
				confirmation: { jkt: "OTHER" },
			}),
		};
		const mw = tokenBindingMw({
			mechanisms: [dpopMechanism(fakeDPoP), otherExplicit],
			dispatchPolicy: "intent-explicit",
		});
		const req = fakeReq();
		const res = fakeRes();
		const next = vi.fn();
		await mw(req, res, next);
		expect(next).not.toHaveBeenCalled();
		expect(res.status).toHaveBeenCalledWith(400);
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
