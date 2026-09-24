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
 * What core mounts for the token endpoint applies to `/oauth/token` exactly —
 * in every spelling the token route itself answers (a trailing slash, any
 * letter case) — and to no longer path beneath it.
 *
 * Core mounted the composed `tokenBindingMw` and the `grantMiddleware`
 * contributions with `router.use("/oauth/token", ...)`, which matches every
 * path beneath `/oauth/token` as well: a later module's
 * `POST /oauth/token/custom` got the token endpoint's binding verdict — a
 * DPoP refusal that is none of its business — and ran its grant middleware.
 * The protected-resource sender-constraint check exempted the same sub-tree,
 * so a DPoP-bound access token replayed there as a plain Bearer was admitted.
 */

import express, { type RequestHandler, Router } from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../../index.mjs";
import type { TokenBindingMechanism } from "../../middleware/tokenBinding.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import type { BootstrapMap } from "../types.mjs";

const BOOT: BootstrapMap = {
	config: makeValidCoreConfig() as never,
	pathResolver: (s: string) => s,
} satisfies Record<string, unknown> as BootstrapMap;

const JKT = "L0AXB6c64d2QW3rhCLLADhOMLf_7u2eTGH-q9ZGja24";

/** An access token bound to a DPoP key (`cnf.jkt`). */
const boundToken = async (): Promise<string> =>
	new SignJWT({ sub: "u1", cnf: { jkt: JKT } })
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.sign(new Uint8Array(32));

const reached: RequestHandler = (_req, res) => {
	res.status(200).json({ reached: true });
};

/**
 * A booted app whose DPoP mechanism refuses every proof it is shown, with a
 * grant middleware beside it; both record the requests they saw. The token
 * route stands in for `oauthModule`'s, and a later module serves
 * `POST /oauth/token/custom`.
 */
const bootApp = async () => {
	const proofsJudged: string[] = [];
	const grantMiddlewareSaw: string[] = [];
	const mechanism: TokenBindingMechanism = {
		kind: "dpop",
		intentExplicit: true,
		extract: async (req) => {
			if (req.headers.dpop === undefined) return null;
			proofsJudged.push(req.originalUrl);
			throw Object.assign(new Error("proof refused"), { code: "invalid_dpop_proof" });
		},
	};
	const handle = await createApp({
		modules: [
			defineModule({
				name: "mechanism",
				requires: [],
				optional: [],
				contributes: { tokenBindingMechanisms: [() => mechanism] },
			}),
			defineModule({
				name: "grant-middleware",
				requires: [],
				optional: [],
				contributes: {
					grantMiddleware: [
						() => (req, _res, next) => {
							grantMiddlewareSaw.push(req.originalUrl);
							next();
						},
					],
				},
			}),
			defineModule({
				name: "token-endpoint",
				requires: [],
				optional: [],
				contributes: {
					routes: [
						() => {
							const router = Router();
							router.post("/token", reached);
							return { id: "token-endpoint", mountPath: "/oauth", handler: router };
						},
					],
				},
			}),
			defineModule({
				name: "later",
				requires: [],
				optional: [],
				contributes: {
					routes: [
						() => {
							const router = Router();
							router.post("/token/custom", reached);
							return { id: "later", mountPath: "/oauth", handler: router };
						},
					],
				},
			}),
		],
		bootstrapComponents: BOOT,
	});
	const app = express();
	app.use(handle.router);
	return { app, proofsJudged, grantMiddlewareSaw };
};

describe("the token endpoint's middleware matches /oauth/token exactly", () => {
	it("leaves a later module's POST /oauth/token/custom alone: no binding verdict, no grant middleware", async () => {
		const { app, proofsJudged, grantMiddlewareSaw } = await bootApp();

		const res = await request(app).post("/oauth/token/custom").set("DPoP", "a.proof.jwt");

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ reached: true });
		expect(proofsJudged).toEqual([]);
		expect(grantMiddlewareSaw).toEqual([]);
	});

	it.each(["/oauth/token", "/oauth/token/", "/OAuth/Token"])(
		"still judges the proof at %s, which the token route answers",
		async (path) => {
			const { app, proofsJudged } = await bootApp();

			const res = await request(app).post(path).set("DPoP", "a.proof.jwt");

			expect(res.status).toBe(400);
			expect(res.body.error).toBe("invalid_dpop_proof");
			expect(proofsJudged).toEqual([path]);
		},
	);

	it.each(["/oauth/token", "/oauth/token/", "/OAuth/Token"])(
		"still runs the grant middleware at %s",
		async (path) => {
			const { app, grantMiddlewareSaw } = await bootApp();

			const res = await request(app).post(path);

			expect(res.status).toBe(200);
			expect(grantMiddlewareSaw).toEqual([path]);
		},
	);
});

describe("the sender-constraint exemption covers /oauth/token exactly", () => {
	it("refuses a bound token replayed as a plain Bearer at a later module's POST /oauth/token/custom", async () => {
		// Exempting the token endpoint's sub-tree left a route there guarded
		// by neither profile: not the token endpoint's, which no longer runs
		// beneath it, and not the protected resource's.
		const { app } = await bootApp();

		const res = await request(app)
			.post("/oauth/token/custom")
			.set("Authorization", `Bearer ${await boundToken()}`);

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_token");
	});

	it.each(["/oauth/token", "/oauth/token/", "/OAuth/Token"])(
		"still exempts %s, which the token route answers",
		async (path) => {
			const { app } = await bootApp();

			const res = await request(app)
				.post(path)
				.set("Authorization", `Bearer ${await boundToken()}`);

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ reached: true });
		},
	);
});
