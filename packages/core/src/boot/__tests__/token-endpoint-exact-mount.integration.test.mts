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
 *
 * Exact without changing what a contribution sees: the middleware is still a
 * `use` mount, so `req.path`, `req.url` and `req.baseUrl` inside it are what
 * they were. And only for a POST — the token endpoint's one method — so a
 * later module's `GET /oauth/token` is neither judged as the token endpoint
 * nor exempt from the sender-constraint check.
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

/** What a contribution mounted on the token endpoint sees of the request's path. */
interface SeenShape {
	readonly path: string;
	readonly url: string;
	readonly baseUrl: string;
}

const shapeOf = (req: { path: string; url: string; baseUrl: string }): SeenShape => ({
	path: req.path,
	url: req.url,
	baseUrl: req.baseUrl,
});

/**
 * A booted app whose DPoP mechanism refuses every proof it is shown, with a
 * grant middleware beside it; both record the requests they saw, and the
 * shape of each. The token route stands in for `oauthModule`'s, and a later
 * module serves `POST /oauth/token/custom` and `GET /oauth/token`. The router
 * is mounted at `mountedAt`, as a host app may mount it; `config` is merged
 * over the valid core config.
 */
const bootApp = async (mountedAt = "/", config: Record<string, unknown> = {}) => {
	const proofsJudged: string[] = [];
	const grantMiddlewareSaw: string[] = [];
	const mechanismShapes: SeenShape[] = [];
	const grantMiddlewareShapes: SeenShape[] = [];
	const mechanism: TokenBindingMechanism = {
		kind: "dpop",
		intentExplicit: true,
		extract: async (req) => {
			mechanismShapes.push(shapeOf(req));
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
							grantMiddlewareShapes.push(shapeOf(req));
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
							router.get("/token", reached);
							return { id: "later", mountPath: "/oauth", handler: router };
						},
					],
				},
			}),
		],
		bootstrapComponents: { ...BOOT, config: { ...makeValidCoreConfig(), ...config } as never },
	});
	const app = express();
	app.use(mountedAt, handle.router);
	return { app, proofsJudged, grantMiddlewareSaw, mechanismShapes, grantMiddlewareShapes };
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

	it("shows a contribution the request as a `use` mount on /oauth/token shows it", async () => {
		// `tokenBindingMechanisms` and `grantMiddleware` are public contribution
		// kinds: what `req.path`, `req.url` and `req.baseUrl` hold inside them
		// is part of what they are given, whatever makes the mount exact.
		const { app, mechanismShapes, grantMiddlewareShapes } = await bootApp("/auth");

		const res = await request(app).post("/auth/oauth/token?a=1");

		expect(res.status).toBe(200);
		const expected = { path: "/", url: "/?a=1", baseUrl: "/auth/oauth/token" };
		expect(mechanismShapes).toEqual([expected]);
		expect(grantMiddlewareShapes).toEqual([expected]);
	});

	it("leaves a later module's GET /oauth/token alone: the token endpoint is POST only", async () => {
		const { app, proofsJudged, grantMiddlewareSaw, mechanismShapes } = await bootApp();

		const res = await request(app).get("/oauth/token").set("DPoP", "a.proof.jwt");

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ reached: true });
		expect(proofsJudged).toEqual([]);
		expect(mechanismShapes).toEqual([]);
		expect(grantMiddlewareSaw).toEqual([]);
	});

	it("answers a CORS preflight for /oauth/token before any of the token endpoint's middleware", async () => {
		// `corsMw` is mounted first; an OPTIONS is not the token endpoint's
		// POST either way.
		const { app, mechanismShapes, grantMiddlewareSaw } = await bootApp("/", {
			cors: { allowedOrigins: ["https://spa.example"] },
		});

		const res = await request(app)
			.options("/oauth/token")
			.set("Origin", "https://spa.example")
			.set("Access-Control-Request-Method", "POST");

		expect(res.status).toBe(204);
		expect(res.headers["access-control-allow-origin"]).toBe("https://spa.example");
		expect(mechanismShapes).toEqual([]);
		expect(grantMiddlewareSaw).toEqual([]);
	});

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

	it("refuses a bound token replayed as a plain Bearer at a later module's GET /oauth/token", async () => {
		// The exemption is the token endpoint's, and the token endpoint is a
		// POST: a GET on its path is any other route's, and guarded as one.
		const { app } = await bootApp();

		const res = await request(app)
			.get("/oauth/token")
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
