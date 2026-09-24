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
 * RFC 6749 Appendix A.7 / A.8 through a booted composition: the error text
 * core's own middleware writes — the token-binding middleware, the
 * protected-resource binding and the rate limiter — stays inside `1*NQSCHAR`
 * (printable ASCII without `"` and `\`) whatever a contributed mechanism or a
 * limiter adapter hands it. Each writer goes through `errorEnvelope`, so this
 * pins the envelope as the one place the rule is applied, on the real path:
 * `createApp` with contributed modules, not the middleware called by hand.
 */

import express, { type RequestHandler, Router } from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { BootstrapMap } from "#/boot/types.mjs";
import type { TokenBinding } from "#/grants/tokenBinding.mjs";
import { createApp, createRateLimitGuard } from "#/index.mjs";
import type { TokenBindingMechanism } from "#/middleware/tokenBinding.mjs";
import { defineModule } from "#/modules/manifest/index.mjs";
import type { RateLimitDecision, RateLimiter } from "#/ratelimit/types.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

/** Every character a contributed text might carry that RFC 6749 does not allow. */
const HOSTILE = 'say "hi" \\ see §3 — café\r\nX-Injected: 1 \u{1F600}';
/** What the wire carries instead: each code point outside the set is one `?`. */
const HOSTILE_ON_THE_WIRE = "say ?hi? ? see ?3 ? caf???X-Injected: 1 ?";

const NQSCHAR_TEXT = /^[\x20-\x21\x23-\x5B\x5D-\x7E]+$/;

/** The body's error text, each field inside RFC 6749's set. */
const expectConformingBody = (body: Record<string, unknown>): void => {
	expect(body.error).toMatch(NQSCHAR_TEXT);
	if (body.error_description !== undefined) expect(body.error_description).toMatch(NQSCHAR_TEXT);
};

const BOOT: BootstrapMap = {
	config: makeValidCoreConfig() as never,
	pathResolver: (s: string) => s,
} satisfies Record<string, unknown> as BootstrapMap;

const JKT = "L0AXB6c64d2QW3rhCLLADhOMLf_7u2eTGH-q9ZGja24";

const boundToken = async (): Promise<string> =>
	new SignJWT({ sub: "u1", cnf: { jkt: JKT } })
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.sign(new Uint8Array(32));

/** A refusal a mechanism throws, in `TokenBindingRefusal`'s shape. */
const refusal = (fields: Record<string, unknown>): Error =>
	Object.assign(new Error("refused"), fields);

const throwingMechanism = (kind: string, thrown: Error): TokenBindingMechanism => ({
	kind,
	intentExplicit: true,
	extract: async () => {
		throw thrown;
	},
});

const acceptingMechanism = (
	kind: string,
	confirmation: TokenBinding["confirmation"],
): TokenBindingMechanism => ({
	kind,
	intentExplicit: true,
	extract: async () => ({ kind, confirmation }),
});

const mechanismModule = (name: string, mechanism: TokenBindingMechanism) =>
	defineModule({
		name,
		requires: [],
		optional: [],
		contributes: { tokenBindingMechanisms: [() => mechanism] },
	});

/** Stands in for the oauth module: a token endpoint and a protected resource. */
const endpointsModule = () =>
	defineModule({
		name: "endpoints",
		requires: [],
		optional: [],
		contributes: {
			routes: [
				() => {
					const router = Router();
					const reached: RequestHandler = (_req, res) => {
						res.status(200).json({ reached: true });
					};
					router.post("/token", reached);
					router.get("/userinfo", reached);
					return { id: "endpoints", mountPath: "/oauth", handler: router };
				},
			],
		},
	});

const boot = async (...mechanisms: readonly TokenBindingMechanism[]) => {
	const handle = await createApp({
		modules: [
			...mechanisms.map((mechanism, i) => mechanismModule(`mechanism-${i}`, mechanism)),
			endpointsModule(),
		],
		bootstrapComponents: BOOT,
	});
	const app = express();
	app.use(handle.router);
	return { app, handle };
};

afterEach(() => {
	vi.restoreAllMocks();
});

describe("the token-binding middleware at /oauth/token", () => {
	it("sends a mechanism's retry instruction inside RFC 6749's set", async () => {
		const { app, handle } = await boot(
			throwingMechanism(
				"dpop",
				refusal({ code: "use_dpop_nonce", retryInstruction: `retry: ${HOSTILE}` }),
			),
		);
		const res = await request(app).post("/oauth/token");
		expect(res.status).toBe(400);
		expect(res.body).toEqual({
			error: "use_dpop_nonce",
			error_description: `retry: ${HOSTILE_ON_THE_WIRE}`,
		});
		expectConformingBody(res.body);
		await handle.dispose();
	});

	it("sends a mechanism's outage description inside RFC 6749's set", async () => {
		const { app, handle } = await boot(
			throwingMechanism("dpop", refusal({ code: "temporarily_unavailable", unavailable: HOSTILE })),
		);
		const res = await request(app).post("/oauth/token");
		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: HOSTILE_ON_THE_WIRE,
		});
		await handle.dispose();
	});

	it("answers a refusal from a mechanism whose kind is outside the set as invalid_request", async () => {
		// No code of its own, so the middleware names one from the kind:
		// `invalid_<kind>_proof`. A kind that makes that code malformed must not
		// reach the wire as the `error`, and the refusal is still the client's.
		const { app, handle } = await boot(throwingMechanism('béta"bind', new Error("proof rejected")));
		const res = await request(app).post("/oauth/token");
		expect(res.status).toBe(400);
		expect(res.body).toEqual({
			error: "invalid_request",
			error_description: "b?ta?bind mechanism rejected the presented material",
		});
		await handle.dispose();
	});

	it("names contributed kinds in a dispatch conflict inside RFC 6749's set", async () => {
		const { app, handle } = await boot(
			acceptingMechanism("dpop—a", { jkt: "a" }),
			acceptingMechanism('dpop"b', { jkt: "b" }),
		);
		const res = await request(app).post("/oauth/token");
		expect(res.status).toBe(400);
		expect(res.body).toEqual({
			error: "invalid_request",
			error_description:
				"multiple explicit-intent token-binding mechanisms succeeded (dpop?a, dpop?b)",
		});
		await handle.dispose();
	});
});

describe("the protected-resource binding", () => {
	it("sends a mechanism's retry instruction inside RFC 6749's set", async () => {
		const { app, handle } = await boot(
			throwingMechanism("dpop", refusal({ code: "use_dpop_nonce", retryInstruction: HOSTILE })),
		);
		const res = await request(app)
			.get("/oauth/userinfo")
			.set("Authorization", `DPoP ${await boundToken()}`);
		expect(res.status).toBe(401);
		expect(res.body).toEqual({ error: "use_dpop_nonce", error_description: HOSTILE_ON_THE_WIRE });
		await handle.dispose();
	});

	it("sends a mechanism's outage description inside RFC 6749's set", async () => {
		const { app, handle } = await boot(
			throwingMechanism("dpop", refusal({ code: "temporarily_unavailable", unavailable: HOSTILE })),
		);
		const res = await request(app)
			.get("/oauth/userinfo")
			.set("Authorization", `DPoP ${await boundToken()}`);
		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: HOSTILE_ON_THE_WIRE,
		});
		await handle.dispose();
	});
});

describe("the rate limiter", () => {
	/** A limiter adapter that refuses every request, giving `reason` as its cause. */
	const refusingLimiter = (reason: unknown): RateLimiter => ({
		kind: "custom",
		check: async () => ({ allowed: false, reason }) as unknown as RateLimitDecision,
	});

	/** The adapter as a module provides it, and a route guarded as oauth and session guard theirs. */
	const bootLimited = async (limiter: RateLimiter) => {
		const handle = await createApp({
			modules: [
				defineModule({
					name: "custom-limiter",
					provides: { rateLimiter: () => limiter },
				}),
				defineModule({
					name: "guarded",
					requires: ["rateLimiter"],
					optional: [],
					contributes: {
						routes: [
							(deps) => {
								const router = Router();
								router.post(
									"/login",
									createRateLimitGuard({
										limiter: deps.rateLimiter,
										tag: "login",
										failMode: "closed",
									}),
									(_req, res) => {
										res.status(200).json({ reached: true });
									},
								);
								return { id: "guarded", mountPath: "/session", handler: router };
							},
						],
					},
				}),
			],
			bootstrapComponents: BOOT,
		});
		const app = express();
		app.use(handle.router);
		return { app, handle };
	};

	it("sends an adapter's refusal reason inside RFC 6749's set", async () => {
		const { app, handle } = await bootLimited(refusingLimiter(HOSTILE));
		const res = await request(app).post("/session/login");
		expect(res.status).toBe(429);
		expect(res.body).toEqual({ error: "rate_limited", error_description: HOSTILE_ON_THE_WIRE });
		await handle.dispose();
	});

	it("answers the default description when an adapter's reason is not a string", async () => {
		// A JavaScript adapter can put anything there. It is not coerced (an
		// object's `toString` is not the adapter's cause), and the 429 still
		// says what happened.
		const { app, handle } = await bootLimited(refusingLimiter({ toString: () => "quota" }));
		const res = await request(app).post("/session/login");
		expect(res.status).toBe(429);
		expect(res.body).toEqual({ error: "rate_limited", error_description: "Rate limit exceeded" });
		await handle.dispose();
	});
});
