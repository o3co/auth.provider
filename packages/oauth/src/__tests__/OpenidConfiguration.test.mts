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

import { describe, expect, it } from "vitest";
import { createRouter } from "#/routes/OpenidConfiguration.mjs";

function createMockExpress() {
	const routes: Record<string, Function> = {};
	const router = {
		get(path: string, handler: Function) {
			routes[path] = handler;
			return router;
		},
	};
	return { Router: () => router, routes };
}

function createMockRes() {
	let statusCode = 200;
	let body: unknown;
	return {
		status(code: number) {
			statusCode = code;
			return this;
		},
		json(data: unknown) {
			body = data;
			return this;
		},
		sendStatus(code: number) {
			statusCode = code;
			return this;
		},
		getStatusCode: () => statusCode,
		getBody: () => body,
	};
}

async function callRoute(opts: {
	issuer: string;
	signingAlgs: string[];
}): Promise<Record<string, unknown>> {
	const express = createMockExpress();
	createRouter(express as any, opts);
	const handler = express.routes["/.well-known/openid-configuration"];
	const res = createMockRes();
	await handler({}, res);
	return res.getBody() as Record<string, unknown>;
}

describe("GET /.well-known/openid-configuration", () => {
	it("returns discovery metadata with F-4 scoped endpoints + signing algs", async () => {
		const body = await callRoute({
			issuer: "https://auth.example.com",
			signingAlgs: ["RS256", "ES256", "EdDSA", "HS256"],
		});
		expect(body.issuer).toBe("https://auth.example.com");
		expect(body.authorization_endpoint).toBe("https://auth.example.com/oauth/authorize");
		expect(body.token_endpoint).toBe("https://auth.example.com/oauth/token");
		expect(body.userinfo_endpoint).toBe("https://auth.example.com/oauth/userinfo");
		expect(body.jwks_uri).toBe("https://auth.example.com/.well-known/jwks.json");
		expect(body.introspection_endpoint).toBe("https://auth.example.com/oauth/introspect");
		expect(body.response_types_supported).toEqual(["code"]);
		expect(body.subject_types_supported).toEqual(["public"]);
		expect(body.id_token_signing_alg_values_supported).toEqual([
			"RS256",
			"ES256",
			"EdDSA",
			"HS256",
		]);
		expect(body.scopes_supported).toEqual(["openid", "profile", "email", "groups"]);
		expect(body.code_challenge_methods_supported).toEqual(["S256"]);
		expect(body.token_endpoint_auth_methods_supported).toEqual(
			expect.arrayContaining(["client_secret_basic", "client_secret_post", "none"]),
		);
	});

	it("does NOT advertise revocation_endpoint / end_session_endpoint / backchannel_logout_supported (out of F-4 scope)", async () => {
		const body = await callRoute({ issuer: "https://auth.example.com", signingAlgs: [] });
		expect(body.revocation_endpoint).toBeUndefined();
		expect(body.end_session_endpoint).toBeUndefined();
		expect(body.backchannel_logout_supported).toBeUndefined();
	});

	it("strips trailing slashes from issuer when building endpoint URLs", async () => {
		const body = await callRoute({
			issuer: "https://auth.example.com///",
			signingAlgs: ["RS256"],
		});
		expect(body.authorization_endpoint).toBe("https://auth.example.com/oauth/authorize");
		expect(body.token_endpoint).toBe("https://auth.example.com/oauth/token");
	});

	it("omits jwks_uri for HS256-only deployments (JWKS route returns 404 for symmetric keys)", async () => {
		const body = await callRoute({ issuer: "https://auth.example.com", signingAlgs: ["HS256"] });
		expect(body.jwks_uri).toBeUndefined();
	});

	it("advertises jwks_uri when any asymmetric alg is configured (RS256 alongside HS256)", async () => {
		const body = await callRoute({
			issuer: "https://auth.example.com",
			signingAlgs: ["RS256", "HS256"],
		});
		expect(body.jwks_uri).toBe("https://auth.example.com/.well-known/jwks.json");
	});
});
