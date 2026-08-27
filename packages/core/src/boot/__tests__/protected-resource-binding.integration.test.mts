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
 * Boot-level coverage for issue #264: the protected-resource sender-constraint
 * middleware must be mounted on every OAuth surface that accepts an access
 * token as a credential, and must be mounted even when the deployment
 * contributes no mechanisms at all.
 */

import express, { type Request, type RequestHandler, Router } from "express";
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

const boundToken = async (): Promise<string> =>
	new SignJWT({ sub: "u1", cnf: { jkt: JKT } })
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.sign(new Uint8Array(32));

const unboundToken = async (): Promise<string> =>
	new SignJWT({ sub: "u1" })
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.sign(new Uint8Array(32));

const dpopMech: TokenBindingMechanism = {
	kind: "dpop",
	intentExplicit: true,
	extract: async (_req: Request) => ({ kind: "dpop", confirmation: { jkt: JKT } }),
};

/**
 * Stands in for the oauth module's protected resources. Each route reports
 * whether the request reached it, which is what "the binding was enforced"
 * has to be measured against.
 */
const protectedRoutesModule = () =>
	defineModule({
		name: "protected-resources",
		requires: [],
		optional: [],
		contributes: {
			routes: [
				() => {
					const router = Router();
					router.use(express.json());
					const handler: RequestHandler = (_req, res) => {
						res.status(200).json({ reached: true });
					};
					router.get("/userinfo", handler);
					router.post("/federation/google/token", handler);
					router.post("/introspect", handler);
					router.post("/logout", handler);
					router.post("/token", handler);
					return { id: "protected", mountPath: "/oauth", handler: router };
				},
			],
		},
	});

const mechanismModule = (mechanism: TokenBindingMechanism | null) =>
	defineModule({
		name: "mechanism",
		requires: [],
		optional: [],
		contributes: { tokenBindingMechanisms: [() => mechanism] },
	});

const bootApp = async (mechanism: TokenBindingMechanism | null) => {
	const handle = await createApp({
		modules: [...(mechanism === null ? [] : [mechanismModule(mechanism)]), protectedRoutesModule()],
		bootstrapComponents: BOOT,
	});
	const app = express();
	app.use(handle.router);
	return app;
};

describe("protected-resource sender-constraint mount (#264)", () => {
	const surfaces = [
		{ name: "userinfo", method: "get" as const, path: "/oauth/userinfo" },
		{
			name: "federation token",
			method: "post" as const,
			path: "/oauth/federation/google/token",
		},
		{ name: "introspection", method: "post" as const, path: "/oauth/introspect" },
		{ name: "logout", method: "post" as const, path: "/oauth/logout" },
	];

	for (const surface of surfaces) {
		it(`refuses a DPoP-bound token replayed as a plain Bearer at ${surface.name}`, async () => {
			const app = await bootApp(dpopMech);
			const res = await request(app)
				[surface.method](surface.path)
				.set("Authorization", `Bearer ${await boundToken()}`);
			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
		});

		it(`admits the same token under the DPoP scheme at ${surface.name}`, async () => {
			const app = await bootApp(dpopMech);
			const res = await request(app)
				[surface.method](surface.path)
				.set("Authorization", `DPoP ${await boundToken()}`);
			expect(res.status).toBe(200);
			expect(res.body).toEqual({ reached: true });
		});

		it(`leaves an unbound Bearer token alone at ${surface.name}`, async () => {
			const app = await bootApp(dpopMech);
			const res = await request(app)
				[surface.method](surface.path)
				.set("Authorization", `Bearer ${await unboundToken()}`);
			expect(res.status).toBe(200);
		});
	}

	it("refuses a bound token when the deployment contributes no mechanisms at all", async () => {
		// The fail-open trap: mounting only when mechanisms exist would let a
		// deployment that removed the DPoP module keep honouring the bound
		// tokens it minted before.
		const app = await bootApp(null);
		const res = await request(app)
			.get("/oauth/userinfo")
			.set("Authorization", `Bearer ${await boundToken()}`);
		expect(res.status).toBe(401);
	});

	it("does not enforce the protected-resource profile at /oauth/token", async () => {
		// The token endpoint has its own middleware and a different profile —
		// there is no access token in play, so no cnf to match.
		const app = await bootApp(dpopMech);
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", "Basic Y2xpZW50OnNlY3JldA==");
		expect(res.status).toBe(200);
	});
});
