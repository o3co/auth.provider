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
 * A `grants` factory that answers `null` — the grant switched off by its
 * module's settings — registers nothing a reader sees: `grantHandlerResolver`
 * answers the grant type as it answers one no module contributes, so the
 * token endpoint's dispatch and discovery's `grant_types_supported`, which
 * both read it, leave the grant out. The grant type stays claimed: a second
 * contribution of it is a duplicate. It is no override target: an override
 * of it is refused as `override-target-missing`, so an override cannot switch
 * on a grant its owner switched off. An override may answer `null` itself,
 * which switches the grant it replaces off.
 */

import express, { Router } from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import type { GrantHandler } from "../../grants/types.mjs";
import { createSymmetricKeyStore } from "../../keys/KeyStore.mjs";
import { defineModule, type Module } from "../../modules/manifest/index.mjs";
import { createTestApp } from "../../testing/create-test-app.mjs";
import { makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";
import { BootError } from "../types.mjs";

const OFF = "urn:test:grant-off";
const ON = "urn:test:grant-on";
const NEVER = "urn:test:grant-never-contributed";

const fakeGrantHandler = (tag: string): GrantHandler => ({
	handle: async () => ({
		result: { status: 200, tokens: { access_token: tag } as never },
	}),
});

function withIssuer() {
	const config = makeValidAppConfig() as { oauth?: { jwt?: Record<string, unknown> } };
	return {
		...config,
		oauth: { ...config.oauth, jwt: { ...config.oauth?.jwt, issuer: "https://auth.example.com" } },
	} as unknown as ReturnType<typeof makeValidAppConfig>;
}

const boot = (modules: readonly Module[]) =>
	createTestApp({
		modules: [...modules],
		bootstrapComponents: { config: withIssuer(), pathResolver: (s: string) => s },
	});

/** What `createTestApp` refused with, or a failure when it booted. */
async function refusal(modules: readonly Module[]): Promise<BootError> {
	try {
		const handle = await boot(modules);
		await handle.dispose();
	} catch (err) {
		expect(err).toBeInstanceOf(BootError);
		return err as BootError;
	}
	return expect.fail("boot should have been refused");
}

const grantsOwner = defineModule({
	name: "test:grants-owner",
	contributes: {
		grants: {
			[OFF]: () => null,
			[ON]: () => fakeGrantHandler("on"),
		},
	},
});

/**
 * Reads the resolver as the bundled token endpoint and discovery contribution
 * do: `/oauth/token` dispatches through `get`, answering `unsupported_grant_type`
 * for a grant type it does not find, and `grant_types_supported` lists
 * `entries()`.
 */
const resolverReader = defineModule({
	name: "test:resolver-reader",
	requires: ["grantHandlerResolver", "keyStore"] as const,
	contributes: {
		routes: [
			(deps) => {
				const router = Router();
				router.post("/token", express.urlencoded({ extended: false }), async (req, res) => {
					const grantType = String(req.body.grant_type);
					const handler = deps.grantHandlerResolver.get(grantType);
					if (handler === undefined) {
						res.status(400).json({ error: "unsupported_grant_type" });
						return;
					}
					const outcome = await handler.handle({} as never);
					res.status(200).json(outcome.result);
				});
				return { id: "test:token", mountPath: "/oauth", handler: router };
			},
		],
		discoveryMetadata: [
			(deps) => ({
				providerRoot: true,
				endpoints: { token_endpoint: "/oauth/token", jwks_uri: "/.well-known/jwks.json" },
				metadata: {
					response_types_supported: [],
					subject_types_supported: ["public"],
					grant_types_supported: [...deps.grantHandlerResolver.entries()].map(
						([grantType]) => grantType,
					),
				},
			}),
		],
	},
});

const keyStoreModule = defineModule({
	name: "test:key-store",
	provides: { keyStore: () => createSymmetricKeyStore("test-secret-for-grants-switched-off!!") },
});

describe("grants — a factory that answers null registers nothing", () => {
	it("leaves the grant out of grantHandlerResolver, and registers its sibling", async () => {
		const handle = await boot([grantsOwner]);
		const resolver = handle.components.grantHandlerResolver;

		expect(resolver?.get(OFF)).toBeUndefined();
		expect([...(resolver?.entries() ?? [])].map(([grantType]) => grantType)).toEqual([ON]);
		expect(await resolver?.get(ON)?.handle({} as never)).toEqual({
			result: { status: 200, tokens: { access_token: "on" } },
		});
		expect([...handle.inspect.grants.keys()]).toEqual([ON]);

		await handle.dispose();
	});

	it("answers a token request for it as for a grant type no module contributes, and discovery does not list it", async () => {
		const handle = await boot([grantsOwner, resolverReader, keyStoreModule]);
		const app = express();
		app.use(handle.router);

		const off = await request(app).post("/oauth/token").type("form").send({ grant_type: OFF });
		const never = await request(app).post("/oauth/token").type("form").send({ grant_type: NEVER });
		expect(off.status).toBe(never.status);
		expect(off.body).toEqual(never.body);
		expect(off.body).toEqual({ error: "unsupported_grant_type" });

		const on = await request(app).post("/oauth/token").type("form").send({ grant_type: ON });
		expect(on.status).toBe(200);
		expect(on.body).toEqual({ status: 200, tokens: { access_token: "on" } });

		const discovery = await request(app).get("/.well-known/openid-configuration");
		expect(discovery.status).toBe(200);
		expect(discovery.body.grant_types_supported).toEqual([ON]);

		await handle.dispose();
	});

	it("keeps the grant type claimed: a second contribution of it is a duplicate, in either order", async () => {
		const second = defineModule({
			name: "test:grants-second",
			contributes: { grants: { [OFF]: () => fakeGrantHandler("second") } },
		});
		for (const modules of [
			[grantsOwner, second],
			[second, grantsOwner],
		]) {
			const err = await refusal(modules);

			expect(err.reason).toBe("duplicate-contribute");
			expect(err.details).toMatchObject({ kind: "grants", identity: OFF });
		}
	});

	it("is no override target: an override of it is refused as override-target-missing", async () => {
		const err = await refusal([
			grantsOwner,
			defineModule({
				name: "test:grants-overrider",
				overrides: { grants: { [OFF]: () => fakeGrantHandler("override") } },
			}),
		]);

		expect(err.reason).toBe("override-target-missing");
		expect(err.details).toEqual({
			reason: "override-target-missing",
			kind: "grants",
			name: OFF,
			overridingModule: "test:grants-overrider",
		});
		expect(err.message).toContain("switched off");
	});

	it("lets an override answer null, which switches off the grant it replaces", async () => {
		const handle = await boot([
			grantsOwner,
			defineModule({
				name: "test:grants-switcher",
				overrides: { grants: { [ON]: () => null } },
			}),
		]);
		const resolver = handle.components.grantHandlerResolver;

		expect(resolver?.get(ON)).toBeUndefined();
		expect([...(resolver?.entries() ?? [])]).toEqual([]);

		await handle.dispose();
	});
});
