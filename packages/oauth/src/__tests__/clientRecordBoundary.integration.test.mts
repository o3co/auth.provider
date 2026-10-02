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
 * The oauth endpoints, booted by `createApp`, read a client record through
 * core's client-record boundary over the `clientRepository` slot's
 * repository: a record the registration schema refuses is an unknown
 * client, a record whose field read throws is the repository's outage, and
 * an ORM entity is read by name.
 */

import {
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	defineModule,
	type GrantHandler,
	jwksModule,
	memoryAccessTokenDenylistModule,
	type PublicClient,
} from "@o3co/auth-provider-core";
import {
	createTestApp,
	createTestLoginEntry,
	makeValidAppConfig,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { oauthModule } from "#/module.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";
import { withOauthCaptures } from "./_helpers/sections.mjs";

const CLIENT_ID = "rp-1";
const SECRET = "rp-1-secret";
const REDIRECT_URI = "https://rp.example/cb";

const VALID = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedRedirectUris: [REDIRECT_URI],
	allowedScopes: ["openid"],
	firstParty: true,
};

/** An entity as an ORM hands it out: each column a getter on the prototype. */
function ormEntity(columns: Record<string, unknown>): object {
	class Entity {
		constructor(readonly dataValues: Record<string, unknown>) {}
	}
	for (const column of Object.keys(columns)) {
		Object.defineProperty(Entity.prototype, column, {
			get(this: Entity) {
				return this.dataValues[column];
			},
		});
	}
	return new Entity({ ...columns });
}

const answering = (record: () => unknown): ClientRepository => ({
	findById: async (clientId) => (clientId === CLIENT_ID ? (record() as PublicClient) : null),
	authenticate: async (clientId, secret) =>
		clientId === CLIENT_ID && secret === SECRET ? (record() as PublicClient) : null,
});

const codeRepository: CodeRepository = {
	createCode: async () =>
		codeRecord({ code: "code-1", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI }),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

/** A stand-in authorization_code grant, so `/authorize` is mounted. Never dispatched to. */
const authorizationCodeGrantModule = defineModule({
	name: "test:authorization-code-grant",
	contributes: {
		grants: {
			authorization_code: (): GrantHandler => ({
				handle: async () => ({
					result: { status: 400, error: "invalid_grant", errorDescription: "stand-in" },
				}),
			}),
		},
	},
});

const boot = async (clientRepository: ClientRepository) => {
	const logger = createMockLogger();
	const config = makeValidAppConfig();
	const handle = await createTestApp({
		modules: [
			oauthModule({ config }),
			memoryAccessTokenDenylistModule,
			jwksModule,
			authorizationCodeGrantModule,
			defineModule({
				name: "test:repositories",
				provides: {
					clientRepository: () => clientRepository,
					codeRepository: () => codeRepository,
					keyStore: () => createSymmetricKeyStore("test-secret-for-client-boundary!!"),
					loginEntry: () => createTestLoginEntry(),
				},
			}),
			defineModule({
				name: "test:logger",
				provides: { logger: () => logger },
				lifecycle: { logger: { eager: true } },
			}),
		],
		bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s },
	});
	const app = express();
	app.use(handle.router);
	return { app, handle, logger };
};

const authorize = (app: express.Express) =>
	request(app).get("/oauth/authorize").query({
		response_type: "code",
		client_id: CLIENT_ID,
		redirect_uri: REDIRECT_URI,
		scope: "openid",
		prompt: "none",
		code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		code_challenge_method: "S256",
	});

const token = (app: express.Express) =>
	request(app)
		.post("/oauth/token")
		.auth(CLIENT_ID, SECRET)
		.type("form")
		.send({ grant_type: "authorization_code", code: "code-1", redirect_uri: REDIRECT_URI });

const refusals = (logger: ReturnType<typeof createMockLogger>) =>
	logger.warn.mock.calls.filter(([, message]) => message === "client_record_refused");

describe("oauth endpoints behind core's client-record boundary", () => {
	it("answer a record the registration schema refuses as an unknown client", async () => {
		const { app, handle, logger } = await boot(
			answering(() => ({ ...VALID, allowedRedirectUris: ["javascript:alert(1)"] })),
		);
		const authorized = await authorize(app);
		expect(authorized.status).toBe(400);
		expect(authorized.body).toMatchObject({ error: "invalid_client" });
		expect(authorized.headers.location).toBeUndefined();
		const exchanged = await token(app);
		expect(exchanged.status).toBe(401);
		expect(exchanged.body).toMatchObject({ error: "invalid_client" });
		// Client authentication looks the client up before it checks the secret,
		// so both requests stop at the lookup.
		expect(refusals(logger).map(([line]) => [line.step, line.clientId])).toEqual([
			["find", CLIENT_ID],
			["find", CLIENT_ID],
		]);
		await handle.dispose();
	});

	it("answer a record whose field read throws as the repository's outage", async () => {
		const unreadable = () =>
			Object.defineProperty({ ...VALID }, "allowedScopes", {
				get() {
					throw new Error("lazy column failed to load");
				},
			});
		const { app, handle, logger } = await boot(answering(unreadable));
		const authorized = await authorize(app);
		expect(authorized.status).toBe(503);
		expect(authorized.body).toMatchObject({ error: "temporarily_unavailable" });
		const exchanged = await token(app);
		expect(exchanged.status).toBe(503);
		expect(exchanged.body).toMatchObject({ error: "temporarily_unavailable" });
		expect(refusals(logger)).toEqual([]);
		await handle.dispose();
	});

	it("read an ORM entity's record by name and serve the client", async () => {
		const { app, handle, logger } = await boot(answering(() => ormEntity(VALID)));
		const authorized = await authorize(app);
		expect([400, 503]).not.toContain(authorized.status);
		const exchanged = await token(app);
		expect([401, 503]).not.toContain(exchanged.status);
		expect(refusals(logger)).toEqual([]);
		await handle.dispose();
	});
});
