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
 * Introspection answers by an access token's authentication time against
 * the subject's revocation boundary, as well as by its issuance time: a token
 * issued after the boundary from an authentication before it is inactive; a
 * token with no `auth_time` is judged by its `iat` alone.
 */

import { createSecretKey } from "node:crypto";
import {
	type ClientRepository,
	type CodeRepository,
	createInMemorySubjectRevocation,
	createSymmetricKeyStore,
	type SubjectRevocation,
} from "@o3co/auth-provider-core";
import {
	GrantRegistry,
	makeValidAppConfig,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { routerInputsOf } from "./_helpers/sections.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

const ISSUER = "https://auth.example";
const CLIENT_ID = "c-1";
const CLIENT_SECRET = "c-1-secret";
const SUBJECT = "u-1";

const clientEntry = (id: string) => ({
	clientId: id,
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedRedirectUris: [],
	allowedScopes: [],
});

const clientRepository: ClientRepository = {
	findById: async (id) => (id === CLIENT_ID ? clientEntry(id) : null),
	authenticate: async (id, secret) =>
		id === CLIENT_ID && secret === CLIENT_SECRET ? clientEntry(id) : null,
};

const codeRepository: CodeRepository = {
	createCode: async () =>
		codeRecord({ code: "test-code", client_id: CLIENT_ID, redirect_uri: "https://rp.example/cb" }),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

const config = {
	...makeValidAppConfig(),
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {},
	},
	endpoints: { login: { url: "/login" } },
} as unknown as import("@o3co/auth-provider-core").AppConfig;

const nowSeconds = (): number => Math.floor(Date.now() / 1000);

/** A sessionless access token, otherwise valid; `authTime` absent leaves `auth_time` out. */
const accessToken = (opts: { iat: number; authTime?: number }): Promise<string> =>
	new SignJWT({
		sub: SUBJECT,
		scope: "read",
		client_id: CLIENT_ID,
		amr: ["hwk"],
		...(opts.authTime === undefined ? {} : { auth_time: opts.authTime }),
	})
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setIssuer(ISSUER)
		.setAudience(CLIENT_ID)
		.setIssuedAt(opts.iat)
		.setExpirationTime(opts.iat + 3600)
		.sign(secretKey);

const buildApp = async (subjectRevocation: SubjectRevocation) => {
	const { router } = await createOAuthRouter(express, {
		requirements: resolverForTests([]),
		registry: new GrantRegistry(),
		...routerInputsOf(config),
		clientRepository,
		codeRepository,
		keyStore,
		subjectRevocation,
	});
	const app = express();
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));
	app.use("/oauth", router);
	return app;
};

const introspect = (app: express.Express, token: string) =>
	request(app)
		.post("/oauth/introspect")
		.auth(CLIENT_ID, CLIENT_SECRET)
		.type("form")
		.send({ token });

/** A boundary stamped a minute ago. */
const stampedAMinuteAgo = async () => {
	const revocation = createInMemorySubjectRevocation();
	const stampMs = Date.now() - 60_000;
	await revocation.revokeBefore(SUBJECT, new Date(stampMs), new Date(Date.now() + 3_600_000));
	return { revocation, stampSeconds: Math.floor(stampMs / 1000) };
};

describe("introspection — an access token's authentication time against the subject boundary", () => {
	it("answers inactive for a token issued after the boundary from an authentication before it", async () => {
		const { revocation, stampSeconds } = await stampedAMinuteAgo();
		const app = await buildApp(revocation);

		const res = await introspect(
			app,
			await accessToken({ iat: nowSeconds(), authTime: stampSeconds - 30 }),
		);

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ active: false });
	});

	it("answers active for one whose authentication is past the boundary and its allowance", async () => {
		const { revocation, stampSeconds } = await stampedAMinuteAgo();
		const app = await buildApp(revocation);

		const res = await introspect(
			app,
			await accessToken({ iat: nowSeconds(), authTime: stampSeconds + 5 }),
		);

		expect(res.status).toBe(200);
		expect(res.body).toMatchObject({ active: true, sub: SUBJECT });
	});

	it("judges a token with no auth_time by its iat alone", async () => {
		const { revocation, stampSeconds } = await stampedAMinuteAgo();
		const app = await buildApp(revocation);

		const after = await introspect(app, await accessToken({ iat: nowSeconds() }));
		const before = await introspect(app, await accessToken({ iat: stampSeconds - 30 }));

		expect(after.body).toMatchObject({ active: true });
		expect(before.body).toEqual({ active: false });
	});
});
