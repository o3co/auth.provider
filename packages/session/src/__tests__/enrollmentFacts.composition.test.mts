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
 * A password login and a federated login, booted through core's `createApp`
 * with the session module over core's memory stores, each record in the
 * session what their login's `User` says for a first binding: the MFA
 * enrollment witness and whether the account has an address
 * (`UserSession.enrollmentFacts`).
 */

import {
	type AppConfig,
	codeChallenge,
	createApp,
	createInMemoryUserSessionStore,
	defaultRefreshTokenFamilyRevocationModule,
	defineModule,
	type FederationProvider,
	memoryFederationTokenStoreModule,
	memoryRefreshTokenFamilyStoreModule,
	memorySessionStoresModule,
	type User,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { sessionModule } from "#/module.mjs";
import { sessionStoreModuleFor } from "#/modules/sessionStoreModule.mjs";

const PASSWORD = "correct horse battery staple";
const CALLBACK_URL = "https://auth.test/session/oauth/federation/stub/callback";

/** A query-mode provider whose IdP always answers the same subject. */
const stubProvider: FederationProvider = {
	name: "stub",
	scope: ["openid"],
	buildAuthorizationUrl: ({ state, codeVerifier }) => {
		const url = new URL("https://idp.example.com/authorize");
		url.searchParams.set("state", state);
		url.searchParams.set("code_challenge", codeChallenge(codeVerifier));
		return url;
	},
	exchangeCode: async () => ({
		issuer: "https://idp.example.com",
		sub: "external-1",
		expiresAt: null,
	}),
};

const stubFederationModule = defineModule({
	name: "test:stub-federation",
	contributes: {
		federations: { stub: () => stubProvider },
		federationRedirectPolicies: {
			stub: () => ({
				validateRedirect: () => ({ ok: true as const, value: undefined }),
				resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
			}),
		},
	},
});

let disposeLast: (() => Promise<void>) | undefined;

afterEach(async () => {
	await disposeLast?.();
	disposeLast = undefined;
});

/**
 * Boots the composition over a Store that answers `user` to a password
 * login and to the stub federation's identity, and answers the app and the
 * session records each login created, as the memory store reads them back.
 */
async function boot(user: User) {
	const sessions = createInMemoryUserSessionStore();
	const created: string[] = [];
	const recording: UserSessionStore = {
		...sessions,
		create: async (input) => {
			await sessions.create(input);
			created.push(input.sid);
		},
	};
	const userRepository: UserRepository = {
		authenticate: async (username, password) =>
			username === user.username && password === PASSWORD ? user : null,
		authenticateByToken: async (token) => (token === "stub:external-1" ? user : null),
	};
	const base = makeValidAppConfig();
	const config = {
		...base,
		// supertest speaks plain HTTP: no `Secure` cookie, so no `__Host-` name.
		session: { ...base.session, name: "auth.session", secure: false },
		federations: {
			stub: {
				enabled: true,
				clientId: "stub-client",
				clientSecret: "stub-secret",
				callbackURL: CALLBACK_URL,
			},
		},
	} as unknown as AppConfig;
	const handle = await createApp({
		modules: [
			// The cookie session's middleware is mounted ahead of the routes that read it.
			sessionStoreModuleFor(config),
			sessionModule,
			memorySessionStoresModule,
			memoryFederationTokenStoreModule,
			memoryRefreshTokenFamilyStoreModule,
			defaultRefreshTokenFamilyRevocationModule,
			stubFederationModule,
			defineModule({
				name: "test:deployment-providers",
				provides: { userRepository: () => userRepository },
			}),
		],
		bootstrapComponents: { config, pathResolver: (s: string) => s },
		overrideComponents: { userSessionStore: recording },
	});
	disposeLast = () => handle.dispose();
	const app = express();
	app.use(handle.router);
	/** The one record the login created, as the store reads it back. */
	const record = async () => {
		expect(created).toHaveLength(1);
		return sessions.get(created[0] as string);
	};
	return { app, record };
}

async function passwordLogin(app: express.Express, username: string): Promise<void> {
	const agent = request.agent(app);
	const csrf = await agent.get("/session/csrf");
	expect(csrf.status).toBe(200);
	const login = await agent
		.post("/session/login")
		.set(csrf.body.header_name as string, csrf.body.csrf_token as string)
		.send({ username, password: PASSWORD });
	expect(login.status).toBe(200);
}

async function federatedLogin(app: express.Express): Promise<void> {
	const agent = request.agent(app);
	const start = await agent.get("/session/oauth/federation/stub");
	expect(start.status).toBe(302);
	const state = new URL(start.headers.location as string).searchParams.get("state") ?? "";
	const callback = await agent
		.get("/session/oauth/federation/stub/callback")
		.query({ code: "stub-code", state });
	expect(callback.status).toBe(302);
}

/** A `User` the Store answers, and the facts the session records of it. */
const USERS: ReadonlyArray<
	readonly [string, User, { readonly witness: string; readonly mailAddress: boolean }]
> = [
	[
		"enrolled, with an address",
		{ id: "user-1", username: "alice", mfaEnrolled: true, email: "alice@example.com" },
		{ witness: "enrolled", mailAddress: true },
	],
	[
		"not enrolled, without an address",
		{ id: "user-2", username: "bob" },
		{ witness: "not_enrolled", mailAddress: false },
	],
	[
		"a witness the Store should not have answered, and an email that is no address",
		{ id: "user-3", username: "carol", mfaEnrolled: null, email: "carol at example.com" },
		{ witness: "malformed", mailAddress: false },
	],
];

describe("a password login through createApp records the enrollment facts its User says", () => {
	it.each(USERS)("for a user %s", async (_label, user, facts) => {
		const { app, record } = await boot(user);
		await passwordLogin(app, user.username as string);
		expect((await record())?.enrollmentFacts).toStrictEqual(facts);
	});
});

describe("a federated login through createApp records the enrollment facts its User says", () => {
	it.each(USERS)("for a user %s", async (_label, user, facts) => {
		const { app, record } = await boot(user);
		await federatedLogin(app);
		expect((await record())?.enrollmentFacts).toStrictEqual(facts);
	});
});
