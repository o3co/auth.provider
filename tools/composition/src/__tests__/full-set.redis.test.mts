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
 * The full set on real Redis, under `deployment.mode = "multi"`: every shared
 * store on the standalone template's one ioredis socket (the added packages'
 * device-code and challenge stores included), express-session on its own
 * node-redis connection, all against the Redis package's shared test
 * container (`testRedis()`, one database for this file).
 *
 * What it holds, with every package on:
 *
 * - the replica-safety declarations: the all-Redis set boots with nothing
 *   declaring replica-unsafe state, and each added memory store is refused at
 *   boot, by name;
 * - the state really is shared: two replicas booted on the one database, a
 *   flow started on one finishes on the other — a login and an authorization
 *   code, a device authorization, a DPoP proof's single use.
 *
 * The WebAuthn credential store is the one exception: no package ships a
 * shared one, and the WebAuthn README has a production deployment wire its own
 * database. The fixture stands one in (`deploymentCredentialStoreModule`);
 * what `multi` refuses is the bundled memory module, and that is checked here.
 */

import { replicaUnsafeReason } from "@o3co/auth-provider-core";
import { DEVICE_CODE_GRANT_TYPE } from "@o3co/auth-provider-device-grant";
import {
	ALICE,
	authorize,
	basic,
	codeFrom,
	ISSUER,
	lodgeGrant,
	login,
	MULTI_ENV,
	redeem,
} from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import { Redis } from "ioredis";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { type TestRedis, testRedis } from "../../../../packages/redis/__tests__/support/redis.mts";
import {
	BINDER,
	composeFullSet,
	dpopProof,
	type FullSet,
	type FullSetOptions,
	memoryWebAuthnCredentialStoreModule,
	TV,
} from "./full-set.fixture.mts";

let redis: TestRedis;
let env: Record<string, string>;
let inspect: Redis;

beforeAll(async () => {
	redis = await testRedis();
	const url = `redis://${redis.host}:${redis.port}/${redis.db}`;
	env = {
		...MULTI_ENV,
		REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: url,
		SESSION_STORAGE_REDIS_URL: url,
	};
	inspect = new Redis({ host: redis.host, port: redis.port, db: redis.db });
});

afterAll(() => {
	inspect?.disconnect();
});

const booted: FullSet[] = [];

afterEach(async () => {
	await Promise.all(booted.splice(0).map((c) => c.handle.dispose()));
});

/** One replica of the full set on this file's Redis database. */
async function replica(options: FullSetOptions = {}): Promise<FullSet> {
	const composition = await composeFullSet({
		env,
		stores: "redis",
		shippedRefreshTokenFamilyStore: true,
		...options,
	});
	booted.push(composition);
	return composition;
}

describe('every package on, every shared store on Redis, deployment.mode = "multi"', () => {
	it("boots, with the added stores on Redis and nothing declaring replica-unsafe state", async () => {
		const { modules, handle } = await replica();
		const names = modules.map((m) => m.name);
		expect(names).toEqual(
			expect.arrayContaining([
				"standalone:redis-clients",
				"redis-device-code-store",
				"redis-challenge-store",
				"deployment:webauthn-credential-store",
			]),
		);
		for (const module of modules) expect(replicaUnsafeReason(module), module.name).toBeUndefined();
		const probes = handle.readinessProbes.filter((p) => p.name === "redis");
		expect(probes).toHaveLength(1);
		await expect(probes[0]?.check()).resolves.toBe("PONG");
	});

	/**
	 * Each added memory store, alone, against the all-Redis rest. The boot
	 * names the module that declared the state it would fork.
	 */
	const REFUSED: ReadonlyArray<readonly [store: string, options: FullSetOptions, module: string]> =
		[
			["the device-code store", { deviceCodeStore: "memory" }, "core-device-code-store-memory"],
			["the challenge store", { challengeStore: "memory" }, "core-challenge-store-memory"],
			[
				"the WebAuthn credential store",
				{ credentialStore: memoryWebAuthnCredentialStoreModule },
				"core-webauthn-credential-store-memory",
			],
		];

	it.each(REFUSED)(
		"%s in memory is refused at boot, naming it",
		async (_store, options, module) => {
			await expect(replica(options)).rejects.toMatchObject({
				name: "BootError",
				reason: "replica-unsafe-adapter",
				details: { modules: [module] },
			});
		},
	);
});

describe("two replicas on one Redis database share every flow's state", () => {
	it("a login and an authorization code on one replica, redeemed and refreshed on the other", async () => {
		const a = await replica();
		const b = await replica();
		const { cookies } = await login(a.app);
		const code = codeFrom(await authorize(b.app, cookies));
		const tokens = await redeem(a.app, code);
		expect(tokens.status).toBe(200);
		const refreshed = await request(b.app)
			.post("/oauth/token")
			.set("Authorization", basic({ id: "web", secret: "web-secret" }))
			.type("form")
			.send({ grant_type: "refresh_token", refresh_token: tokens.body.refresh_token });
		expect(refreshed.status).toBe(200);
	});

	it("a device authorization started on one replica, approved and redeemed on the other", async () => {
		const a = await replica();
		const b = await replica();
		const started = await request(a.app)
			.post("/oauth/device_authorization")
			.type("form")
			.send({ client_id: TV.id });
		expect(started.status).toBe(200);

		const agent = request.agent(b.app);
		const csrf = await agent.get("/session/csrf");
		const signIn = await agent
			.post("/session/login")
			.set(csrf.body.header_name as string, csrf.body.csrf_token as string)
			.type("form")
			.send({ username: ALICE.username, password: ALICE.password });
		expect(signIn.status).toBe(200);
		const fresh = await agent.get("/session/csrf");
		const approved = await agent
			.post("/oauth/device/verification")
			.set(fresh.body.header_name as string, fresh.body.csrf_token as string)
			.send({ action: "approve", user_code: started.body.user_code });
		expect(approved.status).toBe(200);

		const tokens = await request(a.app).post("/oauth/token").type("form").send({
			grant_type: DEVICE_CODE_GRANT_TYPE,
			client_id: TV.id,
			device_code: started.body.device_code,
		});
		expect(tokens.status).toBe(200);
	});

	it("a DPoP proof accepted on one replica is refused on the other", async () => {
		const a = await replica();
		const b = await replica();
		const proof = dpopProof("POST", `${ISSUER}/oauth/token`);
		const token = (app: FullSet["app"]) =>
			request(app)
				.post("/oauth/token")
				.set("Authorization", basic(BINDER))
				.set("DPoP", proof)
				.type("form")
				.send({ grant_type: "client_credentials" });
		expect((await token(a.app)).status).toBe(200);
		const replayed = await token(b.app);
		expect(replayed.status).toBe(400);
		expect(replayed.body.error).toBe("invalid_dpop_proof");
	});

	it("keeps the state in Redis: a WebAuthn challenge and a federation grant intent land in the database", async () => {
		const a = await replica();
		const before = await inspect.dbsize();
		expect(
			(await request(a.app).post("/oauth/webauthn/authentication/options").send({})).status,
		).toBe(200);
		expect((await lodgeGrant(a.app)).status).toBe(201);
		expect(await inspect.dbsize()).toBeGreaterThan(before);
	});
});
