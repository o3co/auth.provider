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
 * The full set on real Redis, under `core.deployment.mode = "multi"`: every shared
 * store on the standalone template's one ioredis socket (the added packages'
 * device-code and challenge stores included), express-session on its own
 * node-redis connection, all against the Redis package's shared test
 * container (`testRedis()`, one database for this file). With every package
 * on:
 *
 * - the all-Redis set boots with nothing declaring replica-unsafe state, and
 *   each added memory store is refused at boot, by name;
 * - the state really is shared: on two replicas booted on the one database, a
 *   flow started on one finishes on the other — a login and an authorization
 *   code, a device authorization, a DPoP proof's single use, a login's MFA
 *   transaction, a session's step-up.
 *
 * The WebAuthn credential store is the one exception: no package ships a
 * shared one, so the fixture stands in the deployment's own
 * (`deploymentCredentialStoreModule`); what `multi` refuses, and this checks,
 * is the bundled memory module.
 */

import {
	type MfaFactorStore,
	type MfaTransactionStore,
	replicaUnsafeReason,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { DEVICE_CODE_GRANT_TYPE } from "@o3co/auth-provider-device-grant";
import { totpCodeForTests } from "@o3co/auth-provider-mfa/testing";
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
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { type TestRedis, testRedis } from "../../../../packages/redis/__tests__/support/redis.mts";
import {
	addFactorRecord,
	BINDER,
	browser,
	composeFullSet,
	dpopProof,
	type FullSet,
	type FullSetOptions,
	memoryWebAuthnCredentialStoreModule,
	removeFactorRecords,
	seedTotp,
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
		REDIS_CLIENTS_URL: url,
		SESSION_STORE_STORAGE_REDIS_URL: url,
	};
	inspect = new Redis({ host: redis.host, port: redis.port, db: redis.db });
});

afterAll(() => {
	inspect?.disconnect();
});

const booted: FullSet[] = [];

/** A POST from a browser holding only `cookies`, with a CSRF token fetched on them from the replica it posts to. */
async function postWith(
	app: FullSet["app"],
	cookies: readonly string[],
	path: string,
	body: Record<string, unknown>,
): Promise<request.Response> {
	const csrf = await request(app).get("/session/csrf").set("Cookie", cookies.join("; "));
	const named = new Map(cookies.map((pair) => [pair.slice(0, pair.indexOf("=")), pair]));
	for (const line of ([] as string[]).concat(csrf.headers["set-cookie"] ?? [])) {
		const pair = line.split(";")[0] ?? "";
		named.set(pair.slice(0, pair.indexOf("=")), pair);
	}
	return request(app)
		.post(path)
		.set("Cookie", [...named.values()].join("; "))
		.set(csrf.body.header_name as string, csrf.body.csrf_token as string)
		.send(body);
}

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

describe('every package on, every shared store on Redis, core.deployment.mode = "multi"', () => {
	it("boots, with the added stores on Redis and nothing declaring replica-unsafe state", async () => {
		const { modules, handle, config } = await replica();
		const names = modules.map((m) => m.name);
		expect(names).toEqual(
			expect.arrayContaining([
				"redis-clients",
				"redis-device-code-store",
				"redis-challenge-store",
				"deployment:webauthn-credential-store",
				"redis-mfa-factor-store",
				"redis-mfa-transaction-store",
			]),
		);
		// Each module's section at its name, as boot parsed it: a declaration
		// made from the section is answered for it.
		const sections = config as unknown as Record<string, unknown>;
		for (const module of modules) {
			expect(replicaUnsafeReason(module, sections[module.name]), module.name).toBeUndefined();
		}
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

	it("the MFA stores in memory are refused at boot, naming both", async () => {
		await expect(replica({ mfaStores: "memory" })).rejects.toMatchObject({
			name: "BootError",
			reason: "replica-unsafe-adapter",
			details: {
				modules: expect.arrayContaining([
					"core-mfa-factor-store-memory",
					"core-mfa-transaction-store-memory",
				]),
			},
		});
	});
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

	it("a subject's device verification attempts are counted once across replicas, on the Redis attempt counter", async () => {
		// Earlier tests approve as the same subject: start from no counts.
		await inspect.flushdb();
		const hocon = "device-grant.rateLimit { limit = 2, windowSeconds = 300 }";
		const a = await replica({ operatorHocon: hocon });
		const b = await replica({ operatorHocon: hocon });
		expect(a.handle.components.attemptCounter).toBeDefined();
		const { cookies } = await login(a.app);
		const lookup = (app: FullSet["app"]) =>
			postWith(app, cookies, "/oauth/device/verification", {
				action: "lookup",
				user_code: "BCDF-GHJK",
			});
		expect((await lookup(a.app)).status).toBe(404);
		expect((await lookup(b.app)).status).toBe(404);
		const limited = await lookup(a.app);
		expect(limited.status).toBe(429);
		expect(limited.body.error).toBe("slow_down");
		expect(Number(limited.headers["retry-after"])).toBeGreaterThan(0);
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

	it("a login the mfa requirement interrupts on one replica is bound to a transaction the other reads, kept in Redis", async () => {
		const a = await replica();
		const b = await replica();
		const components = (set: FullSet) =>
			set.handle.components as unknown as {
				mfaFactorStore: MfaFactorStore;
				mfaTransactionStore: MfaTransactionStore;
			};
		// A factor enrolled through one replica's store is the other's too.
		await addFactorRecord(components(a).mfaFactorStore, {
			id: "f-alice",
			subject: ALICE.sub,
			kind: "totp",
			label: undefined,
			binding: "password",
			createdAt: new Date(),
			lastUsedAt: undefined,
			version: 0,
			data: "sealed",
		});
		const transactions = () => inspect.keys("mfat:tx:*");
		const before = await transactions();
		const agent = request.agent(b.app);
		const csrf = await agent.get("/session/csrf");
		const signIn = await agent
			.post("/session/login")
			.set(csrf.body.header_name as string, csrf.body.csrf_token as string)
			.type("form")
			.send({ username: ALICE.username, password: ALICE.password });
		expect(signIn.status).toBe(403);
		expect(signIn.body.error).toBe("mfa_required");
		expect((await transactions()).filter((key) => !before.includes(key))).toHaveLength(1);
		expect(
			await components(a).mfaTransactionStore.get(signIn.body.transaction as string),
		).toMatchObject({ purpose: "login", subject: ALICE.sub });
	});

	it("a TOTP login interrupted on one replica is verified on the other, and the session it establishes authorizes on the first", async () => {
		const a = await replica();
		const b = await replica();
		const { factorId, secret } = await seedTotp(a.handle.components, a.config, ALICE.sub);
		const page = browser();

		const signIn = await page.post(
			a.app,
			"/session/login",
			{ username: ALICE.username, password: ALICE.password },
			{ form: true },
		);
		expect(signIn.status).toBe(403);
		expect(signIn.body.error).toBe("mfa_required");
		const transaction = signIn.body.transaction as string;
		const verified = await page.post(b.app, "/session/mfa/verify", {
			transaction_id: transaction,
			factor_id: factorId,
			proof: totpCodeForTests(secret),
		});
		expect(verified.status, JSON.stringify(verified.body)).toBe(200);
		expect(await a.handle.components.mfaTransactionStore?.get(transaction)).toBeNull();

		const authorized = await authorize(a.app, page.cookies());
		expect(authorized.status).toBe(302);
		expect((await redeem(b.app, codeFrom(authorized))).status).toBe(200);
	});

	it("a step-up opened on one replica is verified on the other: the Redis session record holds the escalation and the renewal nonce, the old cookie is refused on both, the renewed one admitted for mfa.manage", async () => {
		const a = await replica();
		const b = await replica();
		const sessions = (set: FullSet) =>
			(set.handle.components as unknown as { userSessionStore: UserSessionStore }).userSessionStore;
		// Alice's password login must not be interrupted: whatever factors she holds in this
		// database are set aside for the test, and put back after it, whatever it came to.
		const factors = (a.handle.components as unknown as { mfaFactorStore: MfaFactorStore })
			.mfaFactorStore;
		const setAside = await removeFactorRecords(factors, ALICE.sub);
		try {
			const create = vi.spyOn(sessions(a), "create");
			const page = browser();
			const signIn = await page.post(
				a.app,
				"/session/login",
				{ username: ALICE.username, password: ALICE.password },
				{ form: true },
			);
			expect(signIn.status, JSON.stringify(signIn.body)).toBe(200);
			const sid = (create.mock.calls[0]?.[0] as { sid?: unknown } | undefined)?.sid as string;
			create.mockRestore();
			const { factorId, secret } = await seedTotp(a.handle.components, a.config, ALICE.sub);
			const old = page.cookies();
			expect((await page.post(a.app, "/session/mfa/enrollment", { kind: "totp" })).status).toBe(
				403,
			);

			expect((await postWith(b.app, old, "/session/mfa/step-up", {})).status).toBe(200);
			const opened = await page.post(a.app, "/session/mfa/step-up", {});
			expect(opened.status, JSON.stringify(opened.body)).toBe(200);
			expect(opened.body.email_proof).toBe(false);
			const verified = await page.post(b.app, "/session/mfa/verify", {
				transaction_id: opened.body.transaction,
				factor_id: factorId,
				proof: totpCodeForTests(secret),
			});

			expect(verified.status, JSON.stringify(verified.body)).toBe(200);
			expect(verified.body).toEqual({ step_up: "verified" });
			const record = await sessions(a).get(sid);
			expect(record?.amr).toEqual(["pwd", "otp", "mfa"]);
			expect(record?.authentication?.mfaAt).toBeInstanceOf(Date);
			expect(record?.renewalNonce).toEqual(expect.any(String));
			for (const set of [a, b]) {
				expect((await postWith(set.app, old, "/session/mfa/step-up", {})).status).toBe(401);
			}
			expect((await page.post(a.app, "/session/mfa/enrollment", { kind: "totp" })).status).toBe(
				200,
			);
		} finally {
			await removeFactorRecords(factors, ALICE.sub);
			for (const record of setAside) await addFactorRecord(factors, record);
		}
	});

	it("keeps the state in Redis: a WebAuthn challenge and a federation grant intent land in the database", async () => {
		const a = await replica();
		// Each write, by the key its store writes under (the Redis package's
		// default prefixes): a challenge, and an intent.
		const challenges = () => inspect.keys("chal:*");
		const intents = () => inspect.keys("fg:{intents}:i:*");
		const [challengesBefore, intentsBefore] = [await challenges(), await intents()];

		const options = await request(a.app).post("/oauth/webauthn/authentication/options").send({});
		expect(options.status).toBe(200);
		const issued = (await challenges()).filter((key) => !challengesBefore.includes(key));
		expect(issued).toHaveLength(1);
		expect(issued[0]).toContain(options.body.challenge as string);

		expect((await lodgeGrant(a.app)).status).toBe(201);
		expect((await intents()).filter((key) => !intentsBefore.includes(key))).toHaveLength(1);
	});
});
