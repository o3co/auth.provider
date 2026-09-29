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
 * The session store module's `csrfTokenSigner`: the CSRF token's signature,
 * under a key derived from `session.secret` that never leaves the signer. A
 * fixed vector pins the derivation, so a token signed under a secret verifies
 * for as long as the deployment keeps that secret. The session module's
 * `csrfGuard` and the session routes sign and verify through the slot and
 * read no `session.secret`; a composition without the session store's module
 * fills the slot itself or is refused at boot.
 */

import { createHmac, hkdfSync } from "node:crypto";
import {
	type AppConfig,
	type CsrfGuard,
	type CsrfTokenSigner,
	defineModule,
	type FederationTokenStore,
	type Module,
	type SessionFederationIndex,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	createTestApp,
	createTestCsrfTokenSigner,
	csrfTokenSignerContract,
	makeValidAppConfig,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { createSessionCsrfTokenSigner } from "#/csrf-token-signer.mjs";
import { sessionModule } from "#/module.mjs";
import { sessionStoreModule, sessionStoreModuleFor } from "#/modules/sessionStoreModule.mjs";

/**
 * A token's payload (`<expiry-seconds>.<nonce>`, the expiry in 2100) and its
 * signature under `secret`: what `createCsrfProtection` accepted as a
 * well-signed token when it derived the key from the secret itself.
 */
const VECTOR = {
	secret: "fixed-vector.session-secret.at-least-32-bytes.ok",
	payload: "4102444800.Zml4ZWQtdmVjdG9yLW5vbmNl",
	signature: "uMTD9J4fNg6OrX38rJXZ9QNr3VIPUxlUSG7yRJ3OLkA",
} as const;

/** The whole double-submit token the vector makes. */
const VECTOR_TOKEN = `${VECTOR.payload}.${VECTOR.signature}`;

const OTHER_SECRET = "another-session-secret.at-least-32-bytes.ok";

/** The derivation, written out: HKDF-SHA256 (no salt, 32 bytes) under the info label, then HMAC-SHA256, base64url. */
const derivedSignature = (secret: string, payload: string): string =>
	createHmac(
		"sha256",
		Buffer.from(hkdfSync("sha256", secret, "", "o3co.auth.provider/session-csrf/v1", 32)),
	)
		.update(payload, "utf8")
		.digest("base64url");

/** The valid fixture configuration with `session` changed: plain HTTP for supertest, and `secret`. */
const configWith = (secret: string): AppConfig => {
	const base = makeValidAppConfig();
	return {
		...base,
		session: { ...base.session, name: "auth.session", secure: false, secret },
	} as AppConfig;
};

// ---------------------------------------------------------------------------
// The signer a session secret gives
// ---------------------------------------------------------------------------

describe("createSessionCsrfTokenSigner keeps core's csrfTokenSigner contract", () => {
	it.each(
		csrfTokenSignerContract({
			build: () => createSessionCsrfTokenSigner(VECTOR.secret),
			other: () => createSessionCsrfTokenSigner(OTHER_SECRET),
			sessionSecret: VECTOR.secret,
		}),
	)("$name", async ({ run }) => {
		await run();
	});
});

describe("the signature a session secret gives", () => {
	it("signs the fixed vector, and verifies it", () => {
		const signer = createSessionCsrfTokenSigner(VECTOR.secret);
		expect(signer.sign(VECTOR.payload)).toBe(VECTOR.signature);
		expect(signer.verify(VECTOR.payload, VECTOR.signature)).toBe(true);
	});

	it("is the HMAC-SHA256 of the payload under the HKDF-SHA256 expansion of the secret: no salt, info o3co.auth.provider/session-csrf/v1, 32 bytes", () => {
		const signer = createSessionCsrfTokenSigner(VECTOR.secret);
		for (const payload of [VECTOR.payload, "", "1767225600.bm9uY2Utb2YtYW5vdGhlci10b2tlbg"]) {
			expect(signer.sign(payload)).toBe(derivedSignature(VECTOR.secret, payload));
		}
		expect(derivedSignature(VECTOR.secret, VECTOR.payload)).toBe(VECTOR.signature);
	});

	it("does not verify the vector under another secret", () => {
		expect(
			createSessionCsrfTokenSigner(OTHER_SECRET).verify(VECTOR.payload, VECTOR.signature),
		).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// The session store's module provides it
// ---------------------------------------------------------------------------

/** The session store module's `csrfTokenSigner` provider, called as the planner calls it. */
const providedSigner = (secret: string): CsrfTokenSigner => {
	const provide = (
		sessionStoreModule.provides as
			| { csrfTokenSigner?: (deps: { config: AppConfig }) => CsrfTokenSigner }
			| undefined
	)?.csrfTokenSigner;
	if (provide === undefined)
		throw new Error("the session store's module provides no csrfTokenSigner");
	return provide({ config: configWith(secret) });
};

describe("the session store module's csrfTokenSigner keeps core's contract", () => {
	it.each(
		csrfTokenSignerContract({
			build: () => providedSigner(VECTOR.secret),
			other: () => providedSigner(OTHER_SECRET),
			sessionSecret: VECTOR.secret,
		}),
	)("$name", async ({ run }) => {
		await run();
	});
});

const handles: { dispose(): Promise<void> }[] = [];
afterEach(async () => {
	await Promise.all(handles.splice(0).map((handle) => handle.dispose()));
});

describe("the session store module provides csrfTokenSigner", () => {
	it("hands a module that requires it the signer of session.secret: the fixed vector's signature", async () => {
		const seen: { signer?: CsrfTokenSigner } = {};
		const config = configWith(VECTOR.secret);
		const handle = await createTestApp({
			modules: [
				sessionStoreModuleFor(config),
				defineModule({
					name: "test:csrf-token-signer-consumer",
					requires: ["csrfTokenSigner"],
					contributes: {
						routes: [
							(deps) => {
								seen.signer = deps.csrfTokenSigner;
								return { id: "test:probe", mountPath: "/probe", handler: express.Router() };
							},
						],
					},
				}),
			],
			bootstrapComponents: { config, pathResolver: (s: string) => s },
		});
		handles.push(handle);
		expect(Object.isFrozen(seen.signer)).toBe(true);
		expect(seen.signer?.sign(VECTOR.payload)).toBe(VECTOR.signature);
	});
});

// ---------------------------------------------------------------------------
// The session module signs through the slot
// ---------------------------------------------------------------------------

const providing = <T,>(name: string, slot: string, value: T) =>
	defineModule({ name, provides: { [slot]: () => value } as never });

const fakeUserRepository = {
	authenticate: async () => null,
	authenticateByToken: async () => null,
} as unknown as UserRepository;

const fakeUserSessionStore = (): UserSessionStore =>
	({
		kind: "memory",
		async create() {},
		async get() {
			return null;
		},
		async delete() {},
	}) as unknown as UserSessionStore;

const fakeFederationTokenStore = (): FederationTokenStore =>
	({
		kind: "memory",
		async attach() {},
		async get() {
			return null;
		},
		async update() {},
		async removeBySid() {},
		async delete() {},
	}) as unknown as FederationTokenStore;

const fakeSessionFederationIndex = (): SessionFederationIndex =>
	({
		kind: "memory",
		async addFederation() {},
		async listFederations() {
			return [];
		},
		async removeFederation() {},
		async removeBySid() {},
	}) as unknown as SessionFederationIndex;

/** What the session module requires beside the signer. */
const stores = () => [
	providing("test:user-repository", "userRepository", fakeUserRepository),
	providing("test:user-session-store", "userSessionStore", fakeUserSessionStore()),
	providing("test:federation-token-store", "federationTokenStore", fakeFederationTokenStore()),
	providing(
		"test:session-federation-index",
		"sessionFederationIndex",
		fakeSessionFederationIndex(),
	),
];

/** A cookie session that keeps nothing, where the session store's module is not loaded: the session routes read `req.session`. */
const bareSession = () =>
	defineModule({
		name: "test:bare-session",
		contributes: {
			routes: [
				() => ({
					id: "test:bare-session",
					mountPath: "/",
					handler: (req: express.Request, _res: express.Response, next: express.NextFunction) => {
						(req as unknown as { session: Record<string, unknown> }).session = {
							destroy: (cb: (err: unknown) => void) => cb(null),
							save: (cb: (err: unknown) => void) => cb(null),
						};
						next();
					},
				}),
			],
		},
	});

/** A module that mounts the `csrfGuard` slot in front of `POST /probe`, and answers `GET /probe` with a token the guard issued. */
const probe = () =>
	defineModule({
		name: "test:csrf-guard-consumer",
		requires: ["csrfGuard"],
		contributes: {
			routes: [
				(deps) => {
					const guard: CsrfGuard = deps.csrfGuard;
					const router = express.Router();
					router.post("/", guard.middleware, (_req, res) => {
						res.status(200).json({ ok: true });
					});
					router.get("/", (_req, res) => {
						res.status(200).json({ token: guard.issue(res) });
					});
					return { id: "test:probe", mountPath: "/probe", handler: router };
				},
			],
		},
	});

/** An app over `modules`, booted on `config`. */
const bootApp = async (modules: Module[], config: AppConfig): Promise<express.Express> => {
	const handle = await createTestApp({
		modules,
		bootstrapComponents: { config, pathResolver: (s: string) => s },
	});
	handles.push(handle);
	const app = express();
	app.use(handle.router);
	return app;
};

/** `token`'s payload and signature. */
const partsOf = (token: string): { payload: string; signature: string } => {
	const cut = token.lastIndexOf(".");
	return { payload: token.slice(0, cut), signature: token.slice(cut + 1) };
};

/** A well-formed token for `payload`, signed by `signer`. */
const tokenSignedBy = (signer: CsrfTokenSigner, payload: string): string =>
	`${payload}.${signer.sign(payload)}`;

/** A request carrying `token` as the double-submit pair and no origin signal. */
const withToken = (test: request.Test, token: string): request.Test =>
	test.set("Cookie", `auth.session.csrf=${token}`).set("x-csrf-token", token);

/** A payload a token issued now would carry: an expiry an hour ahead, and a nonce. */
const livePayload = (): string =>
	`${Math.floor(Date.now() / 1000) + 3600}.bGl2ZS1wYXlsb2FkLW5vbmNlLW9mLWEtdGVzdA`;

describe("the session module requires csrfTokenSigner", () => {
	it("declares it in requires", () => {
		expect(sessionModule.requires).toContain("csrfTokenSigner");
	});

	it("is refused at boot in a composition that provides no signer, naming the slot", async () => {
		await expect(
			createTestApp({
				modules: [sessionModule, ...stores()],
				bootstrapComponents: { config: configWith(VECTOR.secret), pathResolver: (s: string) => s },
			}),
		).rejects.toThrow(
			/Missing required component "csrfTokenSigner" — module "session" requires it/,
		);
	});
});

describe("the session module signs and verifies through the signer in the slot, not the session secret", () => {
	/**
	 * The session module without the session store's module, beside a module
	 * that fills the slot with a signer over a key of its own, not
	 * `session.secret`'s.
	 */
	const withOwnSigner = async () => {
		const signer = createTestCsrfTokenSigner();
		const app = await bootApp(
			[
				bareSession(),
				sessionModule,
				...stores(),
				providing("test:csrf-token-signer", "csrfTokenSigner", signer),
				probe(),
			],
			configWith(VECTOR.secret),
		);
		// The session secret's signature, written out rather than taken from the store's signer.
		const secretSigner: CsrfTokenSigner = {
			sign: (payload) => derivedSignature(VECTOR.secret, payload),
			verify: (payload, signature) => derivedSignature(VECTOR.secret, payload) === signature,
		};
		return { app, signer, secretSigner };
	};

	it("GET /session/csrf and the slot's issue sign with the signer", async () => {
		const { app, signer, secretSigner } = await withOwnSigner();
		for (const token of [
			(await request(app).get("/session/csrf")).body.csrf_token as string,
			(await request(app).get("/probe")).body.token as string,
		]) {
			const { payload, signature } = partsOf(token);
			expect(signer.verify(payload, signature)).toBe(true);
			expect(secretSigner.verify(payload, signature)).toBe(false);
		}
	});

	it("POST /session/logout and the slot's guard accept a token the signer signed", async () => {
		const { app, signer } = await withOwnSigner();
		const token = tokenSignedBy(signer, livePayload());
		expect((await withToken(request(app).post("/session/logout"), token).send({})).status).toBe(
			200,
		);
		expect((await withToken(request(app).post("/probe"), token).send({})).status).toBe(200);
	});

	it("POST /session/logout and the slot's guard refuse a token signed under the session secret", async () => {
		const { app, secretSigner } = await withOwnSigner();
		const token = tokenSignedBy(secretSigner, livePayload());
		const logout = await withToken(request(app).post("/session/logout"), token).send({});
		expect(logout.status).toBe(403);
		expect(logout.body.error).toBe("access_denied");
		const probed = await withToken(request(app).post("/probe"), token).send({});
		expect(probed.status).toBe(403);
		expect(probed.body.error).toBe("access_denied");
	});

	it("a token GET /session/csrf hands out passes the slot's guard, and one the slot issues passes POST /session/logout", async () => {
		const { app } = await withOwnSigner();
		const agent = request.agent(app);
		const fromRoutes = await agent.get("/session/csrf");
		expect(
			(await agent.post("/probe").set("x-csrf-token", fromRoutes.body.csrf_token).send({})).status,
		).toBe(200);
		const other = request.agent(app);
		const fromSlot = await other.get("/probe");
		expect(
			(await other.post("/session/logout").set("x-csrf-token", fromSlot.body.token).send({}))
				.status,
		).toBe(200);
	});
});

describe("the session module reads no session.secret", () => {
	it("neither its providers nor its route factories nor its routes read it", async () => {
		const reads: string[] = [];
		const base = configWith(VECTOR.secret);
		const session = new Proxy(base.session as object, {
			get(target, key, receiver) {
				if (key === "secret") reads.push("session.secret");
				return Reflect.get(target, key, receiver);
			},
		});
		const config = { ...base, deployment: { mode: "single" }, session } as unknown as AppConfig;
		// What the planner hands the module's factories; no federation is configured.
		const deps = {
			config,
			csrfTokenSigner: createTestCsrfTokenSigner(),
			userRepository: fakeUserRepository,
			userSessionStore: fakeUserSessionStore(),
			federationTokenStore: fakeFederationTokenStore(),
			sessionFederationIndex: fakeSessionFederationIndex(),
			federationProviders: new Map(),
			federationRedirectPolicyResolver: new Map(),
			sessionRequirementResolver: resolverForTests([]),
		};
		const provides = sessionModule.provides as Record<string, (d: unknown) => unknown>;
		for (const provide of Object.values(provides)) provide(deps);
		const routes = (sessionModule.contributes?.routes ?? []) as unknown as ((d: unknown) => {
			readonly id: string;
			readonly handler: express.RequestHandler;
		})[];
		const app = express();
		app.use((req, _res, next) => {
			(req as unknown as { session: Record<string, unknown> }).session = {
				destroy: (cb: (err: unknown) => void) => cb(null),
				save: (cb: (err: unknown) => void) => cb(null),
			};
			next();
		});
		for (const route of routes) app.use("/session", route(deps).handler);
		const agent = request.agent(app);
		const issued = await agent.get("/session/csrf");
		expect(issued.status).toBe(200);
		const logout = await agent
			.post("/session/logout")
			.set("x-csrf-token", issued.body.csrf_token as string)
			.send({});
		expect(logout.status).toBe(200);
		expect(reads).toEqual([]);
	});
});

// ---------------------------------------------------------------------------
// A token signed under the session secret keeps verifying
// ---------------------------------------------------------------------------

describe("a token signed under session.secret verifies through the session store's signer", () => {
	it("passes POST /session/logout and the csrfGuard slot in a composition with the session store's module", async () => {
		const config = configWith(VECTOR.secret);
		const app = await bootApp(
			[sessionStoreModuleFor(config), sessionModule, ...stores(), probe()],
			config,
		);
		expect(
			(await withToken(request(app).post("/session/logout"), VECTOR_TOKEN).send({})).status,
		).toBe(200);
		expect((await withToken(request(app).post("/probe"), VECTOR_TOKEN).send({})).status).toBe(200);
	});

	it("fails both under another session secret", async () => {
		const config = configWith(OTHER_SECRET);
		const app = await bootApp(
			[sessionStoreModuleFor(config), sessionModule, ...stores(), probe()],
			config,
		);
		expect(
			(await withToken(request(app).post("/session/logout"), VECTOR_TOKEN).send({})).status,
		).toBe(403);
		expect((await withToken(request(app).post("/probe"), VECTOR_TOKEN).send({})).status).toBe(403);
	});
});
