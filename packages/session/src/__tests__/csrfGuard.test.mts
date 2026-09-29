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
 * The session package's `csrfGuard` (#728, #710 C4): the one CSRF policy the
 * session routes run, as the slot other packages require.
 *
 * - It keeps core's contract (`csrfGuardContract`), built from the session
 *   configuration as the session module builds it: the signed double-submit
 *   token of `createCsrfProtectionFromConfig`, the origin rule over
 *   `session.csrf.trustedOrigins`, and the link start's navigation rule.
 * - Its middleware answers and logs what `createCsrfGuard` does — the
 *   guard device verification ran before the slot, so the move changes no
 *   status, body or log line.
 * - The session module provides it, with the key `GET /session/csrf` signs
 *   with: a token the route hands out is accepted by the slot, and one the
 *   slot issues by the route's guard.
 */

import {
	type AppConfig,
	type CsrfGuard,
	defineModule,
	type FederationTokenStore,
	type Logger,
	type SessionFederationIndex,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	createTestApp,
	csrfGuardContract,
	makeValidAppConfig,
} from "@o3co/auth-provider-core/testing";
import express, { type Request, type Response } from "express";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	type CsrfProtection,
	createCsrfGuard,
	createCsrfProtectionFromConfig,
	createSessionCsrfGuard,
	type SessionCsrfConfigSlice,
} from "#/csrf.mjs";
import { csrfGuardOf, sessionModule } from "#/module.mjs";
import { sessionStoreModuleFor } from "#/modules/sessionStoreModule.mjs";

const TRUSTED = "https://app.contract.test";

/** The fixture configuration's session section, trusting one origin beside its own. */
const sessionSlice = (): SessionCsrfConfigSlice => {
	const { session } = makeValidAppConfig();
	return { ...session, csrf: { trustedOrigins: [TRUSTED] } };
};

const guardOver = (now?: () => number): CsrfGuard => {
	const session = sessionSlice();
	return createSessionCsrfGuard({
		csrf: createCsrfProtectionFromConfig(session, now === undefined ? {} : { now }),
		trustedOrigins: session.csrf?.trustedOrigins ?? [],
	});
};

describe("createSessionCsrfGuard keeps core's csrfGuard contract", () => {
	const { session } = makeValidAppConfig();
	it.each(
		csrfGuardContract({
			build: () => guardOver(),
			trustedOrigin: TRUSTED,
			withClock: (now) => guardOver(now),
			sessionCookie: {
				name: session.name,
				secure: session.secure,
				sameSite: session.sameSite,
				domain: undefined,
				maxAgeMs: session.maxAge,
			},
		}),
	)("$name", async ({ run }) => {
		await run();
	});

	it("reads the token from the form field csrf_token and the header x-csrf-token", () => {
		const guard = guardOver();
		expect(guard.bodyField).toBe("csrf_token");
		expect(guard.headerName).toBe("x-csrf-token");
		expect(guard.cookieName).toBe(`${session.name}.csrf`);
	});
});

// ---------------------------------------------------------------------------
// The middleware is createCsrfGuard's, answer and log line alike
// ---------------------------------------------------------------------------

const spyLogger = () => {
	const logger = {
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		child: () => logger,
	};
	return logger;
};

/** What a middleware answered one request with. */
const run = async (
	middleware: express.RequestHandler,
	headers: Record<string, string>,
): Promise<{ readonly status: number; readonly body: unknown }> => {
	const app = express();
	app.post("/verify", middleware, (_req: Request, res: Response) => {
		res.status(200).json({ ok: true });
	});
	const res = await request(app).post("/verify").set(headers).send({});
	return { status: res.status, body: res.body };
};

describe("the guard's middleware answers and logs as createCsrfGuard does", () => {
	/** Each refused request, as the headers it carries, built over the guard's own token mechanism. */
	const cases: ReadonlyArray<readonly [string, (csrf: CsrfProtection) => Record<string, string>]> =
		[
			["a foreign Origin", () => ({ origin: "https://attacker.example" })],
			["a foreign Referer with no Origin", () => ({ referer: "https://attacker.example/page" })],
			["no origin signal and no token", () => ({})],
			[
				"a token with no cookie",
				() => ({ "x-csrf-token": "1.aaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbb" }),
			],
			[
				"a cookie and a header carrying two different tokens, each well signed",
				(csrf) => ({ cookie: `${csrf.cookieName}=${csrf.mint()}`, [csrf.headerName]: csrf.mint() }),
			],
		];

	it.each(cases)("%s: the same status, body and warn line", async (_what, headersFor) => {
		const session = sessionSlice();
		const csrf = createCsrfProtectionFromConfig(session);
		const headers = headersFor(csrf);
		const slotLogger = spyLogger();
		const direct = spyLogger();
		const guard = createSessionCsrfGuard({
			csrf,
			trustedOrigins: [TRUSTED],
			logger: slotLogger as unknown as Logger,
		});
		const before = createCsrfGuard({
			csrf,
			trustedOrigins: [TRUSTED],
			logger: direct as unknown as Logger,
		});
		const viaSlot = await run(guard.middleware, headers);
		const viaGuard = await run(before, headers);
		expect(viaSlot.status).toBe(403);
		expect(viaSlot.status).toBe(viaGuard.status);
		expect(viaSlot.body).toEqual(viaGuard.body);
		expect(slotLogger.warn.mock.calls).toEqual(direct.warn.mock.calls);
		expect(slotLogger.warn).toHaveBeenCalledTimes(1);
	});
});

// ---------------------------------------------------------------------------
// The session module provides it
// ---------------------------------------------------------------------------

const providing = <T,>(name: string, slot: string, value: T) =>
	defineModule({ name, provides: { [slot]: () => value } as never });

const stores = [
	providing("test:user-repository", "userRepository", {
		authenticate: async () => null,
		authenticateByToken: async () => null,
	} as unknown as UserRepository),
	providing("test:user-session-store", "userSessionStore", {
		kind: "memory",
		async create() {},
		async get() {
			return null;
		},
		async delete() {},
	} as unknown as UserSessionStore),
	providing("test:federation-token-store", "federationTokenStore", {
		kind: "memory",
		async attach() {},
		async get() {
			return null;
		},
		async update() {},
		async removeBySid() {},
		async delete() {},
	} as unknown as FederationTokenStore),
	providing("test:session-federation-index", "sessionFederationIndex", {
		kind: "memory",
		async addFederation() {},
		async listFederations() {
			return [];
		},
		async removeFederation() {},
		async removeBySid() {},
	} as unknown as SessionFederationIndex),
];

/** A module that requires the guard and mounts it in front of `POST /probe`, which answers with a token the guard issued. */
const probe = (seen: { guard?: CsrfGuard }) =>
	defineModule({
		name: "test:csrf-guard-consumer",
		requires: ["csrfGuard"],
		contributes: {
			routes: [
				(deps) => {
					seen.guard = deps.csrfGuard;
					const router = express.Router();
					router.post("/", deps.csrfGuard.middleware, (_req, res) => {
						res.status(200).json({ ok: true });
					});
					router.get("/", (_req, res) => {
						res.status(200).json({ token: deps.csrfGuard.issue(res) });
					});
					return { id: "test:probe", mountPath: "/probe", handler: router };
				},
			],
		},
	});

const handles: { dispose(): Promise<void> }[] = [];
afterEach(async () => {
	await Promise.all(handles.splice(0).map((handle) => handle.dispose()));
});

const boot = async (seen: { guard?: CsrfGuard }): Promise<express.Express> => {
	const base = makeValidAppConfig();
	// supertest speaks plain HTTP: no `Secure` cookie and no `__Host-` name.
	const config = {
		...base,
		session: { ...base.session, name: "auth.session", secure: false },
	} as AppConfig;
	const handle = await createTestApp({
		// The session store's middleware first, as every composition lists it.
		modules: [sessionStoreModuleFor(config), sessionModule, ...stores, probe(seen)],
		bootstrapComponents: { config, pathResolver: (s: string) => s },
	});
	handles.push(handle);
	const app = express();
	app.use(handle.router);
	return app;
};

describe("the session module builds one guard per configuration", () => {
	it("hands the csrfGuard slot and loginCompletion the same guard, and another configuration another", () => {
		// The slot's provider and loginCompletion's both build the guard through
		// `csrfGuardOf`; one policy is one object, whichever reads it.
		const config = makeValidAppConfig() as AppConfig;
		const logger = spyLogger() as unknown as Logger;
		const first = csrfGuardOf(config, logger);
		expect(csrfGuardOf(config, logger)).toBe(first);
		expect(csrfGuardOf(makeValidAppConfig() as AppConfig, logger)).not.toBe(first);
		expect(csrfGuardOf(config, spyLogger() as unknown as Logger)).not.toBe(first);
	});
});

describe("the session module provides csrfGuard", () => {
	it("hands a module that requires it a guard that keeps the contract", async () => {
		const seen: { guard?: CsrfGuard } = {};
		await boot(seen);
		expect(seen.guard).toBeDefined();
		expect(Object.isFrozen(seen.guard)).toBe(true);
		expect(seen.guard?.cookieName).toBe("auth.session.csrf");
	});

	it("accepts the token GET /session/csrf hands out: one key, whoever mounts the guard", async () => {
		const app = await boot({});
		const agent = request.agent(app);
		const issued = await agent.get("/session/csrf");
		expect(issued.status).toBe(200);
		const accepted = await agent
			.post("/probe")
			.set(issued.body.header_name as string, issued.body.csrf_token as string)
			.send({});
		expect(accepted.status).toBe(200);
		const refused = await request(app).post("/probe").send({});
		expect(refused.status).toBe(403);
		expect(refused.body.error).toBe("access_denied");
	});

	it("issues a token the session routes' own guard accepts", async () => {
		const app = await boot({});
		const agent = request.agent(app);
		const issued = await agent.get("/probe");
		expect(issued.status).toBe(200);
		// `POST /session/logout` is behind the session routes' guard; with a
		// token it accepts, the request reaches the route (200, nothing to log out).
		const logout = await agent
			.post("/session/logout")
			.set("x-csrf-token", issued.body.token as string)
			.send({});
		expect(logout.status).toBe(200);
	});
});
