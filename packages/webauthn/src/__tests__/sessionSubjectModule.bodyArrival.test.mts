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
 * `webauthnSessionSubjectModule` admits the cookie session once the request
 * body has arrived, not when its headers have: a session that closes while
 * the body of a registration is still arriving registers nothing.
 *
 * The module's route in front of `webauthnModule`'s own verify route, mounted
 * in the order the planner mounts them, over `@simplewebauthn/server`'s real
 * verification of a software authenticator's `none` attestation. The body is
 * sent in two halves over a raw HTTP request, and the session is closed
 * between them.
 */

import { randomBytes } from "node:crypto";
import { once } from "node:events";
import http from "node:http";
import type { AddressInfo } from "node:net";
import {
	createChallengeCeremony,
	createInMemorySessionLifecycleStore,
	createMemoryChallengeStore,
	createMemoryReplaySeenSet,
	createMemoryWebAuthnCredentialStore,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import express, { type RequestHandler } from "express";
import { describe, expect, it, vi } from "vitest";
import { webauthnModule } from "#/module.mjs";
import type { WebAuthnSubject } from "#/request.mjs";
import {
	SESSION_SUBJECT_ADMISSION_ACTIONS,
	webauthnSessionSubjectModule,
} from "#/sessionSubject.mjs";
import { createTestWebAuthnConfig } from "#/testing/index.mjs";
import { softwareAuthenticator } from "./softwareAuthenticator.fixture.mjs";

const SUBJECT = "u-1";
const SID = "s-1";
const VERIFY = "/oauth/webauthn/registration/verify";

interface Contribution {
	readonly id: string;
	readonly mountPath: string;
	readonly handler: RequestHandler;
}

type RouteFactory = (deps: unknown) => Contribution;

const routeFactories = (module: { contributes?: { routes?: unknown } }) =>
	(module.contributes?.routes ?? []) as readonly RouteFactory[];

/** A deferred: settled from outside. */
function deferred() {
	let resolve: () => void = () => {};
	const promise = new Promise<void>((r) => {
		resolve = r;
	});
	return { promise, resolve };
}

/**
 * A signed-in browser's session in front of the session-subject route and
 * both registration routes, each mounted as core mounts it — on its path, on
 * one router — a challenge issued for the subject (and for `preset`'s, so a
 * registration under that subject would verify too); the server listening.
 * `preset` is a subject an earlier middleware set.
 */
async function setup(
	options: {
		readonly preset?: WebAuthnSubject;
		/** A body parser the host installs in front of the provider's routes. */
		readonly upstream?: RequestHandler;
	} = {},
) {
	const now = Date.now();
	const record: UserSession = {
		sid: SID,
		sub: SUBJECT,
		authTime: new Date(now - 60_000),
		createdAt: new Date(now - 60_000),
		expiresAt: new Date(now + 3_600_000),
		claims: {},
		amr: undefined,
		authentication: undefined,
	};
	const userSessionStore = {
		kind: "test",
		create: vi.fn(),
		get: vi.fn(async () => record),
		delete: vi.fn(),
	} as unknown as UserSessionStore;
	const lifecycle = createInMemorySessionLifecycleStore();
	await lifecycle.open(SID, SUBJECT, new Date(now + 3_600_000));
	// Settled once admission has read the lifecycle record.
	const lifecycleRead = deferred();
	const sessionLifecycleStore = {
		...lifecycle,
		read: async (sid: string) => {
			const answer = await lifecycle.read(sid);
			lifecycleRead.resolve();
			return answer;
		},
	};

	const challengeStore = createMemoryChallengeStore();
	const credentialStore = createMemoryWebAuthnCredentialStore();
	const registerCredential = vi.spyOn(credentialStore, "registerCredential");
	const config = createTestWebAuthnConfig();
	const logger = { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() };

	const [sessionSubject] = routeFactories(
		webauthnSessionSubjectModule({ subjectFor: (session) => ({ userId: session.sub }) }),
	).map((factory) =>
		factory({
			sessionRequirementResolver: resolverForTests([], {
				actions: SESSION_SUBJECT_ADMISSION_ACTIONS,
			}),
			userSessionStore,
			sessionLifecycleStore,
			logger,
		}),
	);
	const registrationRoutes = routeFactories(webauthnModule)
		.map((factory) =>
			factory({
				section: config,
				challengeStore,
				challengeCeremony: createChallengeCeremony({
					challengeStore,
					replaySeenSet: createMemoryReplaySeenSet(),
				}),
				webauthnCredentialStore: credentialStore,
				logger,
			}),
		)
		.filter((contribution) => contribution.id.startsWith("webauthn-registration-"));
	if (sessionSubject === undefined || registrationRoutes.length !== 2) {
		throw new Error("routes not built");
	}

	// Settled when the request's headers have reached the server.
	const headersArrived = deferred();
	const app = express();
	app.use((req, _res, next) => {
		(req as unknown as { session: unknown }).session = {
			sid: SID,
			isAuthenticated: true,
			user: { id: SUBJECT },
		};
		if (options.preset !== undefined) req.webauthnSubject = options.preset;
		headersArrived.resolve();
		next();
	});
	if (options.upstream !== undefined) app.use(options.upstream);
	const core = express.Router();
	for (const contribution of [sessionSubject, ...registrationRoutes]) {
		core.use(contribution.mountPath, contribution.handler);
	}
	app.use(core);

	const server = app.listen(0, "127.0.0.1");
	await once(server, "listening");
	const { port } = server.address() as AddressInfo;

	const challenge = randomBytes(32).toString("base64url");
	await challengeStore.issue(`webauthn:registration:${SUBJECT}`, challenge, now + 120_000);
	if (options.preset !== undefined) {
		await challengeStore.issue(
			`webauthn:registration:${options.preset.userId}`,
			challenge,
			now + 120_000,
		);
	}
	const body = JSON.stringify({
		response: softwareAuthenticator({
			rpId: config.rpId,
			origin: config.origin[0] as string,
		}).register(challenge),
	});

	/**
	 * Posts the registration in two halves, running `between` once the first
	 * half is sent and the headers have reached the server, to `path`; answers
	 * the response's status and body. With `emptyChunked`, the request is
	 * chunked with no content type and no data: its headers first, and only
	 * its terminating chunk after `between`.
	 */
	const post = async (
		between: () => Promise<void>,
		path: string = VERIFY,
		emptyChunked = false,
	) => {
		const req = http.request({
			host: "127.0.0.1",
			port,
			method: "POST",
			path,
			headers: emptyChunked
				? { "transfer-encoding": "chunked" }
				: { "content-type": "application/json", "content-length": Buffer.byteLength(body) },
		});
		const response = once(req, "response") as Promise<[http.IncomingMessage]>;
		const half = emptyChunked ? 0 : Math.floor(body.length / 2);
		if (emptyChunked) req.flushHeaders();
		else req.write(body.slice(0, half));
		await headersArrived.promise;
		// Whatever admission does on the headers alone has run by now.
		await Promise.race([lifecycleRead.promise, new Promise((r) => setTimeout(r, 100))]);
		await between();
		req.end(emptyChunked ? undefined : body.slice(half));
		const [res] = await response;
		let text = "";
		res.setEncoding("utf8");
		for await (const chunk of res) text += chunk;
		return { status: res.statusCode, body: JSON.parse(text) as unknown };
	};

	const closeSession = () =>
		lifecycle.beginClose(SID, {
			cause: "rp_logout",
			steps: ["tokens"],
			perParticipant: [],
			retainMs: 0,
		});

	return {
		post,
		lifecycle,
		closeSession,
		credentialStore,
		registerCredential,
		close: () => server.close(),
	};
}

describe("webauthnSessionSubjectModule — admission once the request body has arrived", () => {
	it("registers the passkey of a session that stays active while the body arrives", async () => {
		const { post, registerCredential, close } = await setup();
		try {
			const res = await post(async () => {});

			expect(res.status, JSON.stringify(res.body)).toBe(200);
			expect(registerCredential).toHaveBeenCalledTimes(1);
		} finally {
			close();
		}
	});

	it("answers 401 and registers nothing for a session that closes while the body arrives", async () => {
		const { post, lifecycle, registerCredential, close } = await setup();
		try {
			const res = await post(async () => {
				await lifecycle.beginClose(SID, {
					cause: "rp_logout",
					steps: ["tokens"],
					perParticipant: [],
					retainMs: 0,
				});
			});

			expect(res.status).toBe(401);
			expect(res.body).toEqual({ error: "unauthorized" });
			expect(registerCredential).not.toHaveBeenCalled();
		} finally {
			close();
		}
	});
});

describe("webauthnSessionSubjectModule — on every path the registration routes answer", () => {
	const REGISTRATION = "/oauth/webauthn/registration";
	const PATHS = ["/verify", "/verify/", "/verify//", "/VERIFY", "/Verify/"] as const;
	const PRESET: WebAuthnSubject = { userId: "earlier" };

	it.each(PATHS)(
		"answers 401 and registers nothing at %s for a closed session, over a subject an earlier middleware set",
		async (path) => {
			const { post, closeSession, registerCredential, close } = await setup({ preset: PRESET });
			try {
				await closeSession();
				const res = await post(async () => {}, `${REGISTRATION}${path}`);

				expect(res.status).toBe(401);
				expect(registerCredential).not.toHaveBeenCalled();
			} finally {
				close();
			}
		},
	);

	it.each(PATHS)(
		"registers at %s under the admitted session's subject, not one an earlier middleware set",
		async (path) => {
			const { post, credentialStore, close } = await setup({ preset: PRESET });
			try {
				const res = await post(async () => {}, `${REGISTRATION}${path}`);

				expect(res.status, JSON.stringify(res.body)).toBe(200);
				expect(await credentialStore.listByUserId(SUBJECT)).toHaveLength(1);
				expect(await credentialStore.listByUserId(PRESET.userId)).toEqual([]);
			} finally {
				close();
			}
		},
	);

	it.each(["/options", "/options/", "/options//", "/OPTIONS"])(
		"answers 401 at %s for a closed session, over a subject an earlier middleware set",
		async (path) => {
			const { post, closeSession, close } = await setup({ preset: PRESET });
			try {
				await closeSession();
				const res = await post(async () => {}, `${REGISTRATION}${path}`);

				expect(res.status).toBe(401);
			} finally {
				close();
			}
		},
	);
});

describe("webauthnSessionSubjectModule — admission once an empty chunked body has ended", () => {
	const OPTIONS = "/oauth/webauthn/registration/options";

	it("answers the options of a session that stays active until the body ends", async () => {
		const { post, close } = await setup();
		try {
			const res = await post(async () => {}, OPTIONS, true);

			expect(res.status, JSON.stringify(res.body)).toBe(200);
		} finally {
			close();
		}
	});

	it("answers 401 for a session that closes before the body ends", async () => {
		const { post, closeSession, close } = await setup();
		try {
			const res = await post(
				async () => {
					await closeSession();
				},
				OPTIONS,
				true,
			);

			expect(res.status).toBe(401);
		} finally {
			close();
		}
	});
});

describe("webauthnSessionSubjectModule — a body the host's own parser read first", () => {
	it("registers a JSON body an upstream JSON parser read, as usual", async () => {
		const { post, registerCredential, close } = await setup({ upstream: express.json() });
		try {
			const res = await post(async () => {});

			expect(res.status, JSON.stringify(res.body)).toBe(200);
			expect(registerCredential).toHaveBeenCalledTimes(1);
		} finally {
			close();
		}
	});
});
