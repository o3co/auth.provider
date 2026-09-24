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
 * The device grant booted beside `oauthModule` through core's `createApp` —
 * the composition the package README's Quick start describes.
 *
 * Every other test in this package calls a contribution function directly or
 * boots the module alone, and each of those passed while the composition an
 * operator actually writes could not boot: what this package contributes is
 * only checked for real once core's discovery builder, oauth's token endpoint
 * and oauth's router under the same `/oauth` prefix have all seen it. So
 * nothing here is stubbed except the repositories a deployment supplies.
 */

import http from "node:http";
import type {
	AppConfig,
	ClientRepository,
	CodeRepository,
	UserRepository,
} from "@o3co/auth-provider-core";
import {
	createApp,
	createSymmetricKeyStore,
	defineModule,
	jwksModule,
	type Module,
	memoryAccessTokenDenylistModule,
	memoryDeviceCodeStoreModule,
	memoryFederationTokenStoreModule,
	memoryRateLimiterModule,
	memorySessionStoresModule,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { oauthModule } from "@o3co/auth-provider-oauth";
import { sessionModule, sessionStoreModuleFor } from "@o3co/auth-provider-session";
import express, { type RequestHandler } from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { deviceGrantModule } from "#/module.mjs";
import { DEVICE_CODE_GRANT_TYPE } from "#/types.mjs";

/** The fixture's issuer; discovery prefixes every endpoint with it. */
const ISSUER = "https://auth.test";
const CLIENT_ID = "tv-app";

const deviceClient = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "none" as const,
	allowedScopes: ["openid"],
	defaultScopes: ["openid"],
	allowedGrantTypes: [DEVICE_CODE_GRANT_TYPE],
};

const clientRepository: ClientRepository = {
	findById: async (id) => (id === CLIENT_ID ? (deviceClient as never) : null),
	authenticate: async () => null,
};

/** `oauthModule` requires one; nothing here runs the authorization-code flow. */
const codeRepository: CodeRepository = {
	createCode: async () => {
		throw new Error("the authorization-code flow is not exercised here");
	},
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

const USERNAME = "alice";
const PASSWORD = "correct horse battery staple";

const userRepository: UserRepository = {
	authenticate: async (username, password) =>
		username === USERNAME && password === PASSWORD ? ({ id: "user-1" } as never) : null,
	authenticateByToken: async () => null,
};

/** What a deployment supplies itself: the Quick start's "…the modules that provide what these require". */
const deploymentProviders = defineModule({
	name: "test:deployment-providers",
	provides: {
		clientRepository: () => clientRepository,
		codeRepository: () => codeRepository,
		keyStore: () => createSymmetricKeyStore("device-composition-secret.at-least-32-bytes"),
		userRepository: () => userRepository,
	},
});

const makeConfig = (deviceAuthorization: Record<string, unknown>): AppConfig => {
	const base = makeValidAppConfig();
	return {
		...base,
		// supertest speaks plain HTTP, and express-session sets no `Secure`
		// cookie on it — which also rules out the fixture's `__Host-` name.
		session: { ...base.session, name: "auth.session", secure: false },
		oauth: { ...base.oauth, deviceAuthorization },
	};
};

const ENABLED = {
	enabled: true,
	"verification-uri": `${ISSUER}/device`,
};

/**
 * The Quick start's module list: `ordered` is its first three, whose order a
 * case chooses; then the rest as written; then its "…the modules that
 * provide what these require" — the session and federation-token stores,
 * the access-token denylist the fixture's `oauth.revocation.accessToken`
 * declares, and the repositories and key store.
 */
const bootWith = async (config: AppConfig, ordered: readonly Module[]) => {
	const handle = await createApp({
		modules: [
			...ordered,
			jwksModule,
			sessionModule,
			memoryDeviceCodeStoreModule,
			memoryRateLimiterModule,
			memorySessionStoresModule,
			memoryFederationTokenStoreModule,
			memoryAccessTokenDenylistModule,
			deploymentProviders,
		],
		bootstrapComponents: { config, pathResolver: (s: string) => s },
	});
	const app = express();
	app.use(handle.router);
	return { handle, app };
};

type Agent = ReturnType<typeof request.agent>;

/** The session's double-submit token, fresh: `GET /session/csrf` sets the cookie and returns the value. */
const csrfToken = async (agent: Agent): Promise<{ header: string; token: string }> => {
	const res = await agent.get("/session/csrf");
	expect(res.status).toBe(200);
	return { header: res.body.header_name as string, token: res.body.csrf_token as string };
};

/** Sign in through `POST /session/login`, as the verification page's user would have. */
const signIn = async (agent: Agent): Promise<void> => {
	const { header, token } = await csrfToken(agent);
	const res = await agent
		.post("/session/login")
		.set(header, token)
		.send({ username: USERNAME, password: PASSWORD });
	expect(res.status).toBe(200);
};

/** A JSON body of exactly `bytes` bytes: `fields`, padded. */
const sized = (bytes: number, fields: Record<string, unknown>): string => {
	const body = { ...fields, padding: "" };
	body.padding = "x".repeat(bytes - Buffer.byteLength(JSON.stringify(body)));
	const json = JSON.stringify(body);
	expect(Buffer.byteLength(json)).toBe(bytes);
	return json;
};

/**
 * POST `body` with `Transfer-Encoding: chunked` and no `Content-Length` —
 * the one shape a size check ahead of the parsers cannot see. supertest
 * always declares a length, so this goes through `node:http`.
 */
const postChunked = (
	app: express.Express,
	path: string,
	body: string,
): Promise<{ status: number; contentType: string | undefined; text: string }> =>
	new Promise((resolve, reject) => {
		const server = app.listen(0, "127.0.0.1", () => {
			const { port } = server.address() as { port: number };
			const req = http.request(
				{
					host: "127.0.0.1",
					port,
					path,
					method: "POST",
					headers: { "content-type": "application/json", "transfer-encoding": "chunked" },
				},
				(res) => {
					let text = "";
					res.setEncoding("utf8");
					res.on("data", (chunk: string) => {
						text += chunk;
					});
					res.on("end", () => {
						server.close();
						resolve({
							status: res.statusCode ?? 0,
							contentType: res.headers["content-type"],
							text,
						});
					});
				},
			);
			req.on("error", (error) => {
				server.close();
				reject(error);
			});
			const half = Math.floor(body.length / 2);
			req.write(body.slice(0, half));
			req.end(body.slice(half));
		});
	});

/** A device starts the flow; returns the code a person would type. */
const startDevice = async (app: express.Express): Promise<string> => {
	const res = await request(app)
		.post("/oauth/device_authorization")
		.type("form")
		.send({ client_id: CLIENT_ID });
	expect(res.status).toBe(200);
	return res.body.user_code as string;
};

/**
 * Both orders of the two modules that share `/oauth`. Each parses its own
 * body — `oauthModule`'s router only for its own routes — so every case
 * below has to come out the same in either list order; before that, the
 * OAuth router listed first parsed every body under the prefix.
 */
const orders = [
	[
		"oauthModule listed first",
		(config: AppConfig) => [oauthModule({ config }), deviceGrantModule({ config })],
	],
	[
		"deviceGrantModule listed first",
		(config: AppConfig) => [deviceGrantModule({ config }), oauthModule({ config })],
	],
] as const;

describe("deviceGrantModule beside oauthModule — discovery (RFC 8628 §4)", () => {
	it.each(orders)(
		"boots enabled and advertises device_authorization_endpoint under the issuer (%s)",
		async (_label, ordered) => {
			// `oauthModule` always activates discovery, and core's builder refuses
			// an issuer-relative endpoint handed over as a literal `metadata`
			// field. So the one composition that needs this field — an enabled
			// grant beside the token endpoint it is polled at — is the one that
			// has to boot for the field to exist at all.
			const config = makeConfig(ENABLED);
			const { handle, app } = await bootWith(config, [
				sessionStoreModuleFor(config),
				...ordered(config),
			]);
			try {
				const res = await request(app).get("/.well-known/openid-configuration");

				expect(res.status).toBe(200);
				expect(res.body.device_authorization_endpoint).toBe(`${ISSUER}/oauth/device_authorization`);
				// The grant reaches `grant_types_supported` the way every grant
				// does: from the resolver `/oauth/token` dispatches against.
				expect(res.body.grant_types_supported).toContain(DEVICE_CODE_GRANT_TYPE);
			} finally {
				await handle.dispose();
			}
		},
	);
});

describe("deviceGrantModule beside oauthModule — installed but disabled", () => {
	it.each(orders)(
		"does not advertise the grant, and /oauth/token refuses it as unsupported (%s)",
		async (_label, ordered) => {
			// `grant_types_supported` is read off the resolver `/oauth/token`
			// dispatches against (#283), so a grant that is contributed is a grant
			// that is advertised — including a handler whose only job is to
			// refuse. The document must say what the endpoint does.
			const config = makeConfig({ enabled: false });
			const { handle, app } = await bootWith(config, [
				sessionStoreModuleFor(config),
				...ordered(config),
			]);
			try {
				const discovery = await request(app).get("/.well-known/openid-configuration");
				expect(discovery.status).toBe(200);
				expect(discovery.body.grant_types_supported).not.toContain(DEVICE_CODE_GRANT_TYPE);
				expect(discovery.body.device_authorization_endpoint).toBeUndefined();

				const token = await request(app)
					.post("/oauth/token")
					.type("form")
					.send({ grant_type: DEVICE_CODE_GRANT_TYPE, client_id: CLIENT_ID, device_code: "x" });
				expect(token.status).toBe(400);
				expect(token.body.error).toBe("unsupported_grant_type");
			} finally {
				await handle.dispose();
			}
		},
	);
});

describe("deviceGrantModule beside oauthModule — POST /oauth/device/verification is JSON-only", () => {
	// A form body is a CORS "simple" request: a browser sends it cross-site,
	// with the victim's session cookie and no preflight. When `oauthModule`'s
	// router parsed every body under `/oauth`, a rule that rested on this
	// package mounting no form parser held only when this package was listed
	// first. The CSRF token is valid here on purpose: the media type is the
	// first defence, and it must not depend on the second.
	it.each(orders)(
		"refuses a form-encoded approval carrying a valid CSRF token (%s)",
		async (_label, ordered) => {
			const config = makeConfig(ENABLED);
			const { handle, app } = await bootWith(config, [
				sessionStoreModuleFor(config),
				...ordered(config),
			]);
			try {
				const userCode = await startDevice(app);
				const agent = request.agent(app);
				await signIn(agent);
				const { header, token } = await csrfToken(agent);

				const form = await agent
					.post("/oauth/device/verification")
					.set(header, token)
					.type("form")
					.send(`action=approve&user_code=${userCode}`);

				expect(form.status).toBe(415);
				expect(form.body.error).toBe("invalid_request");

				// The same approval as JSON goes through — so what refused the
				// form was its media type, not the session or the token — and it
				// is an approval, not `409 already_decided`: the form decided
				// nothing.
				const json = await agent
					.post("/oauth/device/verification")
					.set(header, token)
					.send({ action: "approve", user_code: userCode });
				expect(json.status).toBe(200);
				expect(json.body.status).toBe("approved");
			} finally {
				await handle.dispose();
			}
		},
	);

	it.each(orders)(
		"reads no CSRF token from a form body — the guard refuses it before the media type is asked (%s)",
		async (_label, ordered) => {
			// The session's token may travel in a body field, which the guard
			// can only see in a body something has parsed. The route parses
			// JSON only, so a form carrying its token in the body has none —
			// the same answer whether or not `oauthModule`'s router could have
			// parsed it first.
			const config = makeConfig(ENABLED);
			const { handle, app } = await bootWith(config, [
				sessionStoreModuleFor(config),
				...ordered(config),
			]);
			try {
				const userCode = await startDevice(app);
				const agent = request.agent(app);
				await signIn(agent);
				const issued = await agent.get("/session/csrf");
				const field = issued.body.body_field as string;
				const token = issued.body.csrf_token as string;

				const form = await agent
					.post("/oauth/device/verification")
					.type("form")
					.send(`action=approve&user_code=${userCode}&${field}=${token}`);

				expect(form.status).toBe(403);
				expect(form.body.error).toBe("access_denied");
			} finally {
				await handle.dispose();
			}
		},
	);
});

describe("deviceGrantModule beside oauthModule — the 16 KiB body limit", () => {
	// Both routes parse with a 16 KiB limit, and `body-parser` does not parse a
	// body twice — so the bound holds only if no other parser (such as
	// `oauthModule`'s 100 KiB ones) reads the body first. Declared or chunked,
	// just over the bound or over `oauthModule`'s own limit, the answer is one
	// JSON 413 in either order.
	const TOO_LARGE = { error: "invalid_request", error_description: "body_too_large" };

	// 40 000 bytes is over this package's bound and under `oauthModule`'s;
	// 102 401 is one byte over `oauthModule`'s own 100 KiB, where its parser
	// refuses the body itself if it reads it first.
	const oversized = orders.flatMap(([label, ordered]) =>
		[40_000, 102_401].map((bytes) => [bytes, label, ordered] as const),
	);

	it.each(oversized)(
		"refuses a declared %i-byte JSON body at both routes with 413 body_too_large (%s)",
		async (bytes, _label, ordered) => {
			const config = makeConfig(ENABLED);
			const { handle, app } = await bootWith(config, [
				sessionStoreModuleFor(config),
				...ordered(config),
			]);
			try {
				const userCode = await startDevice(app);
				const agent = request.agent(app);
				await signIn(agent);
				const { header, token } = await csrfToken(agent);

				// Signed in and carrying a valid token, so nothing but the size
				// stands between this lookup and the handler.
				const verification = await agent
					.post("/oauth/device/verification")
					.set(header, token)
					.type("json")
					.send(sized(bytes, { action: "lookup", user_code: userCode }));
				expect(verification.status).toBe(413);
				expect(verification.body).toEqual(TOO_LARGE);

				const authorization = await request(app)
					.post("/oauth/device_authorization")
					.type("json")
					.send(sized(bytes, { client_id: CLIENT_ID }));
				expect(authorization.status).toBe(413);
				expect(authorization.body).toEqual(TOO_LARGE);
			} finally {
				await handle.dispose();
			}
		},
	);

	it.each(orders)(
		"refuses a chunked body over 16 KiB at both routes with the same 413 body_too_large (%s)",
		async (_label, ordered) => {
			// No `Content-Length`, so only a parser can find the size — and
			// its refusal has to read like the declared-length one, not like
			// whatever error handler the host app happens to run. Nothing is
			// signed in: the size is refused before anything else is asked.
			const config = makeConfig(ENABLED);
			const { handle, app } = await bootWith(config, [
				sessionStoreModuleFor(config),
				...ordered(config),
			]);
			try {
				const body = sized(40_000, { client_id: CLIENT_ID, action: "lookup" });
				for (const path of ["/oauth/device_authorization", "/oauth/device/verification"]) {
					const res = await postChunked(app, path, body);
					expect(res.status, path).toBe(413);
					expect(res.contentType, path).toMatch(/^application\/json/);
					expect(JSON.parse(res.text), path).toEqual(TOO_LARGE);
				}
			} finally {
				await handle.dispose();
			}
		},
	);

	it.each(orders)(
		"refuses a malformed JSON body at both routes with 400 malformed_body (%s)",
		async (_label, ordered) => {
			// RFC 8628 §3.2 → RFC 6749 §5.2: the error is JSON, like every
			// other answer these routes give — not the host's error page. The
			// parser refuses it before anything else is asked, so nothing is
			// signed in.
			const config = makeConfig(ENABLED);
			const { handle, app } = await bootWith(config, [
				sessionStoreModuleFor(config),
				...ordered(config),
			]);
			try {
				for (const path of ["/oauth/device_authorization", "/oauth/device/verification"]) {
					const res = await request(app).post(path).type("json").send("{not json");
					expect(res.status, path).toBe(400);
					expect(res.headers["content-type"], path).toMatch(/^application\/json/);
					expect(res.body, path).toEqual({
						error: "invalid_request",
						error_description: "malformed_body",
					});
				}
			} finally {
				await handle.dispose();
			}
		},
	);

	it.each(orders)(
		"accepts a body of exactly 16 KiB at both routes, as the parsers it stands in for do (%s)",
		async (_label, ordered) => {
			// `express.json({ limit: "16kb" })` accepts exactly 16384 bytes. A
			// restated bound that disagreed with the parser would accept or
			// refuse the same request depending on how its size was known.
			const config = makeConfig(ENABLED);
			const { handle, app } = await bootWith(config, [
				sessionStoreModuleFor(config),
				...ordered(config),
			]);
			try {
				const authorization = await request(app)
					.post("/oauth/device_authorization")
					.type("json")
					.send(sized(16_384, { client_id: CLIENT_ID }));
				expect(authorization.status).toBe(200);
				expect(typeof authorization.body.device_code).toBe("string");

				const userCode = authorization.body.user_code as string;
				const agent = request.agent(app);
				await signIn(agent);
				const { header, token } = await csrfToken(agent);
				const verification = await agent
					.post("/oauth/device/verification")
					.set(header, token)
					.type("json")
					.send(sized(16_384, { action: "lookup", user_code: userCode }));
				expect(verification.status).toBe(200);
				expect(verification.body.client_id).toBe(CLIENT_ID);
			} finally {
				await handle.dispose();
			}
		},
	);
});

describe("a route of another module under /oauth, listed after oauthModule", () => {
	// What enabling this grant must not change. The route has no parser of
	// its own and reads the request stream itself: whatever oauthModule's
	// router or this package's routes do, the body has to reach it unread.
	const readsItsOwnBody: RequestHandler = (req, res) => {
		const parsedBefore = (req as { body?: unknown }).body ?? null;
		if (req.readableEnded) {
			res.json({ raw: null, parsedBefore });
			return;
		}
		let raw = "";
		req.setEncoding("utf8");
		req.on("data", (chunk: string) => {
			raw += chunk;
		});
		req.on("end", () => {
			res.json({ raw, parsedBefore });
		});
	};

	const elsewhereModule = defineModule({
		name: "test:elsewhere-under-oauth",
		contributes: {
			routes: [
				() => {
					const router = express.Router();
					router.post("/", readsItsOwnBody);
					return { id: "elsewhere", mountPath: "/oauth/elsewhere", handler: router };
				},
			],
		},
	});

	it.each([
		["the grant enabled", ENABLED],
		["the grant disabled", { enabled: false }],
	] as const)("receives its body unread, with %s", async (_label, deviceAuthorization) => {
		const config = makeConfig(deviceAuthorization);
		const { handle, app } = await bootWith(config, [
			sessionStoreModuleFor(config),
			oauthModule({ config }),
			elsewhereModule,
			deviceGrantModule({ config }),
		]);
		try {
			const res = await request(app).post("/oauth/elsewhere").type("form").send("a=1");
			expect(res.status).toBe(200);
			expect(res.body).toEqual({ raw: "a=1", parsedBefore: null });
		} finally {
			await handle.dispose();
		}
	});
});
