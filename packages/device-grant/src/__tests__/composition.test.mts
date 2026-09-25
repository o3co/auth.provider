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
	AuditEvent,
	AuditSink,
	ClientRepository,
	CodeRepository,
	ComponentMap,
	DeviceCodeStore,
	Logger,
	SubjectRevocation,
	SubjectRevocationService,
	SubjectSessionIndex,
	UserRepository,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	createApp,
	createInMemoryUserSessionStore,
	createMemoryDeviceCodeStore,
	createSymmetricKeyStore,
	defaultRefreshTokenFamilyRevocationModule,
	defineModule,
	jwksModule,
	type Module,
	memoryAccessTokenDenylistModule,
	memoryDeviceCodeStoreModule,
	memoryFederationTokenStoreModule,
	memoryRateLimiterModule,
	memoryRefreshTokenFamilyStoreModule,
	memorySessionStoresModule,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { oauthModule, subjectRevocationServiceModule } from "@o3co/auth-provider-oauth";
import { sessionModule, sessionStoreModuleFor } from "@o3co/auth-provider-session";
import express, { type RequestHandler } from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
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
/** A second user, whose Store has published a verified email (#297). */
const VERIFIED_USERNAME = "bob";

const userRepository: UserRepository = {
	authenticate: async (username, password) => {
		if (password !== PASSWORD) return null;
		if (username === USERNAME) return { id: "user-1" } as never;
		if (username === VERIFIED_USERNAME) {
			return { id: "user-2", email: "bob@example.test", emailVerified: true } as never;
		}
		return null;
	},
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
const bootWith = async (
	config: AppConfig,
	ordered: readonly Module[],
	// What a case swaps in: the device-code store, the logger and audit sink it
	// reads, and a component standing in for one a module provides.
	swap: {
		readonly deviceCodeStore?: Module;
		readonly logger?: Logger;
		readonly auditSink?: AuditSink;
		readonly overrideComponents?: Partial<ComponentMap>;
	} = {},
) => {
	const handle = await createApp({
		modules: [
			...ordered,
			jwksModule,
			sessionModule,
			swap.deviceCodeStore ?? memoryDeviceCodeStoreModule,
			memoryRateLimiterModule,
			memorySessionStoresModule,
			memoryFederationTokenStoreModule,
			memoryAccessTokenDenylistModule,
			deploymentProviders,
		],
		bootstrapComponents: {
			config,
			pathResolver: (s: string) => s,
			...(swap.logger ? { logger: swap.logger } : {}),
			...(swap.auditSink ? { auditSink: swap.auditSink } : {}),
		},
		...(swap.overrideComponents ? { overrideComponents: swap.overrideComponents } : {}),
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
const signIn = async (agent: Agent, username: string = USERNAME): Promise<void> => {
	const { header, token } = await csrfToken(agent);
	const res = await agent
		.post("/session/login")
		.set(header, token)
		.send({ username, password: PASSWORD });
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

/** A user code as the store keys it: upper case, separator dropped. */
const normalised = (userCode: string): string => userCode.replace(/[^A-Za-z]/g, "").toUpperCase();

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
					expect(res.headers["cache-control"], path).toBe("no-store");
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

describe("deviceGrantModule beside oauthModule — error text (RFC 6749 Appendix A.8)", () => {
	// `error_description` is 1*NQSCHAR: printable ASCII without `"` and `\`.
	it("sends a refused scope the client asked for within that set", async () => {
		// The refused values are the client's own. A scope is read strictly by
		// RFC 6749 §3.3's grammar, so a value holding a character outside the
		// set — a quote, a non-ASCII letter — is malformed before any entry is
		// refused, and is answered with a description of the server's own; a
		// well-formed refused entry is a scope-token, which the set admits, and
		// is echoed as sent. The sanitiser still stands behind the echo.
		const config = makeConfig(ENABLED);
		const [oauth, device] = orders[0][1](config);
		const { handle, app } = await bootWith(config, [sessionStoreModuleFor(config), oauth, device]);
		const NQSCHAR = /^[\x20-\x21\x23-\x5B\x5D-\x7E]+$/;
		try {
			const malformed = await request(app)
				.post("/oauth/device_authorization")
				.type("form")
				.send({ client_id: CLIENT_ID, scope: 'openid ad"min caf\u00e9' });
			expect(malformed.status).toBe(400);
			expect(malformed.body).toEqual({
				error: "invalid_scope",
				error_description: "scope is not a space-delimited list of scope-tokens",
			});
			expect(malformed.body.error_description).toMatch(NQSCHAR);

			const refused = await request(app)
				.post("/oauth/device_authorization")
				.type("form")
				.send({ client_id: CLIENT_ID, scope: "openid admin cafe~1" });
			expect(refused.status).toBe(400);
			expect(refused.body).toEqual({
				error: "invalid_scope",
				error_description: "scope not permitted for this client: admin cafe~1",
			});
			expect(refused.body.error_description).toMatch(NQSCHAR);
		} finally {
			await handle.dispose();
		}
	});

	it("answers an unknown code in plain ASCII", async () => {
		const config = makeConfig(ENABLED);
		const [oauth, device] = orders[0][1](config);
		const { handle, app } = await bootWith(config, [sessionStoreModuleFor(config), oauth, device]);
		try {
			const agent = request.agent(app);
			await signIn(agent);
			const { header, token } = await csrfToken(agent);
			const res = await agent
				.post("/oauth/device/verification")
				.set(header, token)
				.send({ action: "lookup", user_code: "BCDF-GHJK" });
			expect(res.status).toBe(404);
			expect(res.body).toEqual({
				error: "invalid_user_code",
				error_description: "that code is not valid; check it and try again",
			});
		} finally {
			await handle.dispose();
		}
	});
});

/**
 * A route of some other module, with no parser of its own: it reads the
 * request stream itself and reports what it found — and whether anything
 * had parsed the body before it ran.
 */
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

describe("a route of another module under /oauth, listed after oauthModule", () => {
	// What enabling this grant must not change. The route has no parser of
	// its own and reads the request stream itself: whatever oauthModule's
	// router or this package's routes do, the body has to reach it unread.

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

	// Enabled and disabled, each in both list orders of the two modules the
	// route sits between, each with a form and a JSON body.
	const cases = [
		["enabled", ENABLED],
		["disabled", { enabled: false }],
	].flatMap(([state, deviceAuthorization]) =>
		orders.map(
			([order, ordered]) => [`the grant ${state}, ${order}`, deviceAuthorization, ordered] as const,
		),
	);

	it.each(cases)(
		"receives its body unread, with %s",
		async (_label, deviceAuthorization, ordered) => {
			const config = makeConfig(deviceAuthorization as Record<string, unknown>);
			const [first, second] = ordered(config);
			const { handle, app } = await bootWith(config, [
				sessionStoreModuleFor(config),
				first,
				elsewhereModule,
				second,
			]);
			try {
				const form = await request(app).post("/oauth/elsewhere").type("form").send("a=1");
				expect(form.status).toBe(200);
				expect(form.body).toEqual({ raw: "a=1", parsedBefore: null });

				const json = await request(app).post("/oauth/elsewhere").type("json").send('{"a":1}');
				expect(json.status).toBe(200);
				expect(json.body).toEqual({ raw: '{"a":1}', parsedBefore: null });
			} finally {
				await handle.dispose();
			}
		},
	);
});

describe("a route of another module beneath the device routes' paths", () => {
	// The device routes' middleware — no-store, the throttle, the size check,
	// the parsers, client authentication — is theirs alone. A module listed
	// after the grant that serves a path beneath one of them gets none of it.
	const beneathModule = defineModule({
		name: "test:beneath-the-device-routes",
		contributes: {
			routes: [
				() => {
					const router = express.Router();
					router.post("/device_authorization/custom", readsItsOwnBody);
					router.post("/device/verification/custom", readsItsOwnBody);
					return { id: "beneath", mountPath: "/oauth", handler: router };
				},
			],
		},
	});

	const cases = [
		["enabled", ENABLED],
		["disabled", { enabled: false }],
	].flatMap(([state, deviceAuthorization]) =>
		["/oauth/device_authorization/custom", "/oauth/device/verification/custom"].map(
			(path) => [path, `the grant ${state}`, deviceAuthorization] as const,
		),
	);

	it.each(cases)(
		"%s receives its body unread and none of the device routes' answers, with %s",
		async (path, _state, deviceAuthorization) => {
			const config = makeConfig(deviceAuthorization as Record<string, unknown>);
			const [first, second] = orders[0][1](config);
			const { handle, app } = await bootWith(config, [
				sessionStoreModuleFor(config),
				first,
				second,
				beneathModule,
			]);
			try {
				const form = await request(app).post(path).type("form").send("a=1");
				expect(form.status).toBe(200);
				expect(form.body).toEqual({ raw: "a=1", parsedBefore: null });
				expect(form.headers["cache-control"]).toBeUndefined();

				const json = await request(app).post(path).type("json").send('{"a":1}');
				expect(json.status).toBe(200);
				expect(json.body).toEqual({ raw: '{"a":1}', parsedBefore: null });
			} finally {
				await handle.dispose();
			}
		},
	);
});

describe("deviceGrantModule beside oauthModule — a device-code store outage is 503 temporarily_unavailable", () => {
	// The store can be down after the device asked for its codes: the human's
	// lookup and decision and the device's poll then each reach a store that
	// answers with a transport error. That is an outage, which the product
	// answers 503 temporarily_unavailable and logs at error — never a 500, and
	// never an answer about the code, which nobody could read.
	const UNAVAILABLE = {
		error: "temporarily_unavailable",
		error_description: "the device authorization store is unavailable; retry later",
	};

	/** A reply a Redis client gives a command it could not send. */
	const transportError = (): Error =>
		Object.assign(new Error("Connection is closed."), { name: "Error", code: "ECONNRESET" });

	/**
	 * The memory store, with a switch: while `down`, every operation but
	 * `create` rejects as a store whose connection has gone. `calls` records
	 * each operation asked while down, so a case can say it was asked once.
	 */
	const storeWithOutage = () => {
		const inner = createMemoryDeviceCodeStore();
		const state = { down: false, calls: [] as string[] };
		const guarded =
			<A extends unknown[], R>(name: string, op: (...args: A) => Promise<R>) =>
			(...args: A): Promise<R> => {
				if (!state.down) return op(...args);
				state.calls.push(name);
				return Promise.reject(transportError());
			};
		const store: DeviceCodeStore = {
			kind: "outage",
			create: (input) => inner.create(input),
			findPendingByUserCode: guarded("findPendingByUserCode", inner.findPendingByUserCode),
			approve: guarded("approve", inner.approve),
			deny: guarded("deny", inner.deny),
			poll: guarded("poll", inner.poll),
			remove: guarded("remove", inner.remove),
		};
		return {
			state,
			module: defineModule({
				name: "test:device-code-store-with-outage",
				provides: { deviceCodeStore: () => store },
			}),
		};
	};

	const recordingLogger = () => ({
		warn: vi.fn(),
		info: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	});

	it.each(orders)(
		"answers the verification page's lookup, approval and denial with 503, logs each at error, and audits a decision whose outcome is unknown (%s)",
		async (_label, ordered) => {
			const config = makeConfig(ENABLED);
			const outage = storeWithOutage();
			const logger = recordingLogger();
			const events: AuditEvent[] = [];
			const { handle, app } = await bootWith(
				config,
				[sessionStoreModuleFor(config), ...ordered(config)],
				{
					deviceCodeStore: outage.module,
					logger: logger as unknown as Logger,
					auditSink: {
						kind: "recording",
						record: async (event) => {
							events.push(event);
						},
					},
				},
			);
			try {
				const userCode = await startDevice(app);
				const agent = request.agent(app);
				await signIn(agent);
				const { header, token } = await csrfToken(agent);

				outage.state.down = true;
				for (const action of ["lookup", "approve", "deny"] as const) {
					const res = await agent
						.post("/oauth/device/verification")
						.set(header, token)
						.set("User-Agent", "verification-page/1.0")
						.send({ action, user_code: userCode });
					expect(res.status, action).toBe(503);
					expect(res.body, action).toEqual(UNAVAILABLE);
					expect(res.headers["cache-control"], action).toContain("no-store");
				}
				// Each request asked the store once, and nothing else was tried.
				expect(outage.state.calls).toEqual(["findPendingByUserCode", "approve", "deny"]);
				expect(logger.error).toHaveBeenCalledTimes(3);
				for (const [line, event] of logger.error.mock.calls) {
					expect(event).toBe("device_verification_store_unavailable");
					expect(line).toMatchObject({ err: { name: "Error", code: "ECONNRESET" } });
					expect((line as { err: unknown }).err).not.toBeInstanceOf(Error);
				}
				expect(logger.error).not.toHaveBeenCalledWith(
					expect.anything(),
					"device_route_unexpected_error",
				);

				// An approval or a denial whose reply was lost may already be
				// recorded — the store's script can run before the connection goes
				// — and the device's poll can then mint tokens that no
				// `device.approved` accounts for. So each is audited as an outcome
				// nobody knows, naming the action; a lookup decides nothing and is
				// not. It is attributed as the decision would have been — the
				// signed-in subject — and the client cannot be known: the record
				// could not be read.
				const unknown = events.filter((event) => event.type === "device.decision_outcome_unknown");
				expect(unknown.map((event) => event.details)).toEqual([
					{ action: "approve" },
					{ action: "deny" },
				]);
				for (const event of unknown) {
					expect(event.subject).toBe("user-1");
					expect(event.clientId).toBeUndefined();
					expect(event.timestamp).toBeInstanceOf(Date);
					expect(JSON.stringify(event)).not.toContain(normalised(userCode));
				}
				expect(events.some((event) => event.type === "device.approved")).toBe(false);

				// Every other answer is what it was: back up, the same code is
				// still pending, and the approval goes through.
				outage.state.down = false;
				const approved = await agent
					.post("/oauth/device/verification")
					.set(header, token)
					.set("User-Agent", "verification-page/1.0")
					.send({ action: "approve", user_code: userCode });
				expect(approved.status).toBe(200);
				expect(approved.body.status).toBe("approved");

				// The unknown outcomes carry the attribution the decision event
				// carries: the same subject, address and user agent.
				const decided = events.find((event) => event.type === "device.approved");
				expect(decided?.ip).toEqual(expect.any(String));
				expect(decided?.userAgent).toBe("verification-page/1.0");
				for (const event of unknown) {
					expect({ subject: event.subject, ip: event.ip, userAgent: event.userAgent }).toEqual({
						subject: decided?.subject,
						ip: decided?.ip,
						userAgent: decided?.userAgent,
					});
				}
			} finally {
				await handle.dispose();
			}
		},
	);

	it.each(orders)(
		"answers the device's poll at /oauth/token with 503 temporarily_unavailable, and logs it at error (%s)",
		async (_label, ordered) => {
			const config = makeConfig(ENABLED);
			const outage = storeWithOutage();
			const logger = recordingLogger();
			const { handle, app } = await bootWith(
				config,
				[sessionStoreModuleFor(config), ...ordered(config)],
				{
					deviceCodeStore: outage.module,
					logger: logger as unknown as Logger,
				},
			);
			try {
				const started = await request(app)
					.post("/oauth/device_authorization")
					.type("form")
					.send({ client_id: CLIENT_ID });
				expect(started.status).toBe(200);
				const poll = () =>
					request(app).post("/oauth/token").type("form").send({
						grant_type: DEVICE_CODE_GRANT_TYPE,
						client_id: CLIENT_ID,
						device_code: started.body.device_code,
					});

				outage.state.down = true;
				const res = await poll();
				// Written by oauth's token route, as every grant's error is.
				expect(res.status).toBe(503);
				expect(res.body).toEqual(UNAVAILABLE);
				expect(outage.state.calls).toEqual(["poll"]);
				expect(logger.error).toHaveBeenCalledWith(
					expect.objectContaining({
						clientId: CLIENT_ID,
						err: expect.objectContaining({ name: "Error", code: "ECONNRESET" }),
					}),
					"device_code_grant_store_unavailable",
				);

				// Back up, the device is told what it was always told: keep polling.
				outage.state.down = false;
				const pending = await poll();
				expect(pending.status).toBe(400);
				expect(pending.body.error).toBe("authorization_pending");
			} finally {
				await handle.dispose();
			}
		},
	);
});

describe("deviceGrantModule beside oauthModule — an approval needs the live session behind the cookie", () => {
	// The verification page runs inside the end-user session, and the cookie
	// says `isAuthenticated`. That is the browser's claim; the `UserSession`
	// record its `sid` names is the fact. A logout, a subject-wide revocation
	// or a record deleted out of band ends the record and leaves the cookie as
	// it was — and the device token an approval leads to carries no `sid` and
	// no `family_id`, so nothing revokes it afterwards. The approval is the one
	// place the session can be asked about, so it is asked there, as
	// `/authorize`, the session grant and `/oauth/consent` ask it.

	const [first] = orders;
	const modulesFor = (config: AppConfig): Module[] => [
		sessionStoreModuleFor(config),
		...first[1](config),
	];

	/** The one session `user-1` holds, found the way a credential change finds it. */
	const sidOf = async (components: Readonly<Partial<ComponentMap>>): Promise<string> => {
		const index = components.subjectSessionIndex as SubjectSessionIndex;
		const sids = await index.listSids("user-1");
		expect(sids).toHaveLength(1);
		return sids[0] as string;
	};

	/** The device's poll at `/oauth/token`. */
	const pollFor = (app: express.Express, deviceCode: string) =>
		request(app).post("/oauth/token").type("form").send({
			grant_type: DEVICE_CODE_GRANT_TYPE,
			client_id: CLIENT_ID,
			device_code: deviceCode,
		});

	/** A device starts the flow; both codes, for a case that polls too. */
	const startWithCodes = async (
		app: express.Express,
	): Promise<{ userCode: string; deviceCode: string }> => {
		const res = await request(app)
			.post("/oauth/device_authorization")
			.type("form")
			.send({ client_id: CLIENT_ID });
		expect(res.status).toBe(200);
		return { userCode: res.body.user_code as string, deviceCode: res.body.device_code as string };
	};

	const LOGIN_REQUIRED = expect.objectContaining({ error: "login_required" });

	it("approves from a live session, and the device's poll is then answered with a token", async () => {
		const config = makeConfig(ENABLED);
		const { handle, app } = await bootWith(config, modulesFor(config));
		try {
			const { userCode, deviceCode } = await startWithCodes(app);
			const agent = request.agent(app);
			await signIn(agent);
			const { header, token } = await csrfToken(agent);

			const approved = await agent
				.post("/oauth/device/verification")
				.set(header, token)
				.send({ action: "approve", user_code: userCode });
			expect(approved.status).toBe(200);
			expect(approved.body.status).toBe("approved");

			const polled = await pollFor(app, deviceCode);
			expect(polled.status).toBe(200);
			expect(typeof polled.body.access_token).toBe("string");
		} finally {
			await handle.dispose();
		}
	});

	it("refuses every action once the UserSession behind the cookie is deleted, and the device stays pending", async () => {
		const config = makeConfig(ENABLED);
		const { handle, app } = await bootWith(config, modulesFor(config));
		try {
			const { userCode, deviceCode } = await startWithCodes(app);
			const agent = request.agent(app);
			await signIn(agent);
			const { header, token } = await csrfToken(agent);

			// Out of band: the record goes, the browser's cookie stays.
			const store = handle.components.userSessionStore as UserSessionStore;
			await store.delete(await sidOf(handle.components));

			for (const action of ["lookup", "approve", "deny"] as const) {
				const res = await agent
					.post("/oauth/device/verification")
					.set(header, token)
					.send({ action, user_code: userCode });
				expect(res.status, action).toBe(401);
				expect(res.body, action).toEqual(LOGIN_REQUIRED);
				expect(res.headers["cache-control"], action).toContain("no-store");
			}

			// Nothing was decided: the device is told to keep polling.
			const polled = await pollFor(app, deviceCode);
			expect(polled.status).toBe(400);
			expect(polled.body.error).toBe("authorization_pending");
		} finally {
			await handle.dispose();
		}
	});

	it("refuses an approval after the subject's sessions were revoked with revokeAllForSubject", async () => {
		// The Store's call after a credential change. It ends every session the
		// subject holds and stamps a watermark over every token minted before
		// it — and a device token minted from an approval AFTER it would carry
		// a later `iat`, so the watermark cannot reach it. Only the approval can.
		const config = makeConfig(ENABLED);
		const { handle, app } = await bootWith(config, [
			...modulesFor(config),
			subjectRevocationServiceModule,
			memoryRefreshTokenFamilyStoreModule,
			defaultRefreshTokenFamilyRevocationModule,
		]);
		try {
			const { userCode, deviceCode } = await startWithCodes(app);
			const agent = request.agent(app);
			await signIn(agent);
			const { header, token } = await csrfToken(agent);

			const service = handle.components.subjectRevocationService as SubjectRevocationService;
			const report = await service.revokeAllForSubject({ subject: "user-1" });
			expect(report.complete).toBe(true);

			const res = await agent
				.post("/oauth/device/verification")
				.set(header, token)
				.send({ action: "approve", user_code: userCode });
			expect(res.status).toBe(401);
			expect(res.body).toEqual(LOGIN_REQUIRED);

			const polled = await pollFor(app, deviceCode);
			expect(polled.status).toBe(400);
			expect(polled.body.error).toBe("authorization_pending");
		} finally {
			await handle.dispose();
		}
	});

	it("refuses an approval from a session the subject's sessions boundary covers, though its record survived", async () => {
		// revokeAllForSubject stamps the boundary first and deletes the
		// sessions after it. A cascade that failed for this session — or a
		// session the subject index never learnt of — leaves the record while
		// the boundary is in force: the record says live, the boundary says
		// ended, and the boundary is the one a credential change relies on.
		const config = makeConfig(ENABLED);
		const { handle, app } = await bootWith(config, modulesFor(config));
		try {
			const { userCode, deviceCode } = await startWithCodes(app);
			const agent = request.agent(app);
			await signIn(agent);
			const { header, token } = await csrfToken(agent);

			const revocation = handle.components.subjectRevocation as SubjectRevocation;
			await revocation.revokeBefore("user-1", new Date(), new Date(Date.now() + 3_600_000));
			// The record is still there.
			const store = handle.components.userSessionStore as UserSessionStore;
			expect(await store.get(await sidOf(handle.components))).not.toBeNull();

			const res = await agent
				.post("/oauth/device/verification")
				.set(header, token)
				.send({ action: "approve", user_code: userCode });
			expect(res.status).toBe(401);
			expect(res.body).toEqual(LOGIN_REQUIRED);

			const polled = await pollFor(app, deviceCode);
			expect(polled.body.error).toBe("authorization_pending");
		} finally {
			await handle.dispose();
		}
	});

	it("refuses the device's poll when the subject's sessions were revoked between the approval and the poll", async () => {
		// The approval was given from a live session. revokeAllForSubject then
		// lands before the device polls — within the code's lifetime, ten
		// minutes by default — and the token the poll would mint postdates its
		// watermark, so nothing downstream would refuse it. A holder of a
		// stolen live session could approve codes ahead and redeem them after
		// the victim's credential change.
		const config = makeConfig(ENABLED);
		const { handle, app } = await bootWith(config, [
			...modulesFor(config),
			subjectRevocationServiceModule,
			memoryRefreshTokenFamilyStoreModule,
			defaultRefreshTokenFamilyRevocationModule,
		]);
		try {
			const { userCode, deviceCode } = await startWithCodes(app);
			const agent = request.agent(app);
			await signIn(agent);
			const { header, token } = await csrfToken(agent);
			const approved = await agent
				.post("/oauth/device/verification")
				.set(header, token)
				.send({ action: "approve", user_code: userCode });
			expect(approved.status).toBe(200);

			const service = handle.components.subjectRevocationService as SubjectRevocationService;
			expect((await service.revokeAllForSubject({ subject: "user-1" })).complete).toBe(true);

			const polled = await pollFor(app, deviceCode);
			expect(polled.status).toBe(400);
			expect(polled.body.error).toBe("invalid_grant");
			expect(polled.body.access_token).toBeUndefined();
		} finally {
			await handle.dispose();
		}
	});

	it("answers a session-store outage with 503 temporarily_unavailable, logged once at error, and decides nothing", async () => {
		// The store said nothing about whether the user is signed in, so the
		// answer is the outage, not `login_required` — and not an approval on
		// the cookie's word either.
		const inner = createInMemoryUserSessionStore();
		const outage = { down: false };
		const userSessionStore: UserSessionStore = {
			kind: "outage",
			create: (input) => inner.create(input),
			delete: (sid) => inner.delete(sid),
			get: (sid) =>
				outage.down
					? Promise.reject(
							Object.assign(new Error("Connection is closed."), { code: "ECONNRESET" }),
						)
					: inner.get(sid),
		};
		const logger = { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() };
		const config = makeConfig(ENABLED);
		const { handle, app } = await bootWith(config, modulesFor(config), {
			logger: logger as unknown as Logger,
			overrideComponents: { userSessionStore },
		});
		try {
			const { userCode, deviceCode } = await startWithCodes(app);
			const agent = request.agent(app);
			await signIn(agent);
			const { header, token } = await csrfToken(agent);

			// What the boot and the sign-in wrote (the replica-safety warning)
			// is not this request's; the assertions below count only its lines.
			logger.warn.mockClear();
			logger.error.mockClear();
			outage.down = true;
			const res = await agent
				.post("/oauth/device/verification")
				.set(header, token)
				.send({ action: "approve", user_code: userCode });
			expect(res.status).toBe(503);
			expect(res.body).toEqual({
				error: "temporarily_unavailable",
				error_description: "session store unavailable",
			});
			expect(res.headers["cache-control"]).toContain("no-store");

			const lines = logger.error.mock.calls.filter(
				(call) => call[1] === "device_verification_session_liveness_unavailable",
			);
			expect(lines).toHaveLength(1);
			const line = lines[0]?.[0] as Record<string, unknown>;
			expect(line).toMatchObject({
				store: "user_session",
				step: "get",
				sid: await sidOf(handle.components),
				err: { name: "Error", code: "ECONNRESET" },
			});
			expect(line.err).not.toBeInstanceOf(Error);
			expect(logger.error).toHaveBeenCalledTimes(1);
			expect(logger.warn).not.toHaveBeenCalled();

			outage.down = false;
			const polled = await pollFor(app, deviceCode);
			expect(polled.status).toBe(400);
			expect(polled.body.error).toBe("authorization_pending");
		} finally {
			await handle.dispose();
		}
	});

	it("refuses an approval from a user without a verified email when oauth.requireEmailVerified is on, and lets a verified one approve", async () => {
		// #297: the gate `/authorize` and the session grant hold at issuance.
		// An approval is what the device's token is issued from, so it is held
		// here too — otherwise a deployment requiring a verified email would
		// find those two gated and this path open.
		const base = makeConfig(ENABLED);
		const config = { ...base, oauth: { ...base.oauth, requireEmailVerified: true } } as AppConfig;
		const { handle, app } = await bootWith(config, modulesFor(config));
		try {
			const unverified = await startWithCodes(app);
			const alice = request.agent(app);
			await signIn(alice);
			const aliceCsrf = await csrfToken(alice);
			const refused = await alice
				.post("/oauth/device/verification")
				.set(aliceCsrf.header, aliceCsrf.token)
				.send({ action: "approve", user_code: unverified.userCode });
			expect(refused.status).toBe(403);
			expect(refused.body).toEqual({
				error: "access_denied",
				error_description: "email address is not verified",
			});
			const pending = await pollFor(app, unverified.deviceCode);
			expect(pending.body.error).toBe("authorization_pending");

			const verified = await startWithCodes(app);
			const bob = request.agent(app);
			await signIn(bob, VERIFIED_USERNAME);
			const bobCsrf = await csrfToken(bob);
			const approved = await bob
				.post("/oauth/device/verification")
				.set(bobCsrf.header, bobCsrf.token)
				.send({ action: "approve", user_code: verified.userCode });
			expect(approved.status).toBe(200);
			expect(approved.body.status).toBe("approved");
		} finally {
			await handle.dispose();
		}
	});
});
