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
 * What a `form_post` federation does when the transaction cannot be written,
 * read or retired (#494).
 *
 * Every one of these paths fails closed. The ephemeral state is the CSRF, PKCE
 * and nonce binding all at once, so a transaction that cannot be persisted
 * before the redirect, or cannot be retired before the code is exchanged, is a
 * flow that must not continue — an attacker who could force the failure and
 * then replay would otherwise bypass the binding entirely.
 */

import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { codeChallenge } from "#/federations/pkce.mjs";
import {
	deriveFederationTransactionCookieName,
	FEDERATION_TRANSACTION_KEY_PREFIX,
} from "#/federations/transaction.mjs";
import type { FederationProvider } from "#/federations/types.mjs";
import { createRouter } from "#/routes/Federation.mjs";
import {
	makeFederationTokenStore,
	makePermissivePolicy,
	makeRecordStore,
	makeSessionFederationIndex,
	makeUserRepository,
	makeUserSessionStore,
} from "./federation-harness.mjs";

const CALLBACK_URL = "https://app.example.com/oauth/federation/apple/callback";
const QUERY_CALLBACK_URL = "https://app.example.com/oauth/federation/query-idp/callback";

function makeApple(): FederationProvider {
	return {
		name: "apple",
		scope: ["name", "email"],
		responseMode: "form_post",
		buildAuthorizationUrl: ({ state, codeVerifier }) => {
			const url = new URL("https://appleid.apple.com/auth/authorize");
			url.searchParams.set("state", state);
			url.searchParams.set("code_challenge", codeChallenge(codeVerifier));
			return url;
		},
		exchangeCode: async () => ({
			issuer: "https://appleid.apple.com",
			sub: "apple-sub",
			expiresAt: null,
		}),
	};
}

/** A plain query-mode provider, for the branch that still uses the session. */
function makeQueryProvider(): FederationProvider {
	return {
		name: "query-idp",
		scope: ["openid"],
		buildAuthorizationUrl: ({ state }) => {
			const url = new URL("https://idp.example.com/authorize");
			url.searchParams.set("state", state);
			return url;
		},
		exchangeCode: async () => ({
			issuer: "https://idp.example.com",
			sub: "query-sub",
			expiresAt: null,
		}),
	};
}

type Knobs = {
	/** Mount no `req.sessionStore` at all. */
	withoutSessionStore?: boolean;
	/** Mount something that is not store-shaped. */
	malformedSessionStore?: boolean;
	/** Make one store method fail. */
	failOn?: "get" | "set" | "destroy";
	/** Register this callback URL instead of a well-formed one. */
	callbackUrl?: string | null;
	/** Passed straight through as the router's `config`. */
	config?: unknown;
	/** Passed straight through; omit to let the router derive it from `config`. */
	cookieName?: string;
	/** Make the session's own `save` fail, for the query-mode branch. */
	failSessionSave?: boolean;
};

const DEFAULT_COOKIE_NAME = deriveFederationTransactionCookieName("harness.session");

function buildApp(knobs: Knobs = {}) {
	const records = new Map<string, unknown>();
	const backing = makeRecordStore(records);
	const sessionStore = {
		get(sid: string, cb: (err: unknown, record?: unknown) => void) {
			if (knobs.failOn === "get") return cb(new Error("store down"));
			backing.get(sid, cb);
		},
		set(sid: string, record: unknown, cb?: (err?: unknown) => void) {
			if (knobs.failOn === "set") return cb?.(new Error("store down"));
			backing.set(sid, record, cb);
		},
		destroy(sid: string, cb?: (err?: unknown) => void) {
			if (knobs.failOn === "destroy") return cb?.(new Error("store down"));
			backing.destroy(sid, cb);
		},
	};

	const app = express();
	app.use((req, _res, next) => {
		(req as unknown as { session: Record<string, unknown> }).session = {
			cookie: { sameSite: "lax", secure: false, httpOnly: true },
			save(cb?: (err: unknown) => void) {
				cb?.(knobs.failSessionSave ? new Error("store down") : null);
			},
			regenerate(cb?: (err: unknown) => void) {
				cb?.(null);
			},
			destroy(cb?: (err: unknown) => void) {
				cb?.(null);
			},
		};
		if (!knobs.withoutSessionStore) {
			(req as unknown as { sessionStore: unknown }).sessionStore = knobs.malformedSessionStore
				? { get: "not-a-function" }
				: sessionStore;
		}
		next();
	});

	const providers = new Map<string, FederationProvider>([
		["apple", makeApple()],
		["query-idp", makeQueryProvider()],
	]);
	const callbackUrls = new Map<string, string>([["query-idp", QUERY_CALLBACK_URL]]);
	if (knobs.callbackUrl !== null) callbackUrls.set("apple", knobs.callbackUrl ?? CALLBACK_URL);

	app.use(
		createRouter(express, {
			// `in` rather than `??`, so a test can pass `null` as the config and
			// still reach the router's own fallback.
			config: ("config" in knobs
				? knobs.config
				: { session: { name: "harness.session" } }) as never,
			federationProviders: providers,
			federationRedirectPolicyResolver: new Map([["apple", makePermissivePolicy()]]) as never,
			providerCallbackUrls: callbackUrls,
			userRepository: makeUserRepository(),
			userSessionStore: makeUserSessionStore(),
			sessionFederationIndex: makeSessionFederationIndex(),
			federationTokenStore: makeFederationTokenStore(),
			...(knobs.cookieName === undefined
				? {}
				: { federationTransactionCookieName: knobs.cookieName }),
		}),
	);

	return { app, records };
}

/** Start a flow and return the transaction cookie to replay. */
async function start(app: express.Express, records: Map<string, unknown>) {
	const res = await request(app).get("/oauth/federation/apple");
	const header = ((res.headers["set-cookie"] as unknown as string[]) ?? []).find((c) =>
		c.startsWith(`${DEFAULT_COOKIE_NAME}=`),
	);
	if (!header) throw new Error("start leg issued no transaction cookie");
	const id = decodeURIComponent(header.split(";")[0]?.split("=").slice(1).join("=") ?? "");
	const record = records.get(`${FEDERATION_TRANSACTION_KEY_PREFIX}${id}`) as {
		federation: { state: string };
	};
	return {
		id,
		state: record.federation.state,
		cookie: `${DEFAULT_COOKIE_NAME}=${encodeURIComponent(id)}`,
	};
}

describe("a form_post start leg refuses when it cannot hold a transaction", () => {
	it("500s when no express-session store is mounted on the request", async () => {
		// The old code warned and carried on, redirecting the user to Apple for a
		// callback that could not possibly have worked.
		const { app } = buildApp({ withoutSessionStore: true });
		const res = await request(app).get("/oauth/federation/apple");
		expect(res.status).toBe(500);
		expect(res.body.error).toBe("misconfiguration");
	});

	it("500s when what is mounted is not a store", async () => {
		const { app } = buildApp({ malformedSessionStore: true });
		const res = await request(app).get("/oauth/federation/apple");
		expect(res.status).toBe(500);
		expect(res.body.error).toBe("misconfiguration");
	});

	it("500s when the callback URL has no path to scope the cookie to", async () => {
		const { app } = buildApp({ callbackUrl: "not-a-url" });
		const res = await request(app).get("/oauth/federation/apple");
		expect(res.status).toBe(500);
		expect(res.body.error).toBe("misconfiguration");
	});

	it("500s when the provider has no callback URL registered at all", async () => {
		const { app } = buildApp({ callbackUrl: null });
		const res = await request(app).get("/oauth/federation/apple");
		expect(res.status).toBe(500);
		expect(res.body.error).toBe("misconfiguration");
	});

	it("500s, and redirects nobody, when the transaction cannot be written", async () => {
		const { app, records } = buildApp({ failOn: "set" });
		const res = await request(app).get("/oauth/federation/apple");
		expect(res.status).toBe(500);
		expect(res.body.error).toBe("server_error");
		expect(records.size).toBe(0);
	});
});

describe("a query federation still fails closed on its own session save", () => {
	it("500s when the start leg cannot persist the envelope in the session", async () => {
		// The query branch is untouched by #494 and keeps the behaviour it had:
		// a store that cannot hold the state must not send the user to the IdP.
		const { app } = buildApp({ failSessionSave: true });
		const res = await request(app).get("/oauth/federation/query-idp");
		expect(res.status).toBe(500);
		expect(res.body.error).toBe("server_error");
	});
});

describe("a form_post callback refuses when the transaction cannot be resolved or retired", () => {
	it("500s when the store cannot be read", async () => {
		const { app, records } = buildApp();
		const flow = await start(app, records);

		const { app: broken } = buildApp({ failOn: "get" });
		const res = await request(broken)
			.post("/oauth/federation/apple/callback")
			.set("Cookie", flow.cookie)
			.type("form")
			.send({ state: flow.state, code: "c" });

		expect(res.status).toBe(500);
		expect(res.body.error).toBe("server_error");
	});

	it("500s rather than exchanging the code when the transaction cannot be deleted", async () => {
		// Reuse prevention is the whole point of the delete: if it fails, the
		// transaction is still replayable, so the flow stops here.
		const { app, records } = buildApp();
		const flow = await start(app, records);

		const { app: undeletable, records: sharedRecords } = buildApp({ failOn: "destroy" });
		sharedRecords.set(
			`${FEDERATION_TRANSACTION_KEY_PREFIX}${flow.id}`,
			records.get(`${FEDERATION_TRANSACTION_KEY_PREFIX}${flow.id}`),
		);

		const res = await request(undeletable)
			.post("/oauth/federation/apple/callback")
			.set("Cookie", flow.cookie)
			.type("form")
			.send({ state: flow.state, code: "c" });

		expect(res.status).toBe(500);
		expect(res.body.error).toBe("server_error");
	});

	it("still refuses cleanly when the provider has no callback URL to scope the cleared cookie to", async () => {
		const { app } = buildApp({ callbackUrl: null });
		const res = await request(app)
			.post("/oauth/federation/apple/callback")
			.set("Cookie", `${DEFAULT_COOKIE_NAME}=some-id`)
			.type("form")
			.send({ state: "s", code: "c" });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_session");
	});
});

describe("the transaction cookie's name follows the deployment's session cookie", () => {
	const cookieNameFrom = async (config: unknown): Promise<string> => {
		const { app } = buildApp({ config });
		const res = await request(app).get("/oauth/federation/apple");
		const header = ((res.headers["set-cookie"] as unknown as string[]) ?? []).find((c) =>
			c.includes(".federation="),
		);
		return header?.split("=")[0] ?? "";
	};

	it("derives it from config.session.name, dropping a __Host- prefix it could not satisfy", async () => {
		expect(await cookieNameFrom({ session: { name: "__Host-acme.sid" } })).toBe(
			"__Secure-acme.sid.federation",
		);
	});

	it("falls back to the reference default when the config carries no session name", async () => {
		// Only reachable through a hand-built AppConfig; the module wiring always
		// passes the real name.
		for (const config of [{}, { session: {} }, { session: { name: "" } }, null, "nonsense"]) {
			expect(await cookieNameFrom(config)).toBe("__Secure-auth.session.federation");
		}
	});
});
