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
 * The OAuth router parses the bodies of the routes it owns, and only those.
 *
 * It is mounted at `/oauth`, a prefix other packages mount routes under too —
 * the device grant, federation grants, WebAuthn, a deployment's own. A body
 * parser that ran for every request beneath the prefix consumed those
 * routes' request streams whenever the OAuth router happened to be mounted
 * ahead of them: what another route received depended on the order the
 * composition listed its modules in, and `body-parser` does not parse a body
 * twice, so that route's own parser, limit and media types never ran.
 */

import type {
	AppConfig,
	ClientRepository,
	CodeRepository,
	ConsentStore,
	FederationTokenStore,
	PendingConsentStore,
	RefreshTokenFamilyRevocation,
	SessionFamilyIndex,
	SessionFederationIndex,
	SessionRPRegistry,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import { createSymmetricKeyStore } from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express, { type ErrorRequestHandler, type RequestHandler, type Router } from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

const config = {
	oauth: {
		jwt: { issuer: "https://issuer.example" },
		oidcMode: "dual",
		grants: {},
		revocation: { accessToken: "unsupported" },
	},
	rateLimit: { failMode: "open" as const },
	endpoints: { login: { url: "/login" } },
} as unknown as AppConfig;

const clientRepository: ClientRepository = {
	findById: async () => null,
	authenticate: async () => null,
};

const codeRepository: CodeRepository = {
	createCode: async () => {
		throw new Error("not exercised");
	},
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

/**
 * The router with every optional surface mounted — logout, federation
 * token, consent — or with none of them. The stores are never called: only
 * construction and body parsing are exercised.
 */
const routerWith = async (surfaces: "all" | "none"): Promise<Router> => {
	const unused = {} as never;
	const { router } = await createOAuthRouter(express, {
		registry: new GrantRegistry(),
		config,
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore("body-parsing-secret.at-least-32-bytes"),
		...(surfaces === "all"
			? {
					userSessionStore: unused as UserSessionStore,
					sessionRPRegistry: unused as SessionRPRegistry,
					sessionFamilyIndex: unused as SessionFamilyIndex,
					sessionFederationIndex: unused as SessionFederationIndex,
					federationTokenStore: unused as FederationTokenStore,
					refreshTokenFamilyRevocation: unused as RefreshTokenFamilyRevocation,
					consentStore: unused as ConsentStore,
					pendingConsentStore: unused as PendingConsentStore,
				}
			: {}),
		logger: createMockLogger(),
	});
	return router;
};

const fullRouter = () => routerWith("all");

/** Every route path registered on `router`, its sub-routers' included. */
const routePaths = (router: Router): string[] =>
	(router.stack as unknown as { route?: { path: string }; handle?: { stack?: unknown } }[]).flatMap(
		(layer) =>
			layer.route !== undefined
				? [layer.route.path]
				: layer.handle?.stack !== undefined
					? routePaths(layer.handle as unknown as Router)
					: [],
	);

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

describe("the OAuth router's body parsing", () => {
	it.each([
		["a form body", "form", "a=1&b=2"],
		["a JSON body", "json", '{"a":1}'],
	] as const)(
		"leaves %s to a route under /oauth that it does not own unread",
		async (_label, type, body) => {
			const app = express();
			app.use("/oauth", await fullRouter());
			app.post("/oauth/elsewhere", readsItsOwnBody);

			const res = await request(app).post("/oauth/elsewhere").type(type).send(body);

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ raw: body, parsedBefore: null });
		},
	);

	it.each([
		["every optional surface mounted", "all"],
		["no optional surface mounted", "none"],
	] as const)("parses exactly the routes it mounts, with %s", async (_label, surfaces) => {
		// Both directions. Every route the router mounts is parsed — a
		// malformed JSON body is refused by its parser. Every path it could
		// own but has not mounted — /logout, /consent and the federation
		// routes without their stores — reaches a route mounted after it
		// with the body unread, so a deployment's own route there parses
		// its own. The candidate paths are discovered from the router
		// with everything mounted, so a route added later is covered.
		const candidates = new Set(routePaths(await fullRouter()));
		expect([...candidates]).toEqual(
			expect.arrayContaining([
				"/token",
				"/introspect",
				"/authorize",
				"/userinfo",
				"/logout",
				"/federation/:name/logout",
				"/federation/:name/token",
				"/revoke",
				"/consent",
			]),
		);
		const router = await routerWith(surfaces);
		const mounted = new Set(routePaths(router));
		if (surfaces === "none") {
			for (const conditional of ["/logout", "/consent", "/federation/:name/token"]) {
				expect(mounted.has(conditional), conditional).toBe(false);
			}
		}

		const concrete = (path: string) => `/oauth${path.replace(":name", "example")}`;
		const recordParserError: ErrorRequestHandler = (error, _req, res, _next) => {
			res.status(599).json({ type: (error as { type?: unknown }).type ?? null });
		};
		const app = express();
		app.use("/oauth", router);
		for (const path of candidates) {
			if (!mounted.has(path)) app.post(concrete(path), readsItsOwnBody);
		}
		app.use(recordParserError);

		for (const path of candidates) {
			if (mounted.has(path)) {
				const res = await request(app)
					.post(concrete(path))
					.set("Content-Type", "application/json")
					.send("{not json");
				expect(res.status, path).toBe(599);
				expect(res.body, path).toEqual({ type: "entity.parse.failed" });
			} else {
				const res = await request(app).post(concrete(path)).type("form").send("a=1");
				expect(res.status, path).toBe(200);
				expect(res.body, path).toEqual({ raw: "a=1", parsedBefore: null });
			}
		}
	});
});
