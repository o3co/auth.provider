/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * #500 — `cors.allowedOrigins` was declared, shipped in every reference.conf,
 * and read by nothing. A cross-origin preflight to `/oauth/token` got no
 * `Access-Control-Allow-Origin`, so a browser SPA on any origin but the
 * provider's could not use this provider at all — and the operator who set the
 * key had no way to discover that, because a silent no-op config key produces
 * no error, no warning and no log line.
 *
 * These exercise the middleware through a real Express app rather than a stub
 * `Response`: `res.vary` appends rather than sets, the path match has to agree
 * with what the router actually routes, and a preflight has to end the
 * response. None of that is visible against a fake.
 */

import express, { type Express, Router } from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createApp } from "#/index.mjs";
import { browserFacingCorsRoutes, corsMw } from "#/middleware/cors.mjs";
import { defineModule } from "#/modules/manifest/index.mjs";
import { makeValidAppConfig } from "#/testing/fixtures/valid-config.mjs";

const ALLOWED = "https://app.example.com";
const OTHER_ALLOWED = "https://admin.example.com";
const UNLISTED = "https://evil.example.com";

/** Every path the middleware guards answers 200 with a marker body. */
const GUARDED_PATHS = [
	"/oauth/token",
	"/oauth/userinfo",
	"/oauth/revoke",
	"/.well-known/openid-configuration",
	"/.well-known/jwks.json",
] as const;

/** Paths that must be untouched by CORS. */
const UNGUARDED_PATHS = ["/oauth/introspect", "/oauth/authorize"] as const;

/**
 * An app with the middleware mounted the way `assembleApp` mounts it — first,
 * ahead of every route — plus a handler on each path it guards and each path
 * it must not.
 */
function buildApp(
	allowedOrigins: readonly string[],
	config: { oauth?: { jwt?: { jwksPath?: unknown } } } = {},
	logger?: { warn: (m: string) => void },
): Express {
	const app = express();
	const mw = corsMw({
		allowedOrigins,
		routes: browserFacingCorsRoutes(config),
		...(logger ? { logger: logger as never } : {}),
	});
	if (mw !== null) app.use(mw);
	for (const path of [...GUARDED_PATHS, ...UNGUARDED_PATHS, "/oauth/deviceauth"]) {
		app.all(path, (_req, res) => {
			res.status(200).json({ ok: path });
		});
	}
	// A route that fails, so the "an SPA must be able to READ the error"
	// property has something to assert against.
	app.all("/oauth/token/fail", (_req, res) => {
		res.status(400).json({ error: "invalid_grant" });
	});
	return app;
}

describe("corsMw — an exact-match allowlist on the browser-facing surface (#500)", () => {
	describe("the allowlist", () => {
		it("echoes the matched origin back, exactly", async () => {
			const res = await request(buildApp([ALLOWED]))
				.post("/oauth/token")
				.set("Origin", ALLOWED);
			expect(res.headers["access-control-allow-origin"]).toBe(ALLOWED);
		});

		it("gives an unlisted origin no header at all", async () => {
			const res = await request(buildApp([ALLOWED]))
				.post("/oauth/token")
				.set("Origin", UNLISTED);
			expect(res.headers["access-control-allow-origin"]).toBeUndefined();
			// Refusal is the ABSENT header, not a refused request: the endpoint
			// still answers, the browser is what declines to hand the body over.
			expect(res.status).toBe(200);
		});

		it("never reflects an arbitrary origin", async () => {
			// The reflection bug this shape exists to make impossible: an
			// implementation that echoes whatever arrived would pass the first
			// test above and fail this one.
			for (const origin of [UNLISTED, "null", "https://app.example.com.evil.test"]) {
				const res = await request(buildApp([ALLOWED]))
					.post("/oauth/token")
					.set("Origin", origin);
				expect(res.headers["access-control-allow-origin"]).toBeUndefined();
			}
		});

		it("never emits `*`, on any guarded path", async () => {
			// Including the unauthenticated documents, where it would be
			// harmless — one code path that can emit `*` is one code path away
			// from emitting it on a response carrying a token.
			for (const path of GUARDED_PATHS) {
				const res = await request(buildApp([ALLOWED]))
					.get(path)
					.set("Origin", ALLOWED);
				expect(res.headers["access-control-allow-origin"]).not.toBe("*");
			}
		});

		it("matches an origin's own case and port exactly", async () => {
			const app = buildApp([ALLOWED]);
			for (const near of [
				"https://APP.example.com",
				"https://app.example.com:443",
				"http://app.example.com",
			]) {
				const res = await request(app).post("/oauth/token").set("Origin", near);
				expect(res.headers["access-control-allow-origin"]).toBeUndefined();
			}
		});
	});

	describe("credentials", () => {
		it("never sends Access-Control-Allow-Credentials", async () => {
			// A cross-origin SPA here is a public client using PKCE and needs no
			// cookie. Allowing credentials would reach the cookie-backed
			// `session` grant, which exchanges an authenticated browser session
			// for tokens — a much larger grant, and CORS ships the two together.
			const app = buildApp([ALLOWED]);
			const simple = await request(app).post("/oauth/token").set("Origin", ALLOWED);
			expect(simple.headers["access-control-allow-credentials"]).toBeUndefined();

			const preflight = await request(app)
				.options("/oauth/token")
				.set("Origin", ALLOWED)
				.set("Access-Control-Request-Method", "POST");
			expect(preflight.headers["access-control-allow-credentials"]).toBeUndefined();
		});
	});

	describe("preflight", () => {
		it("answers 204 with the route's methods and the headers an SPA sends", async () => {
			const res = await request(buildApp([ALLOWED]))
				.options("/oauth/token")
				.set("Origin", ALLOWED)
				.set("Access-Control-Request-Method", "POST");

			expect(res.status).toBe(204);
			expect(res.headers["access-control-allow-origin"]).toBe(ALLOWED);
			expect(res.headers["access-control-allow-methods"]).toBe("POST");
			expect(res.headers["access-control-allow-headers"]).toBe("content-type, authorization, dpop");
			expect(res.headers["access-control-max-age"]).toBe("600");
		});

		it("advertises both methods userinfo answers (OIDC Core §5.3)", async () => {
			const res = await request(buildApp([ALLOWED]))
				.options("/oauth/userinfo")
				.set("Origin", ALLOWED)
				.set("Access-Control-Request-Method", "GET");
			expect(res.headers["access-control-allow-methods"]).toBe("GET, POST");
		});

		it("gives an unlisted origin a 204 with no CORS headers", async () => {
			// Ends here rather than falling through: the guarded routes answer
			// POST or GET, so the OPTIONS would 404 and tell the operator the
			// path is wrong when the answer is that the origin is not listed.
			const res = await request(buildApp([ALLOWED]))
				.options("/oauth/token")
				.set("Origin", UNLISTED)
				.set("Access-Control-Request-Method", "POST");
			expect(res.status).toBe(204);
			expect(res.headers["access-control-allow-origin"]).toBeUndefined();
			expect(res.headers["access-control-allow-methods"]).toBeUndefined();
		});

		it("leaves a plain OPTIONS (no Access-Control-Request-Method) to the route", async () => {
			const res = await request(buildApp([ALLOWED]))
				.options("/oauth/token")
				.set("Origin", ALLOWED);
			expect(res.status).toBe(200);
			expect(res.body).toEqual({ ok: "/oauth/token" });
		});
	});

	describe("Vary", () => {
		it("is set on every response from a guarded route, allowed or not", async () => {
			const app = buildApp([ALLOWED]);
			for (const path of GUARDED_PATHS) {
				for (const headers of [{ Origin: ALLOWED }, { Origin: UNLISTED }, {}]) {
					const res = await request(app).get(path).set(headers);
					expect(res.headers.vary, `${path} ${JSON.stringify(headers)}`).toMatch(/\bOrigin\b/);
				}
			}
		});

		it("is set on the preflight too", async () => {
			const res = await request(buildApp([ALLOWED]))
				.options("/oauth/token")
				.set("Origin", UNLISTED)
				.set("Access-Control-Request-Method", "POST");
			expect(res.headers.vary).toMatch(/\bOrigin\b/);
		});
	});

	describe("the routes it does and does not cover", () => {
		it("leaves /oauth/introspect and /oauth/authorize untouched", async () => {
			// Introspection is server-to-server and already refuses public
			// clients; /authorize is a top-level navigation, not a fetch. Neither
			// gains a header, and neither gains a `Vary` — nothing about them
			// depends on the Origin.
			const app = buildApp([ALLOWED]);
			for (const path of UNGUARDED_PATHS) {
				const res = await request(app).post(path).set("Origin", ALLOWED);
				expect(res.headers["access-control-allow-origin"], path).toBeUndefined();
				expect(res.headers.vary, path).toBeUndefined();
			}
		});

		it("leaves a route it has never heard of untouched", async () => {
			// The mount is an allowlist on purpose: a route contributed by a
			// module core does not know about must not silently acquire a
			// cross-origin read.
			const res = await request(buildApp([ALLOWED]))
				.post("/oauth/deviceauth")
				.set("Origin", ALLOWED);
			expect(res.headers["access-control-allow-origin"]).toBeUndefined();
		});

		it("follows oauth.jwt.jwksPath rather than assuming the default", async () => {
			const app = buildApp([ALLOWED], { oauth: { jwt: { jwksPath: "/keys.json" } } });
			// The route table is resolved through the same `resolveJwksPath` the
			// route registration and the advertised `jwks_uri` use.
			const moved = await request(app).get("/.well-known/jwks.json").set("Origin", ALLOWED);
			expect(moved.headers["access-control-allow-origin"]).toBeUndefined();
		});

		it("matches the path the way the router does — case and trailing slash", async () => {
			const app = buildApp([ALLOWED]);
			for (const path of ["/OAuth/Token", "/oauth/token/"]) {
				const res = await request(app).post(path).set("Origin", ALLOWED);
				expect(res.headers["access-control-allow-origin"], path).toBe(ALLOWED);
			}
		});
	});

	describe("what the browser can read", () => {
		it("puts the header on an error response too", async () => {
			// The `400 invalid_grant` is the response an SPA most needs to read.
			// Headers are set on the way IN, so whatever the route does with the
			// response they are already there.
			const res = await request(buildApp([ALLOWED]))
				.post("/oauth/token")
				.set("Origin", ALLOWED);
			expect(res.headers["access-control-allow-origin"]).toBe(ALLOWED);

			const app = express();
			const mw = corsMw({ allowedOrigins: [ALLOWED], routes: browserFacingCorsRoutes({}) });
			if (mw !== null) app.use(mw);
			app.post("/oauth/token", (_req, res2) => {
				res2.status(400).json({ error: "invalid_grant" });
			});
			const failed = await request(app).post("/oauth/token").set("Origin", ALLOWED);
			expect(failed.status).toBe(400);
			expect(failed.headers["access-control-allow-origin"]).toBe(ALLOWED);
		});

		it("exposes the two headers a caller cannot act without", async () => {
			const res = await request(buildApp([ALLOWED]))
				.post("/oauth/token")
				.set("Origin", ALLOWED);
			expect(res.headers["access-control-expose-headers"]).toBe("WWW-Authenticate, Retry-After");
		});
	});

	describe("an empty allowlist means CORS is off", () => {
		it("builds no middleware at all", () => {
			expect(corsMw({ allowedOrigins: [], routes: browserFacingCorsRoutes({}) })).toBeNull();
		});

		it("leaves the guarded routes with no header and no Vary", async () => {
			const res = await request(buildApp([])).post("/oauth/token").set("Origin", ALLOWED);
			expect(res.headers["access-control-allow-origin"]).toBeUndefined();
			expect(res.headers.vary).toBeUndefined();
		});
	});

	describe("a hand-built config that never passed the schema", () => {
		it("drops an entry the schema would have refused, and says which", () => {
			// Same discipline as `resolveJwksPath` re-applying `isValidJwksPath`:
			// this codebase supports hand-built `AppConfig`s, and a silently
			// narrowed allowlist is the same class of failure as the silently
			// absent one.
			const warn = vi.fn();
			const mw = corsMw({
				allowedOrigins: [ALLOWED, "https://bad.example.com/", "https://*.example.com"],
				routes: browserFacingCorsRoutes({}),
				logger: { warn } as never,
			});
			expect(mw).not.toBeNull();
			expect(warn).toHaveBeenCalledTimes(2);
			expect(warn.mock.calls.map((c) => String(c[0])).join("\n")).toMatch(/bad\.example\.com/);
		});

		it("builds nothing when every entry is refused", () => {
			expect(
				corsMw({ allowedOrigins: ["https://*.example.com"], routes: browserFacingCorsRoutes({}) }),
			).toBeNull();
		});

		it("never admits an entry it warned about", async () => {
			const app = buildApp([ALLOWED, "https://bad.example.com/"], {}, { warn: () => {} });
			const res = await request(app).post("/oauth/token").set("Origin", "https://bad.example.com");
			expect(res.headers["access-control-allow-origin"]).toBeUndefined();
		});
	});
});

describe("assembleApp mounts the CORS middleware from config (#500)", () => {
	/** A module contributing the OAuth surface at the paths the table names. */
	const surfaceModule = defineModule({
		name: "cors-test-surface",
		contributes: {
			routes: [
				() => {
					const router = Router();
					for (const path of [...GUARDED_PATHS, ...UNGUARDED_PATHS]) {
						router.all(path, (_req, res) => {
							res.status(200).json({ ok: path });
						});
					}
					return { id: "cors-test-surface", mountPath: "/", handler: router as never };
				},
			],
		},
	});

	const bootWith = async (allowedOrigins: unknown) => {
		const config = makeValidAppConfig() as unknown as Record<string, unknown>;
		config.cors = { allowedOrigins };
		const handle = await createApp({
			modules: [surfaceModule],
			bootstrapComponents: {
				config: config as never,
				pathResolver: (s: string) => s,
			} as never,
		});
		const app = express();
		app.use(handle.router);
		return { app, handle };
	};

	it("stamps the header on the token endpoint after a real boot", async () => {
		const { app, handle } = await bootWith([ALLOWED]);
		const res = await request(app).post("/oauth/token").set("Origin", ALLOWED);
		expect(res.status).toBe(200);
		expect(res.headers["access-control-allow-origin"]).toBe(ALLOWED);
		await handle.dispose();
	});

	it("answers the preflight before any other middleware sees it", async () => {
		// Mounted first, ahead of the sender-constraint middleware: a preflight
		// carries no Authorization and no body and must not reach anything that
		// would inspect either.
		const { app, handle } = await bootWith([ALLOWED]);
		const res = await request(app)
			.options("/oauth/token")
			.set("Origin", ALLOWED)
			.set("Access-Control-Request-Method", "POST");
		expect(res.status).toBe(204);
		expect(res.headers["access-control-allow-methods"]).toBe("POST");
		await handle.dispose();
	});

	it("mounts nothing when the list is empty", async () => {
		const { app, handle } = await bootWith([]);
		const res = await request(app).post("/oauth/token").set("Origin", ALLOWED);
		expect(res.headers["access-control-allow-origin"]).toBeUndefined();
		expect(res.headers.vary).toBeUndefined();
		await handle.dispose();
	});

	// The environment variable is the documented way to configure this, and it
	// can only carry a list as a comma-separated string. `assembleApp` reads
	// `components.config`, which has NOT necessarily been through
	// `AppConfigSchema` — `validateAndComposeConfig` validates with the core
	// schema, which does not declare `cors`, and merges the raw extras back
	// over the result. Testing that string for `Array.isArray` mounted nothing
	// at all, silently, which is the failure this key exists to end.
	it("mounts from a comma-separated string, the shape an env var carries", async () => {
		const { app, handle } = await bootWith(`${ALLOWED}, ${OTHER_ALLOWED}`);
		for (const origin of [ALLOWED, OTHER_ALLOWED]) {
			const res = await request(app).post("/oauth/token").set("Origin", origin);
			expect(res.status, origin).toBe(200);
			expect(res.headers["access-control-allow-origin"], origin).toBe(origin);
		}
		const refused = await request(app).post("/oauth/token").set("Origin", UNLISTED);
		expect(refused.headers["access-control-allow-origin"]).toBeUndefined();
		await handle.dispose();
	});

	it("treats an exported-but-empty variable as CORS off", async () => {
		const { app, handle } = await bootWith("");
		const res = await request(app).post("/oauth/token").set("Origin", ALLOWED);
		expect(res.headers["access-control-allow-origin"]).toBeUndefined();
		expect(res.headers.vary).toBeUndefined();
		await handle.dispose();
	});

	it("warns rather than staying silent when the value is a shape nothing can read", async () => {
		const warn = vi.fn();
		const config = makeValidAppConfig() as unknown as Record<string, unknown>;
		config.cors = { allowedOrigins: 42 };
		const handle = await createApp({
			modules: [surfaceModule],
			bootstrapComponents: {
				config: config as never,
				logger: { ...console, warn, child: () => console } as never,
				pathResolver: (s: string) => s,
			} as never,
		});
		expect(warn).toHaveBeenCalledWith(
			expect.objectContaining({ received: "number" }),
			"cors_allowed_origins_unreadable",
		);
		await handle.dispose();
	});

	it("leaves introspection and authorize alone after a real boot", async () => {
		const { app, handle } = await bootWith([ALLOWED]);
		for (const path of UNGUARDED_PATHS) {
			const res = await request(app).post(path).set("Origin", ALLOWED);
			expect(res.headers["access-control-allow-origin"], path).toBeUndefined();
		}
		await handle.dispose();
	});
});
