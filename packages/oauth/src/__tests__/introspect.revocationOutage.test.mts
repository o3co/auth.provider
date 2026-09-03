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
 * #459 — a denylist backend outage reaches the token-accepting surfaces as
 * the outage it is, not as a revocation.
 *
 * `verifyJwt` fails closed when `denylist.has(jti)` throws — right — but it
 * reported that as `reason: "revoked"`, so the audit line for a Redis blip and
 * for a genuinely revoked token was the same `jwt_verify_rejected
 * reason=revoked`, for every token on every replica until the backend came
 * back. #408 split the outage from the finding for the subject watermark and
 * named it `revocation_unavailable`; this pins the denylist on the same reason
 * at the endpoints a resource server actually asks.
 *
 * What does NOT change here, deliberately: the wire answer. Introspection has
 * no `temporarily_unavailable` slot — RFC 7662 §2.2 defines `active: false`
 * for any token the AS declines to vouch for — and #408 kept the watermark
 * outage on `active: false` for exactly that reason. The denylist outage
 * answers the same: parity, and still fail-closed. The refresh grant, the one
 * surface #408 remaps to 503, has no denylist slot at all
 * (`GrantDependencies`), so there is no token-endpoint counterpart to pin.
 */

import { createSecretKey } from "node:crypto";
import {
	type AccessTokenDenylist,
	type ClientRepository,
	type CodeRepository,
	createMemoryAccessTokenDenylist,
	createSymmetricKeyStore,
	type Logger,
	type SubjectRevocation,
} from "@o3co/auth-provider-core";
import { GrantRegistry, makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createRouter as createUserinfoRouter } from "#/routes/userinfo.mjs";
import { createOAuthRouter } from "#/routes.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

const ISSUER = "https://auth.example";
const CLIENT_ID = "c-1";
const CLIENT_SECRET = "c-1-secret";
const SUBJECT = "u-1";

const clientEntry = (id: string) => ({
	clientId: id,
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedRedirectUris: [],
	allowedScopes: [],
});

const clientRepository: ClientRepository = {
	findById: async (id) => (id === CLIENT_ID ? clientEntry(id) : null),
	authenticate: async (id, secret) =>
		id === CLIENT_ID && secret === CLIENT_SECRET ? clientEntry(id) : null,
};

const codeRepository: CodeRepository = {
	createCode: async () => ({
		code: "test-code",
		client_id: CLIENT_ID,
		redirect_uri: "https://rp.example/cb",
	}),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

const baseConfig = {
	...makeValidAppConfig(),
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {},
	},
	endpoints: { login: { url: "/login" } },
} as unknown as import("@o3co/auth-provider-core").AppConfig;

/** An otherwise-valid access token: the only thing that can refuse it is revocation. */
async function mintAT(jti: string): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	return new SignJWT({ sub: SUBJECT, scope: "openid email", client_id: CLIENT_ID, jti })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setIssuer(ISSUER)
		.setAudience(CLIENT_ID)
		.setIssuedAt(now)
		.setExpirationTime(now + 3600)
		.sign(secretKey);
}

/** A denylist whose consult always fails — a transient outage, not a revocation. */
const outageDenylist = (): AccessTokenDenylist => ({
	kind: "outage",
	async add() {},
	async has() {
		throw new Error("ECONNREFUSED");
	},
});

/** The watermark's equivalent, so the two outages can be compared side by side. */
const outageWatermark = (): SubjectRevocation => ({
	kind: "outage",
	async revokeBefore() {},
	async revokedBefore() {
		throw new Error("ECONNREFUSED");
	},
});

const spyLogger = (): Logger => {
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: () => logger,
	};
	return logger as unknown as Logger;
};

describe("#459 — a denylist outage at /oauth/introspect", () => {
	const buildApp = async (opts: {
		denylist?: AccessTokenDenylist;
		subjectRevocation?: SubjectRevocation;
		logger?: Logger;
	}) => {
		const { router } = await createOAuthRouter(express, {
			registry: new GrantRegistry(),
			config: baseConfig,
			clientRepository,
			codeRepository,
			keyStore,
			...(opts.denylist ? { accessTokenDenylist: opts.denylist } : {}),
			...(opts.subjectRevocation ? { subjectRevocation: opts.subjectRevocation } : {}),
			...(opts.logger ? { logger: opts.logger } : {}),
		});
		const app = express();
		app.use(express.json());
		app.use(express.urlencoded({ extended: false }));
		app.use("/oauth", router);
		return app;
	};

	/** RFC 7662 §2.1 client-authenticated call: the body handler consults the denylist. */
	const introspectAsClient = (app: express.Express, token: string) =>
		request(app)
			.post("/oauth/introspect")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token });

	/** Bearer self-introspection: the credential path consults the denylist first. */
	const introspectAsBearer = (app: express.Express, token: string) =>
		request(app)
			.post("/oauth/introspect")
			.set("Authorization", `Bearer ${token}`)
			.type("form")
			.send({ token });

	it("answers active:false on the client-authenticated path — still fail-closed", async () => {
		const app = await buildApp({ denylist: outageDenylist() });
		const res = await introspectAsClient(app, await mintAT("j-1"));
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ active: false });
	});

	it("answers active:false on the bearer path — a token cannot vouch for itself during an outage", async () => {
		const app = await buildApp({ denylist: outageDenylist() });
		const res = await introspectAsBearer(app, await mintAT("j-2"));
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ active: false });
	});

	it("keeps Cache-Control: no-store and Pragma: no-cache on the refusal", async () => {
		// #293 item 2: an intermediary must not cache a liveness answer, and an
		// outage answer least of all — it would keep serving `active: false`
		// after the backend came back.
		const app = await buildApp({ denylist: outageDenylist() });
		const res = await introspectAsClient(app, await mintAT("j-3"));
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.headers.pragma).toBe("no-cache");
	});

	it("logs jwt_verify_rejected with reason=revocation_unavailable, not revoked", async () => {
		// The operator-facing half of the issue: `emitRejection` logs the
		// reason and not the message, so before #459 a Redis blip and a real
		// revocation were the same line. Introspection is where a resource
		// server's "is this token good?" lands, so it is where that line is
		// read.
		const logger = spyLogger();
		const app = await buildApp({ denylist: outageDenylist(), logger });
		await introspectAsClient(app, await mintAT("j-4"));
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ reason: "revocation_unavailable", jti: "j-4" }),
			"jwt_verify_rejected",
		);
		expect(logger.warn).not.toHaveBeenCalledWith(
			expect.objectContaining({ reason: "revoked" }),
			"jwt_verify_rejected",
		);
	});

	it("answers exactly what a watermark outage answers — one event class, one answer (#408 parity)", async () => {
		const viaDenylist = await introspectAsClient(
			await buildApp({ denylist: outageDenylist() }),
			await mintAT("j-5"),
		);
		const viaWatermark = await introspectAsClient(
			await buildApp({ subjectRevocation: outageWatermark() }),
			await mintAT("j-6"),
		);
		expect(viaDenylist.status).toBe(viaWatermark.status);
		expect(viaDenylist.body).toEqual(viaWatermark.body);
		expect(viaDenylist.body).toEqual({ active: false });
	});

	it("keeps a genuine denylist hit logged as revoked", async () => {
		// Distinguishable in both directions: an outage must not read as a
		// revocation, and a revocation must not read as an outage.
		const denylist = createMemoryAccessTokenDenylist();
		await denylist.add("j-7", Date.now() + 600_000);
		const logger = spyLogger();
		const app = await buildApp({ denylist, logger });
		const res = await introspectAsClient(app, await mintAT("j-7"));
		expect(res.body).toEqual({ active: false });
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ reason: "revoked", jti: "j-7" }),
			"jwt_verify_rejected",
		);
		expect(logger.warn).not.toHaveBeenCalledWith(
			expect.objectContaining({ reason: "revocation_unavailable" }),
			"jwt_verify_rejected",
		);
	});
});

describe("#459 — a denylist outage at /oauth/userinfo", () => {
	// No session store: a verified token answers `{ sub }`, so the only thing
	// between the token and a 200 is the denylist consult.
	const buildApp = (denylist: AccessTokenDenylist, logger?: Logger) => {
		const app = express();
		app.use(express.json());
		app.use(
			"/oauth",
			createUserinfoRouter(express, {
				keyStore,
				issuer: ISSUER,
				accessTokenDenylist: denylist,
				...(logger ? { logger } : {}),
			}),
		);
		return app;
	};

	const userinfo = (app: express.Express, token: string) =>
		request(app).get("/oauth/userinfo").set("Authorization", `Bearer ${token}`);

	it("answers 401 invalid_token — a bearer surface stays fail-closed, as for a watermark outage", async () => {
		const at = await mintAT("j-8");
		// The same token is served while the denylist is healthy, so the 401
		// below is the outage and not some other check.
		expect((await userinfo(buildApp(createMemoryAccessTokenDenylist()), at)).status).toBe(200);

		const res = await userinfo(buildApp(outageDenylist()), at);
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_token");
		expect(res.headers["www-authenticate"]).toContain('error="invalid_token"');
	});

	it("logs jwt_verify_rejected with reason=revocation_unavailable", async () => {
		const logger = spyLogger();
		await userinfo(buildApp(outageDenylist(), logger), await mintAT("j-9"));
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ reason: "revocation_unavailable", jti: "j-9" }),
			"jwt_verify_rejected",
		);
	});
});
