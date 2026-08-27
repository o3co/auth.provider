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
 * End-to-end seam for issue #264: the real DPoP mechanism behind the real
 * `protectedResourceBindingMw`, over a real access token carrying the `cnf`
 * the grant would have stamped on it.
 *
 * The unit tests on either side of this seam use fakes — the middleware's
 * tests stub the mechanism, the mechanism's tests call `extract` directly.
 * Neither would catch a mismatch in what the two actually exchange, which is
 * exactly where a sender-constraint bypass would hide.
 */

import type { Server } from "node:http";
import { protectedResourceBindingMw } from "@o3co/auth-provider-core";
import express from "express";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { computeAth } from "#/ath.mjs";
import { createMemoryDPoPReplayStore } from "#/memory/replay-store.mjs";
import { computeJkt } from "#/thumbprint.mjs";
import { createDPoPMechanism } from "#/verifier.mjs";

const RESOURCE_PATH = "/userinfo";

/** A client's DPoP key pair, plus the `jkt` a grant would put in `cnf`. */
const makeClientKey = async () => {
	const { publicKey, privateKey } = await generateKeyPair("ES256");
	const jwk = await exportJWK(publicKey);
	return { jwk, privateKey, jkt: await computeJkt(jwk) };
};

type ClientKey = Awaited<ReturnType<typeof makeClientKey>>;

/**
 * An access token bound to `jkt`, as the authorization-code grant mints it.
 *
 * `jti` is included because the grant emits one and because these tests need
 * two tokens bound to the same key to be *different tokens* — without it the
 * claims are identical, the JWTs are byte-identical, and the replay case
 * would be asserting against the very token it means to substitute.
 */
const mintBoundAccessToken = async (jkt: string): Promise<string> =>
	new SignJWT({ sub: "user-1", jti: crypto.randomUUID(), cnf: { jkt } })
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.sign(new Uint8Array(32));

const mintProof = async (
	key: ClientKey,
	opts: { htu: string; ath?: string; htm?: string },
): Promise<string> =>
	new SignJWT({
		htm: opts.htm ?? "GET",
		htu: opts.htu,
		iat: Math.floor(Date.now() / 1000),
		jti: crypto.randomUUID(),
		...(opts.ath === undefined ? {} : { ath: opts.ath }),
	})
		.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk: key.jwk })
		.sign(key.privateKey);

describe("DPoP at a protected resource (#264)", () => {
	let server: Server;
	let key: ClientKey;
	let accessToken: string;
	let htu: string;

	beforeEach(async () => {
		key = await makeClientKey();
		accessToken = await mintBoundAccessToken(key.jkt);

		const mechanism = createDPoPMechanism({
			replayStore: createMemoryDPoPReplayStore(),
			iatWindowSeconds: 60,
		});

		const app = express();
		app.use(protectedResourceBindingMw({ mechanisms: [mechanism] }));
		app.get(RESOURCE_PATH, (req, res) => {
			res.status(200).json({ binding: req.tokenBinding ?? null });
		});

		// The proof's `htu` must name the URL the request actually reaches, so
		// the server is started here and reused for every request in the test
		// rather than letting supertest bind a fresh ephemeral port per call.
		// Otherwise the positive case could only ever assert "401 or 200", which
		// would pass just as happily if enforcement were broken.
		server = await new Promise<Server>((resolve) => {
			const listening = app.listen(0, "127.0.0.1", () => resolve(listening));
		});
		const address = server.address();
		const port = typeof address === "object" && address !== null ? address.port : 0;
		htu = `http://127.0.0.1:${port}${RESOURCE_PATH}`;
	});

	afterEach(async () => {
		await new Promise<void>((resolve) => server.close(() => resolve()));
	});

	const call = (headers: Record<string, string>) => request(server).get(RESOURCE_PATH).set(headers);

	it("admits a bound token presented with a matching, ath-bound proof", async () => {
		const proof = await mintProof(key, { htu, ath: await computeAth(accessToken) });
		const res = await call({ Authorization: `DPoP ${accessToken}`, DPoP: proof });
		expect(res.status).toBe(200);
		expect(res.body.binding).toEqual({ kind: "dpop", confirmation: { jkt: key.jkt } });
	});

	it("refuses the bound token as a plain Bearer even with a valid proof attached", async () => {
		const proof = await mintProof(key, { htu, ath: await computeAth(accessToken) });
		const res = await call({ Authorization: `Bearer ${accessToken}`, DPoP: proof });
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_token");
		expect(res.headers["www-authenticate"]).toContain("DPoP");
	});

	it("refuses the bound token when no proof is presented", async () => {
		const res = await call({ Authorization: `DPoP ${accessToken}` });
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_token");
	});

	it("refuses a proof carrying another token's ath — the captured-proof replay", async () => {
		// Same client, same key, different token: the proof is genuinely the
		// client's own, just bound to a token other than the one presented.
		const otherToken = await mintBoundAccessToken(key.jkt);
		expect(otherToken).not.toBe(accessToken);
		const proof = await mintProof(key, { htu, ath: await computeAth(otherToken) });
		const res = await call({ Authorization: `DPoP ${accessToken}`, DPoP: proof });
		expect(res.status).toBe(401);
	});

	it("refuses a proof from a different key than the token is bound to", async () => {
		const attackerKey = await makeClientKey();
		const proof = await mintProof(attackerKey, { htu, ath: await computeAth(accessToken) });
		const res = await call({ Authorization: `DPoP ${accessToken}`, DPoP: proof });
		expect(res.status).toBe(401);
	});
});
