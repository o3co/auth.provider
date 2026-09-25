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
 * What core's `isFederationUpstreamOutage` makes of what this adapter's
 * delegated code exchange really throws — the federation-grants callback
 * answers `temporarily_unavailable` and logs an outage exactly when it says
 * so, and `upstream_error` otherwise. Judged against the real openid-client /
 * oauth4webapi and undici, not a hand-built copy of their shapes: a port
 * nothing listens on, a token endpoint that does not answer in time, one
 * answering 503 or 502, and one refusing the code.
 */

import { createServer } from "node:net";
import {
	isFederationUpstreamOutage,
	supportsDelegatedAuthorization,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { createOidcProvider } from "#/oidc.mjs";
import { createFakeIdp } from "./helpers.mjs";

const ISSUER = "https://idp-outage.test";

/** A loopback port nothing listens on: a connection there is really refused. */
const closedPort = () =>
	new Promise<number>((resolve) => {
		const probe = createServer();
		probe.listen(0, "127.0.0.1", () => {
			const { port } = probe.address() as { port: number };
			probe.close(() => resolve(port));
		});
	});

/** What the delegated code exchange throws when the token endpoint answers with `token`. */
async function exchangeFailure(
	token: (init: RequestInit | undefined) => Promise<Response>,
	signal?: AbortSignal,
): Promise<unknown> {
	const idp = await createFakeIdp({ issuer: ISSUER });
	const provider = await createOidcProvider("idp-outage", {
		issuer: ISSUER,
		clientId: idp.clientId,
		clientSecret: "s3cret",
		callbackURL: "https://auth.test/session/oauth/federation/idp-outage/callback",
		fetch: async (input, init) => {
			const url = String(input instanceof Request ? input.url : input);
			return url === `${ISSUER}/token` ? token(init) : idp.fetch(input, init);
		},
	});
	if (!supportsDelegatedAuthorization(provider)) throw new Error("fixture: no capability");
	try {
		await provider.exchangeDelegatedCode({
			code: "code-1",
			codeVerifier: "v".repeat(43),
			redirectUri: "https://auth.test/session/federation-grants/callback/calendar",
			nonce: "nonce-1",
			callbackParams: {},
			identityClaims: [],
			...(signal === undefined ? {} : { signal }),
		});
	} catch (error) {
		return error;
	}
	throw new Error("the exchange was expected to fail");
}

const answer = (status: number, body: string | null, contentType?: string) => async () =>
	new Response(body, {
		status,
		...(contentType === undefined ? {} : { headers: { "content-type": contentType } }),
	});

describe("the delegated code exchange's failures, as the federation-grants callback reads them", () => {
	it("reads a port nothing listens on as an outage: undici's TypeError over a coded cause", async () => {
		const port = await closedPort();
		const error = await exchangeFailure((init) => fetch(`http://127.0.0.1:${port}/token`, init));
		expect(error).toMatchObject({ name: "TypeError", cause: { code: "ECONNREFUSED" } });
		expect(isFederationUpstreamOutage(error)).toBe(true);
	});

	it("reads a token endpoint that does not answer before the signal as an outage: OAUTH_TIMEOUT", async () => {
		const error = await exchangeFailure(
			(init) =>
				new Promise((_resolve, reject) => {
					init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
				}),
			AbortSignal.timeout(50),
		);
		expect(error).toMatchObject({ name: "ClientError", code: "OAUTH_TIMEOUT" });
		expect(isFederationUpstreamOutage(error)).toBe(true);
	});

	it.each([
		[
			"503 with a JSON body",
			answer(503, JSON.stringify({ error: "temporarily_unavailable" }), "application/json"),
		],
		["503 with an HTML body", answer(503, "<html><body>down</body></html>", "text/html")],
		["502 with no body", answer(502, null)],
	])("reads a token endpoint answering %s as an outage", async (_label, token) => {
		const error = await exchangeFailure(token);
		expect(error).toMatchObject({
			name: "ClientError",
			code: "OAUTH_RESPONSE_IS_NOT_CONFORM",
		});
		expect(isFederationUpstreamOutage(error)).toBe(true);
	});

	it("reads the token endpoint refusing the code with invalid_grant as the upstream's refusal", async () => {
		const error = await exchangeFailure(
			answer(400, JSON.stringify({ error: "invalid_grant" }), "application/json"),
		);
		expect(error).toMatchObject({ name: "ResponseBodyError", status: 400, error: "invalid_grant" });
		expect(isFederationUpstreamOutage(error)).toBe(false);
	});
});
