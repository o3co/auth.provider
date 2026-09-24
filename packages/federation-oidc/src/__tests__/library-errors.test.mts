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
 * What core's `loggableError` makes of the errors this adapter's library
 * actually throws, when the token endpoint answers something it cannot use.
 * The routes log exactly this projection (the session callback, oauth's
 * federation token route), so it is judged here against the real
 * openid-client / oauth4webapi rather than a hand-built copy of their shapes:
 * whatever an upstream wrote into the answer must not reach a log line, and
 * what an operator needs to tell the failures apart — the status, the content
 * type, the OAuth error and its description — must.
 */

import { loggableError } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { createOidcProvider } from "#/oidc.mjs";
import { createFakeIdp } from "./helpers.mjs";

const ISSUER = "https://idp.test";

/** An OIDC provider whose token endpoint answers `answer()` as it stands. */
const providerAnswering = async (answer: () => Response) => {
	const idp = await createFakeIdp({ issuer: ISSUER });
	const provider = await createOidcProvider("idp", {
		issuer: ISSUER,
		clientId: idp.clientId,
		clientSecret: "client-secret",
		callbackURL: "https://auth.test/session/oauth/federation/idp/callback",
		fetch: async (input, init) => {
			const url = String(input instanceof Request ? input.url : input);
			return url === `${ISSUER}/token` ? answer() : idp.fetch(input, init);
		},
	});
	return provider;
};

/** The projection of what a refresh against that answer throws. */
const refreshFailure = async (answer: () => Response) => {
	const provider = await providerAnswering(answer);
	try {
		await provider.refreshToken("rt-1");
	} catch (err) {
		return loggableError(err);
	}
	throw new Error("the refresh was expected to fail");
};

describe("loggableError on the errors openid-client throws for a token answer", () => {
	it.each([
		["a form-encoded body under a JSON content type", '{"access_token":gho_SECRET1234567890}'],
		["a bare token under a JSON content type", "gho_SHORTSECRET"],
	])("%s: the parser's message, which quotes the body, is dropped", async (_label, body) => {
		const projected = await refreshFailure(
			() => new Response(body, { status: 200, headers: { "content-type": "application/json" } }),
		);
		const serialised = JSON.stringify(projected);
		expect(serialised).not.toContain("SECRET");
		expect(projected).toMatchObject({
			code: "OAUTH_PARSE_ERROR",
			cause: { code: "OAUTH_PARSE_ERROR", cause: { name: "SyntaxError" } },
		});
	});

	it("a form-encoded answer is refused by content type; the projection keeps the status and the type, never the body", async () => {
		const projected = await refreshFailure(
			() =>
				new Response("access_token=gho_FORMSECRET&token_type=bearer", {
					status: 200,
					headers: { "content-type": "application/x-www-form-urlencoded" },
				}),
		);
		expect(JSON.stringify(projected)).not.toContain("FORMSECRET");
		expect(projected).toMatchObject({
			code: "OAUTH_RESPONSE_IS_NOT_JSON",
			response: { status: 200, contentType: "application/x-www-form-urlencoded" },
		});
	});

	it("a gateway's 503 page keeps its status", async () => {
		const projected = await refreshFailure(
			() =>
				new Response("<html>Service Unavailable</html>", {
					status: 503,
					headers: { "content-type": "text/html" },
				}),
		);
		expect(projected).toMatchObject({
			code: "OAUTH_RESPONSE_IS_NOT_CONFORM",
			response: { status: 503, contentType: "text/html" },
		});
	});

	it("an OAuth refusal keeps its error and description, which tell a revoked grant from a broken client", async () => {
		const projected = await refreshFailure(
			() =>
				new Response(
					JSON.stringify({
						error: "invalid_grant",
						error_description: "Token has been expired or revoked.",
					}),
					{ status: 400, headers: { "content-type": "application/json" } },
				),
		);
		expect(projected).toMatchObject({
			name: "ResponseBodyError",
			status: 400,
			error: "invalid_grant",
			error_description: "Token has been expired or revoked.",
		});
	});
});
