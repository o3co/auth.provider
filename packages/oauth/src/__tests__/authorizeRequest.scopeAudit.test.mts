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
 * `/authorize`'s scope stage: a refusal is sent only once its
 * `authorize.rejected` emit has answered, as every other refusal is.
 */

import type { PublicClient } from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import { auditFailure } from "#/routes/authorizeAnswers.mjs";
import type { AuthorizeContext } from "#/routes/authorizeContext.mjs";
import { resolveScopes } from "#/routes/authorizeRequest.mjs";

vi.mock("#/routes/authorizeAnswers.mjs", async (importOriginal) => ({
	...(await importOriginal<typeof import("#/routes/authorizeAnswers.mjs")>()),
	auditFailure: vi.fn(),
}));

const REDIRECT_URI = "https://app.example/cb";

const contextFor = (redirect: ReturnType<typeof vi.fn>): AuthorizeContext =>
	({
		req: { ip: "127.0.0.1", get: () => undefined },
		res: { redirect },
		opts: { oauth: { oidcMode: "dual" } },
		issuerOrigin: "https://issuer.example",
		clientId: "client-a",
		redirectUri: REDIRECT_URI,
		state: "xyz",
		params: {},
	}) as unknown as AuthorizeContext;

describe("resolveScopes — an omitted scope with no defaultScopes", () => {
	it("redirects invalid_scope only after its authorize.rejected emit has answered", async () => {
		let answer: () => void = () => {};
		vi.mocked(auditFailure).mockImplementationOnce(
			() =>
				new Promise<void>((resolve) => {
					answer = resolve;
				}),
		);
		const redirect = vi.fn();
		const client = {
			clientId: "client-a",
			allowedScopes: ["read"],
		} as unknown as PublicClient;

		const resolved = resolveScopes(contextFor(redirect), undefined, client);
		await new Promise((resolve) => setImmediate(resolve));

		expect(vi.mocked(auditFailure)).toHaveBeenCalledWith(expect.anything(), {
			reason: "scope_omitted_without_default",
		});
		expect(redirect).not.toHaveBeenCalled();

		answer();
		expect(await resolved).toBeNull();
		expect(redirect).toHaveBeenCalledTimes(1);
		const location = new URL(redirect.mock.calls[0]?.[0] as string);
		expect(location.origin + location.pathname).toBe(REDIRECT_URI);
		expect(location.searchParams.get("error")).toBe("invalid_scope");
	});
});
