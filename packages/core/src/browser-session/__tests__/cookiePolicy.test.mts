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
 * The `cookiePolicy` slot (#728): the session cookie's attributes, which
 * other modules need to set a cookie of their own beside it or to size what
 * must outlive a session. Its contract suite and the test double: the
 * double keeps every case, and each way a policy can break the contract
 * fails the case that names it.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type { SessionCookiePolicy } from "#/browser-session/types.mjs";
import { MAX_DURATION_MS } from "#/config/durations.mjs";
import { createApp, defineModule, type ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import {
	createTestSessionCookiePolicy,
	type SessionCookiePolicyContractInput,
	sessionCookiePolicyContract,
} from "#/testing/index.mjs";

const RULES = {
	name: "name is a cookie name: a non-empty RFC 6265 token",
	attributes: "sameSite is lax, strict or none, and secure is true or false",
	domain: "domain is a non-empty string, or undefined for a host-only cookie",
	host: "a __Host- name is secure and host-only",
	maxAge: "maxAgeMs is a whole number of milliseconds from 1 to the one-year ceiling",
	frozen: "the policy is frozen",
} as const;

/** The names of the cases `build` fails. */
const failing = async (build: SessionCookiePolicyContractInput["build"]): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of sessionCookiePolicyContract({ build })) {
		try {
			await run();
		} catch {
			failed.push(name);
		}
	}
	return failed;
};

/** The double's policy with `members` put over it, frozen as a provider hands it. */
const policyWith = (members: Record<string, unknown>): SessionCookiePolicy =>
	Object.freeze({ ...createTestSessionCookiePolicy(), ...members }) as SessionCookiePolicy;

describe("the cookiePolicy slot", () => {
	it("is optional, and holds the session cookie's attributes", () => {
		expectTypeOf<ComponentMap["cookiePolicy"]>().toEqualTypeOf<SessionCookiePolicy | undefined>();
		expectTypeOf<
			ProviderDeps<"cookiePolicy">["cookiePolicy"]
		>().toEqualTypeOf<SessionCookiePolicy>();
		expectTypeOf<SessionCookiePolicy>().toEqualTypeOf<{
			readonly name: string;
			readonly secure: boolean;
			readonly sameSite: "lax" | "strict" | "none";
			readonly domain: string | undefined;
			readonly maxAgeMs: number;
		}>();
		expect(true).toBe(true);
	});

	it("is filled by a module, and read by another", async () => {
		const policy = createTestSessionCookiePolicy();
		let seen: SessionCookiePolicy | undefined;
		const owner = defineModule({
			name: "test:cookie-policy-owner",
			provides: { cookiePolicy: () => policy },
		});
		const reader = defineModule({
			name: "test:cookie-policy-reader",
			requires: ["cookiePolicy"] as const,
			contributes: {
				routes: [
					(deps) => {
						seen = deps.cookiePolicy;
						return {
							id: "test-cookie-policy-reader",
							mountPath: "/__test_cookie_policy_reader__",
							handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
						};
					},
				],
			},
		});
		const handle = await createApp({
			modules: [owner, reader],
			bootstrapComponents: {
				config: makeValidCoreConfig(),
				pathResolver: (p: string) => p,
			} as never,
		});
		try {
			expect(seen).toBe(policy);
		} finally {
			await handle.dispose();
		}
	});
});

describe("sessionCookiePolicyContract — the double", () => {
	const cases = sessionCookiePolicyContract({ build: () => createTestSessionCookiePolicy() });

	it("names every rule", () => {
		expect(cases.map((c) => c.name)).toEqual([
			RULES.name,
			RULES.attributes,
			RULES.domain,
			RULES.host,
			RULES.maxAge,
			RULES.frozen,
		]);
	});

	it.each(cases)("$name", async ({ run }) => {
		await run();
	});

	it("keeps them for a cookie shared across subdomains, over plain HTTP in development", async () => {
		expect(
			await failing(() =>
				createTestSessionCookiePolicy({
					name: "auth.session",
					secure: false,
					sameSite: "strict",
					domain: ".example.com",
					maxAgeMs: MAX_DURATION_MS,
				}),
			),
		).toEqual([]);
	});
});

describe("createTestSessionCookiePolicy", () => {
	it("is the fixture configuration's session cookie unless told otherwise", () => {
		expect(createTestSessionCookiePolicy()).toStrictEqual({
			name: "__Host-auth.session",
			secure: true,
			sameSite: "lax",
			domain: undefined,
			maxAgeMs: 3_600_000,
		});
		expect(createTestSessionCookiePolicy({ sameSite: "none" }).sameSite).toBe("none");
	});
});

describe("sessionCookiePolicyContract — each way a policy can break it", () => {
	it("a name that is not a cookie name", async () => {
		for (const name of ["", "auth session", "auth;session", "auth=session", "sessión"]) {
			expect(await failing(() => createTestSessionCookiePolicy({ name }))).toEqual([RULES.name]);
		}
	});

	it("an attribute outside its vocabulary, or a string an environment variable left unread", async () => {
		expect(await failing(() => policyWith({ sameSite: "Lax" }))).toEqual([RULES.attributes]);
		expect(await failing(() => policyWith({ sameSite: undefined }))).toEqual([RULES.attributes]);
		expect(await failing(() => policyWith({ secure: "true", name: "auth.session" }))).toEqual([
			RULES.attributes,
		]);
	});

	it("a domain that is empty, or null where a host-only cookie is undefined", async () => {
		for (const domain of ["", null]) {
			expect(await failing(() => policyWith({ domain, name: "auth.session" }))).toEqual([
				RULES.domain,
			]);
		}
	});

	it("a __Host- name that is not secure, or that names a domain", async () => {
		expect(await failing(() => createTestSessionCookiePolicy({ secure: false }))).toEqual([
			RULES.host,
		]);
		expect(await failing(() => createTestSessionCookiePolicy({ domain: "example.com" }))).toEqual([
			RULES.host,
		]);
	});

	it("a lifetime that is none, not whole, or past the ceiling", async () => {
		for (const maxAgeMs of [0, -1, 1.5, MAX_DURATION_MS + 1, Number.NaN]) {
			expect(await failing(() => createTestSessionCookiePolicy({ maxAgeMs }))).toEqual([
				RULES.maxAge,
			]);
		}
	});

	it("a policy a reader could change under the others", async () => {
		expect(await failing(() => ({ ...createTestSessionCookiePolicy() }))).toEqual([RULES.frozen]);
	});
});
