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
 * `sessionCookiePolicyContract` run over core's
 * `createTestSessionCookiePolicy`, whose policies keep every case, and the
 * proof that its cases are not vacuous: each way a policy can break the
 * contract fails the case that names it.
 */

import { MAX_DURATION_MS, type SessionCookiePolicy } from "@o3co/auth-provider-core";
import { createTestSessionCookiePolicy } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { type SessionCookiePolicyContractInput, sessionCookiePolicyContract } from "#/index.mjs";

const RULES = {
	name: "name is a cookie name: a non-empty RFC 6265 token",
	attributes: "sameSite is lax, strict or none, and secure is true or false",
	domain:
		"domain is a cookie domain — a host name, one leading dot allowed — or undefined for a host-only cookie",
	crossSite: "a cookie sent cross-site (sameSite none) is secure",
	host: "a __Host- name is secure and host-only, and a __Secure- name secure",
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

describe("sessionCookiePolicyContract — the double", () => {
	const cases = sessionCookiePolicyContract({ build: () => createTestSessionCookiePolicy() });

	it("names every rule", () => {
		expect(cases.map((c) => c.name)).toEqual([
			RULES.name,
			RULES.attributes,
			RULES.domain,
			RULES.crossSite,
			RULES.host,
			RULES.maxAge,
			RULES.frozen,
		]);
	});

	it.each(cases)("$name", async ({ run }) => {
		await run();
	});

	it("keeps them for a cookie sent cross-site over HTTPS, under either prefix", async () => {
		for (const name of ["__Host-auth.session", "__Secure-auth.session", "auth.session"]) {
			expect(
				await failing(() =>
					createTestSessionCookiePolicy({ name, sameSite: "none", secure: true }),
				),
			).toEqual([]);
		}
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

describe("sessionCookiePolicyContract — each way a policy can break it", () => {
	it("a name that is not a cookie name", async () => {
		for (const name of [
			"",
			"auth session",
			"auth;session",
			"auth=session",
			"sessión",
			42 as unknown as string,
		]) {
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

	it("a domain a cookie cannot carry: a URL, a port, an empty label, a label's edge hyphen, a space", async () => {
		for (const domain of [
			"https://auth.example.com",
			"auth.example.com:8443",
			"example..com",
			"..example.com",
			"-example.com",
			"example-.com",
			"exa mple.com",
			42,
		]) {
			expect(await failing(() => policyWith({ domain, name: "auth.session" }))).toEqual([
				RULES.domain,
			]);
		}
	});

	it("a cookie sent cross-site that is not secure: the browser refuses it", async () => {
		expect(
			await failing(() =>
				createTestSessionCookiePolicy({ name: "auth.session", sameSite: "none", secure: false }),
			),
		).toEqual([RULES.crossSite]);
	});

	it("a __Secure- name, in any case, that is not secure", async () => {
		for (const name of [
			"__Secure-auth.session",
			"__secure-auth.session",
			"__SECURE-auth.session",
		]) {
			expect(await failing(() => createTestSessionCookiePolicy({ name, secure: false }))).toEqual([
				RULES.host,
			]);
		}
	});

	it("a __Host- name, in any case, that is not secure, or that names a domain", async () => {
		for (const name of ["__Host-auth.session", "__host-auth.session", "__HOST-auth.session"]) {
			expect(await failing(() => createTestSessionCookiePolicy({ name, secure: false }))).toEqual([
				RULES.host,
			]);
			expect(
				await failing(() => createTestSessionCookiePolicy({ name, domain: "example.com" })),
			).toEqual([RULES.host]);
		}
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
