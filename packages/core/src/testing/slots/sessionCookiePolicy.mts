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
 * The contract suite of the `sessionCookiePolicy` slot (#728) and its test
 * double.
 * `sessionCookiePolicyContract(input)` holds the policy to what the session
 * configuration and the session store module hold the cookie to today: a
 * name that is an RFC 6265 token, `sameSite` of the three and `secure` a
 * boolean, a domain that is a non-empty string or absent, what a browser
 * keeps — a cookie sent cross-site (`sameSite: "none"`) and a `__Secure-`
 * name only secure, a `__Host-` name only secure and host-only — a lifetime
 * of whole milliseconds within the one-year ceiling, and the whole frozen. `createTestSessionCookiePolicy`
 * answers the fixture configuration's session cookie with any attribute
 * replaced; it checks nothing. Published on
 * `@o3co/auth-provider-core/testing`.
 */

import assert from "node:assert/strict";
import type { SessionCookiePolicy } from "../../browser-session/types.mjs";
import { MAX_DURATION_MS } from "../../config/durations.mjs";
import type { ContractCase } from "../../session-admission/testing/requirement.contract.mjs";
import { unfrozenPath } from "./shared.mjs";

export interface SessionCookiePolicyContractInput {
	/** The policy under test, built afresh for each case: a provider's, over the configuration its test chose. */
	readonly build: () => SessionCookiePolicy;
}

/** RFC 6265 §4.1.1: a cookie name is an RFC 2616 token — visible ASCII but separators. */
const COOKIE_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

const SAME_SITE: ReadonlySet<unknown> = new Set(["lax", "strict", "none"]);

/** The cases of the `sessionCookiePolicy` contract over the policy `input` builds. */
export function sessionCookiePolicyContract(
	input: SessionCookiePolicyContractInput,
): readonly ContractCase[] {
	const { build } = input;
	return [
		{
			name: "name is a cookie name: a non-empty RFC 6265 token",
			run: async () => {
				const { name } = build();
				assert.ok(
					typeof name === "string" && COOKIE_NAME.test(name),
					`name ${JSON.stringify(name)} is not a cookie name`,
				);
			},
		},
		{
			name: "sameSite is lax, strict or none, and secure is true or false",
			run: async () => {
				const { sameSite, secure } = build();
				assert.ok(
					SAME_SITE.has(sameSite),
					`sameSite ${String(sameSite)} is not lax, strict or none`,
				);
				assert.equal(typeof secure, "boolean", `secure ${String(secure)} is not true or false`);
			},
		},
		{
			name: "domain is a non-empty string, or undefined for a host-only cookie",
			run: async () => {
				const { domain } = build();
				assert.ok(
					domain === undefined || (typeof domain === "string" && domain.length > 0),
					`domain ${JSON.stringify(domain)} is neither a domain nor undefined`,
				);
			},
		},
		{
			name: "a cookie sent cross-site (sameSite none) is secure",
			run: async () => {
				const { sameSite, secure } = build();
				if (sameSite !== "none") return;
				assert.equal(
					secure,
					true,
					"a SameSite=None cookie that is not secure is refused by the browser",
				);
			},
		},
		{
			name: "a __Host- name is secure and host-only, and a __Secure- name secure",
			run: async () => {
				const { name, secure, domain } = build();
				if (typeof name !== "string") return;
				if (name.startsWith("__Secure-")) {
					assert.equal(
						secure,
						true,
						"a __Secure- cookie that is not secure is dropped by the browser",
					);
				}
				if (!name.startsWith("__Host-")) return;
				assert.equal(secure, true, "a __Host- cookie that is not secure is dropped by the browser");
				assert.equal(
					domain,
					undefined,
					"a __Host- cookie that names a domain is dropped by the browser",
				);
			},
		},
		{
			name: "maxAgeMs is a whole number of milliseconds from 1 to the one-year ceiling",
			run: async () => {
				const { maxAgeMs } = build();
				assert.ok(
					Number.isInteger(maxAgeMs) && maxAgeMs > 0 && maxAgeMs <= MAX_DURATION_MS,
					`maxAgeMs ${String(maxAgeMs)} is not a lifetime`,
				);
			},
		},
		{
			name: "the policy is frozen",
			run: async () => {
				const found = unfrozenPath(build(), "the policy");
				assert.equal(
					found,
					undefined,
					`${found} is not frozen: a module that reads the policy could change it under the others`,
				);
			},
		},
	];
}

/**
 * The fixture configuration's session cookie — `__Host-auth.session`,
 * secure, `lax`, host-only, one hour — with `overrides` applied, frozen.
 */
export function createTestSessionCookiePolicy(
	overrides: Partial<SessionCookiePolicy> = {},
): SessionCookiePolicy {
	return Object.freeze({
		name: "__Host-auth.session",
		secure: true,
		sameSite: "lax",
		domain: undefined,
		maxAgeMs: 3_600_000,
		...overrides,
	});
}
