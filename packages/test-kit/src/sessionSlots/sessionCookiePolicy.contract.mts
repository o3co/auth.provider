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
 * The contract suite of core's `sessionCookiePolicy` slot.
 * `sessionCookiePolicyContract(input)` holds the policy to what the session
 * configuration and store hold the cookie to, what a browser keeps
 * included (`SameSite=None`, `__Secure-` and `__Host-` names). Core's
 * `createTestSessionCookiePolicy` answers a policy to run it over.
 */

import assert from "node:assert/strict";
import { MAX_DURATION_MS, type SessionCookiePolicy } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
import { unfrozenPath } from "../unfrozenPath.mjs";

export interface SessionCookiePolicyContractInput {
	/** The policy under test, built afresh for each case: a provider's, over the configuration its test chose. */
	readonly build: () => SessionCookiePolicy;
}

/** RFC 6265 §4.1.1: a cookie name is an RFC 2616 token — visible ASCII but separators. */
const COOKIE_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/** A `Domain` a cookie can carry: LDH labels, one leading dot allowed (the `cookie` package's rule). */
const COOKIE_DOMAIN =
	/^([.]?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;

/** RFC 6265bis: browsers match the `__Host-` and `__Secure-` prefixes case-insensitively. */
const HOST_PREFIX = /^__host-/i;
const SECURE_PREFIX = /^__secure-/i;

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
			name: "domain is a cookie domain — a host name, one leading dot allowed — or undefined for a host-only cookie",
			run: async () => {
				const { domain } = build();
				assert.ok(
					domain === undefined || (typeof domain === "string" && COOKIE_DOMAIN.test(domain)),
					`domain ${JSON.stringify(domain)} is neither a cookie domain nor undefined`,
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
				if (SECURE_PREFIX.test(name)) {
					assert.equal(
						secure,
						true,
						"a __Secure- cookie that is not secure is dropped by the browser",
					);
				}
				if (!HOST_PREFIX.test(name)) return;
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
