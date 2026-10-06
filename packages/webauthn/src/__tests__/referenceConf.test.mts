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
 * The package's `config/reference.conf`: the modules that read it — the
 * grant's and the second factor's — declare it as their section's reference,
 * and it holds only their sections, which their section schemas parse
 * without losing a path —
 * core's `packageReferenceProblems`, the check every package with defaults
 * runs over its own file. The removed `allowCredentialsForKnownUser` and
 * `rateLimit` are declared removed, and their variables, the older rate-limit
 * names included, are captured and bound nowhere.
 */

import { packageReferenceProblems } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { webauthnMfaFactorModule } from "#/mfaFactor/module.mjs";
import { webauthnModule } from "#/module.mjs";

/** The package's defaults, as a composition root finds them. */
const REFERENCE = new URL("../../config/reference.conf", import.meta.url);

describe("the package's config/reference.conf", () => {
	const modules = [webauthnModule, webauthnMfaFactorModule];
	const read = (path: string, env: Readonly<Record<string, string>>): unknown =>
		parseFile(path, { env: { ...env } }).toObject();

	it("is read at the section named after its module", () => {
		expect(
			modules.map((module) => [
				module.name,
				module.section !== undefined,
				Object.hasOwn(module.section ?? {}, "at"),
			]),
		).toEqual([
			["webauthn", true, false],
			["webauthn-mfa-factor", true, false],
		]);
	});

	it("is declared by each of them and holds only their sections, which their schemas parse without losing a path, once the operator names the relying party", () => {
		const withRelyingParty = (path: string, env: Readonly<Record<string, string>>): unknown =>
			read(path, {
				WEBAUTHN_RP_ID: "example.com",
				WEBAUTHN_RP_NAME: "Example App",
				WEBAUTHN_ORIGIN: "https://example.com",
				...env,
			});
		expect(
			packageReferenceProblems({ reference: REFERENCE, modules, read: withRelyingParty }),
		).toEqual([]);
	});

	it("leaves exactly the relying party to the operator: with no variable set, only its three keys are refused", () => {
		expect(packageReferenceProblems({ reference: REFERENCE, modules, read })).toEqual([
			expect.stringMatching(/^webauthn\.origin: refused by module "webauthn"'s section schema/),
			expect.stringMatching(/^webauthn\.rpId: refused by module "webauthn"'s section schema/),
			expect.stringMatching(/^webauthn\.rpName: refused by module "webauthn"'s section schema/),
		]);
	});

	it("declares each removed key's variables, the older rate-limit names included", () => {
		expect(webauthnModule.section?.renamedVariables).toEqual({
			WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT: "webauthn.rateLimit.authenticationOptions.limit",
			WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_WINDOW_SECONDS:
				"webauthn.rateLimit.authenticationOptions.windowSeconds",
			WEBAUTHN_RATE_LIMIT_AUTHENTICATION_OPTIONS_LIMIT:
				"webauthn.rateLimit.authenticationOptions.limit",
			WEBAUTHN_RATE_LIMIT_AUTHENTICATION_OPTIONS_WINDOW_SECONDS:
				"webauthn.rateLimit.authenticationOptions.windowSeconds",
			WEBAUTHN_ALLOW_CREDENTIALS_FOR_KNOWN_USER: "webauthn.allowCredentialsForKnownUser",
		});
	});

	it("declares allowCredentialsForKnownUser and rateLimit removed, and binds their variables nowhere", () => {
		expect(webauthnModule.section?.relocatedFrom).toEqual({
			"webauthn.allowCredentialsForKnownUser": null,
			"webauthn.rateLimit": null,
		});
		const tree = read(new URL(REFERENCE).pathname, {
			WEBAUTHN_ALLOW_CREDENTIALS_FOR_KNOWN_USER: "true",
		}) as { webauthn: Record<string, unknown> };
		expect(tree.webauthn).not.toHaveProperty("allowCredentialsForKnownUser");
	});

	it.each([
		"WEBAUTHN_RATE_LIMIT_AUTHENTICATION_OPTIONS_LIMIT",
		"WEBAUTHN_RATE_LIMIT_AUTHENTICATION_OPTIONS_WINDOW_SECONDS",
		"WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT",
		"WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_WINDOW_SECONDS",
	])("binds %s nowhere in the section, and captures it", (variable) => {
		const tree = read(new URL(REFERENCE).pathname, { [variable]: "7" }) as {
			webauthn: Record<string, unknown>;
			"renamed-variables": Record<string, unknown>;
		};
		expect(tree.webauthn).not.toHaveProperty("rateLimit");
		expect(tree["renamed-variables"][variable]).toBe("7");
	});
});
