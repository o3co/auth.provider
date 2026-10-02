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
 * runs over its own file. The two rate-limit variables are named after the
 * paths they set; their old names are declared renamed and bound nowhere. The
 * removed `allowCredentialsForKnownUser` is declared removed, and its variable
 * is bound nowhere.
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
			modules.map((module) => [module.name, module.section !== undefined, module.section?.at]),
		).toEqual([
			["webauthn", true, undefined],
			["webauthn-mfa-factor", true, undefined],
		]);
	});

	it("is declared by each of them and holds only their sections, which their schemas parse without losing a path", () => {
		expect(packageReferenceProblems({ reference: REFERENCE, modules, read })).toEqual([]);
	});

	it("declares the two rate-limit variables renamed to the names their paths derive, and the removed key's variable", () => {
		expect(webauthnModule.section?.renamedVariables).toEqual({
			WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT: "webauthn.rateLimit.authenticationOptions.limit",
			WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_WINDOW_SECONDS:
				"webauthn.rateLimit.authenticationOptions.windowSeconds",
			WEBAUTHN_ALLOW_CREDENTIALS_FOR_KNOWN_USER: "webauthn.allowCredentialsForKnownUser",
		});
	});

	it("declares allowCredentialsForKnownUser removed, and binds its variable nowhere", () => {
		expect(webauthnModule.section?.relocatedFrom).toEqual({
			"webauthn.allowCredentialsForKnownUser": null,
		});
		const tree = read(new URL(REFERENCE).pathname, {
			WEBAUTHN_ALLOW_CREDENTIALS_FOR_KNOWN_USER: "true",
		}) as { webauthn: Record<string, unknown> };
		expect(tree.webauthn).not.toHaveProperty("allowCredentialsForKnownUser");
	});

	it.each([
		["WEBAUTHN_RATE_LIMIT_AUTHENTICATION_OPTIONS_LIMIT", "limit"],
		["WEBAUTHN_RATE_LIMIT_AUTHENTICATION_OPTIONS_WINDOW_SECONDS", "windowSeconds"],
	])("reads %s at webauthn.rateLimit.authenticationOptions.%s", (variable, key) => {
		const tree = read(new URL(REFERENCE).pathname, { [variable]: "7" }) as {
			webauthn: { rateLimit: { authenticationOptions: Record<string, unknown> } };
		};
		expect(tree.webauthn.rateLimit.authenticationOptions[key]).toBe("7");
	});
});
