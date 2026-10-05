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
 * What an `oauth.authorize.acrValues` key may be: exactly the names an
 * `acr_values` request can carry as one value, refused in one wording.
 */

import { describe, expect, it } from "vitest";
import { checkAcrValueName } from "#/config/acr-values.mjs";
import { readSpaceDelimitedParameter } from "#/federations/scope.mjs";

describe("checkAcrValueName — an acr value name /authorize can be asked for", () => {
	const usable = ["urn:o3co:acr:mfa", "urn:o3co:acr:phr", "1", "!#$%&'()*+,-./:;<=>?@[]^_`{|}~"];
	const unusable = [
		"",
		"urn:x pwd",
		" urn:x",
		"urn:x\tpwd",
		"urn:x\n",
		'urn:"x"',
		"urn:x\\y",
		"urn:\u00e9",
		"urn:x\u007f",
		"urn:x\u0000",
	];

	it.each(usable)("accepts %j", (name) => {
		expect(checkAcrValueName(name)).toBeNull();
	});

	it.each(unusable)("refuses %j", (name) => {
		expect(checkAcrValueName(name)).not.toBeNull();
	});

	it("accepts exactly the names an acr_values request can carry as one value", () => {
		for (const name of [...usable, ...unusable]) {
			const requested = readSpaceDelimitedParameter(name);
			const requestable = requested?.length === 1 && requested[0] === name;
			expect(checkAcrValueName(name) === null, JSON.stringify(name)).toBe(requestable);
		}
	});

	it("names the key, as JSON, and the path, and says what a key may hold", () => {
		expect(checkAcrValueName("urn:x\tpwd")).toBe(
			'oauth.authorize.acrValues key "urn:x\\tpwd" can never be requested: /authorize reads acr_values as space-delimited RFC 6749 §3.3 scope-tokens, so a key is one or more printable ASCII characters other than the space, " and \\',
		);
	});
});
