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
 * `readClientData`: a response's client data as `@simplewebauthn/server` decodes it — a JSON
 * object, or `undefined` for anything else.
 */

import { describe, expect, it } from "vitest";
import { readClientData } from "#/internal/clientData.mjs";
import { nonCanonicalBase64url } from "./softwareAuthenticator.fixture.mjs";

const CLIENT_DATA = {
	type: "webauthn.create",
	challenge: "Y2hhbGxlbmdl",
	origin: "https://test.example",
};

/** `json`'s UTF-8 bytes, in canonical base64url. */
const encoded = (json: string): string => Buffer.from(json).toString("base64url");

describe("readClientData", () => {
	it("answers a JSON object as it decodes", () => {
		expect(readClientData(encoded(JSON.stringify(CLIENT_DATA)))).toEqual(CLIENT_DATA);
	});

	it("answers a JSON object from base64url that is not canonical as the library reads it: a space where an A was", () => {
		const withAnA = { ...CLIENT_DATA, extension: "@@@" };

		expect(
			readClientData(nonCanonicalBase64url(" ")(Buffer.from(JSON.stringify(withAnA)))),
		).toEqual(withAnA);
	});

	it.each([
		["the empty text", ""],
		["an =", "="],
		[
			"a leading space before a JSON object's base64url",
			` ${encoded(JSON.stringify(CLIENT_DATA))}`,
		],
	])("answers undefined for text that does not decode to JSON: %s", (_what, clientDataJSON) => {
		expect(readClientData(clientDataJSON)).toBeUndefined();
	});

	it.each([
		["null", "null"],
		["a number", "7"],
		["a string", '"Y2hhbGxlbmdl"'],
		["an array", '[{"challenge":"Y2hhbGxlbmdl"}]'],
	])("answers undefined for JSON that is not an object: %s", (_what, json) => {
		expect(readClientData(encoded(json))).toBeUndefined();
	});
});
