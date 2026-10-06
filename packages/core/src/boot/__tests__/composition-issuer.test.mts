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
 * `compositionIssuer`: the issuer boot's own machinery builds on — the
 * discovery document, the CORS table, a session requirement's pages. The
 * `oauthTokenSettings` slot's when the composition holds it; otherwise the
 * configuration's, which no schema of core's holds to the canonical-issuer
 * rule, so it is read only when it holds and is none otherwise.
 */

import { describe, expect, it } from "vitest";
import { compositionIssuer } from "#/boot/oauth-token-settings.mjs";
import { createTestOAuthTokenSettings } from "#/testing/slots/oauthTokenSettings.mjs";

const withConfigIssuer = (issuer: unknown) => ({ config: { oauth: { jwt: { issuer } } } });

describe("compositionIssuer", () => {
	it("reads the slot's issuer when the composition holds the slot", () => {
		expect(
			compositionIssuer({
				...withConfigIssuer("https://config.example"),
				oauthTokenSettings: createTestOAuthTokenSettings({ issuer: "https://slot.example" }),
			}),
		).toBe("https://slot.example");
	});

	it("reads a canonical configured issuer when the composition holds no slot", () => {
		for (const issuer of [
			"https://auth.example",
			"https://auth.example/t",
			"http://localhost:3000",
		]) {
			expect(compositionIssuer(withConfigIssuer(issuer))).toBe(issuer);
		}
	});

	it("reads none for a configured issuer that is not canonical, or absent", () => {
		for (const issuer of [
			undefined,
			"",
			42,
			"http://auth.example",
			"https://auth.example/",
			"https://auth.example?x=1",
			"https://auth.example#f",
			"https://u:p@auth.example",
			"auth.example",
		]) {
			expect(compositionIssuer(withConfigIssuer(issuer))).toBeUndefined();
		}
		expect(compositionIssuer({})).toBeUndefined();
		expect(compositionIssuer({ config: { oauth: "garbage" } })).toBeUndefined();
	});
});
