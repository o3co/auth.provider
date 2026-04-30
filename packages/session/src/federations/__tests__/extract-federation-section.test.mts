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

import { describe, expect, it } from "vitest";
import { extractFederationSection } from "#/federations/extract-federation-section.mjs";

describe("extractFederationSection", () => {
	it("returns undefined when the federation entry is absent", () => {
		expect(extractFederationSection({}, "google")).toBeUndefined();
	});

	it("returns undefined when enabled is not true", () => {
		const federations = { google: { enabled: false, clientId: "x" } };
		expect(extractFederationSection(federations, "google")).toBeUndefined();
	});

	it("flat shape: defaults type to the federation key when type is omitted", () => {
		const federations = {
			google: { enabled: true, clientId: "id", clientSecret: "s", callbackURL: "cb" },
		};
		const out = extractFederationSection(federations, "google");
		expect(out).toEqual({
			type: "google",
			clientId: "id",
			clientSecret: "s",
			callbackURL: "cb",
		});
	});

	it("flat shape: preserves explicit type", () => {
		const federations = {
			myidp: { enabled: true, type: "oidc", clientId: "id", callbackURL: "cb" },
		};
		const out = extractFederationSection(federations, "myidp");
		expect(out).toMatchObject({ type: "oidc", clientId: "id", callbackURL: "cb" });
	});

	it("nested shape: merges sub-section credentials with top-level passthrough fields", () => {
		const federations = {
			"google-work": {
				enabled: true,
				type: "google",
				audience: "api://corp",
				google: { clientId: "id", clientSecret: "s", callbackURL: "cb" },
			},
		};
		const out = extractFederationSection(federations, "google-work");
		expect(out).toEqual({
			type: "google",
			audience: "api://corp",
			clientId: "id",
			clientSecret: "s",
			callbackURL: "cb",
		});
	});

	it("nested shape: throws on mixed shape (top-level credential + nested sub-section)", () => {
		const federations = {
			google: {
				enabled: true,
				type: "google",
				clientId: "id",
				google: { clientSecret: "s", callbackURL: "cb" },
			},
		};
		expect(() => extractFederationSection(federations, "google")).toThrow(/mixed shape/i);
	});

	it("control fields (enabled, type, [type]) do not leak into the merged result", () => {
		const federations = {
			"google-work": {
				enabled: true,
				type: "google",
				google: { clientId: "id", callbackURL: "cb" },
			},
		};
		const out = extractFederationSection(federations, "google-work");
		expect(out).not.toHaveProperty("enabled");
		expect(out?.google).toBeUndefined();
		expect(out?.type).toBe("google");
	});

	it("returns undefined for non-object entries (defensive)", () => {
		expect(extractFederationSection({ google: null }, "google")).toBeUndefined();
		expect(extractFederationSection({ google: "string" }, "google")).toBeUndefined();
		expect(extractFederationSection({ google: [] }, "google")).toBeUndefined();
	});
});
