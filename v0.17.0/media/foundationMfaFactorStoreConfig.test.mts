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
 * The testing entry's builder of the `foundation-mfa-factor-store` section:
 * a configuration fragment under the section's name holding the four URLs it
 * is handed — any other endpoint a fake Store names left behind — and the
 * extra keys a test adds on purpose, which the section's schema then reads.
 */

import { describe, expect, it } from "vitest";
import { foundationMfaFactorStoreSection } from "#/mfa/section.mjs";
import { foundationMfaFactorStoreConfig } from "#/testing/index.mjs";

const URLS = {
	listUrl: "https://store.example/mfa/list",
	createUrl: "https://store.example/mfa/create",
	updateUrl: "https://store.example/mfa/update",
	deleteUrl: "https://store.example/mfa/delete",
};

describe("foundationMfaFactorStoreConfig", () => {
	it("is the section under its module's name, holding the four URLs and nothing else of what it is handed", () => {
		const built = foundationMfaFactorStoreConfig({
			...URLS,
			authenticateUrl: "https://store.example/authenticate",
			markMfaEnrolledUrl: "https://store.example/mfa/enrolled",
		} as typeof URLS);
		expect(built).toEqual({ "foundation-mfa-factor-store": URLS });
		expect(
			foundationMfaFactorStoreSection.schema.safeParse(built["foundation-mfa-factor-store"])
				.success,
		).toBe(true);
	});

	it("leaves out a URL it is not handed, and holds the extra keys it is handed", () => {
		const { deleteUrl: _left, ...rest } = URLS;
		expect(foundationMfaFactorStoreConfig(rest)).toEqual({ "foundation-mfa-factor-store": rest });
		expect(foundationMfaFactorStoreConfig({}, { unknownKey: 1 })).toEqual({
			"foundation-mfa-factor-store": { unknownKey: 1 },
		});
	});
});
