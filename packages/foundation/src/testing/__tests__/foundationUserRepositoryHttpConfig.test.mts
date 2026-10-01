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
 * The testing entry's builder of the user repository's `http` block: the
 * Store URLs the `"http"` builder reads, taken from what it is handed — any
 * other endpoint a fake Store names left behind — and the extra keys a test
 * adds on purpose. A composition places the block with core's
 * `withUserRepositoryHttp`.
 */

import {
	createAdapterFactory,
	supportsMfaEnrollmentWitness,
	type UserRepository,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { registerBuiltinAdapters } from "#/index.mjs";
import { foundationUserRepositoryHttpConfig } from "#/testing/index.mjs";

const URLS = {
	authenticateUrl: "https://store.example/authenticate",
	authenticateByTokenUrl: "https://store.example/authenticate-by-token",
	linkFederatedIdentityUrl: "https://store.example/link",
	findSubjectByFederatedIdentityUrl: "https://store.example/find",
	markMfaEnrolledUrl: "https://store.example/mfa/enrolled",
};

describe("foundationUserRepositoryHttpConfig", () => {
	it("holds the user repository's URLs and nothing else of what it is handed", () => {
		expect(
			foundationUserRepositoryHttpConfig({
				...URLS,
				listUrl: "https://store.example/mfa/list",
				deleteUrl: "https://store.example/mfa/delete",
			} as typeof URLS),
		).toEqual(URLS);
	});

	it("leaves out a URL it is not handed, and holds the extra keys it is handed", () => {
		const { markMfaEnrolledUrl: _left, ...rest } = URLS;
		expect(foundationUserRepositoryHttpConfig(rest)).toEqual(rest);
		expect(foundationUserRepositoryHttpConfig({}, { timeout: 1000 })).toEqual({ timeout: 1000 });
	});

	it("is a block the http builder takes: the witness URL handed, the repository writes the witness", async () => {
		const userFactory = createAdapterFactory<UserRepository>("UserRepository");
		registerBuiltinAdapters({ userFactory });
		const built = await userFactory.create({
			...foundationUserRepositoryHttpConfig(URLS, { timeout: 1000 }),
			type: "http",
		});
		expect(supportsMfaEnrollmentWitness(built)).toBe(true);
	});
});
