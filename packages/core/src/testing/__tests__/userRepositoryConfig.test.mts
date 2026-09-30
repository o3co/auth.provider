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
 * The testing entry's builder of the user repository's HTTP settings:
 * `repositories.user.http` set, everything else of the configuration kept,
 * the configuration handed in left as it was.
 */

import { describe, expect, it } from "vitest";
import { makeValidAppConfig, withUserRepositoryHttp } from "#/testing/index.mjs";

describe("withUserRepositoryHttp", () => {
	it("sets the user repository's http block and keeps every other key", () => {
		const base = makeValidAppConfig();
		const http = { bearerToken: "t", timeout: 300, maxResponseBytes: 1024 };
		const built = withUserRepositoryHttp(base, http);
		expect(built.repositories.user).toEqual({ ...base.repositories.user, http });
		expect(built.repositories.client).toEqual(base.repositories.client);
		expect(built.repositories.code).toEqual(base.repositories.code);
		const { repositories: _built, ...rest } = built;
		const { repositories: _base, ...baseRest } = base;
		expect(rest).toEqual(baseRest);
	});

	it("leaves the configuration it was handed as it was", () => {
		const base = makeValidAppConfig();
		const before = structuredClone(base);
		withUserRepositoryHttp(base, { timeout: 1 });
		expect(base).toEqual(before);
	});
});
