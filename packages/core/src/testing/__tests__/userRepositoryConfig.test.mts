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
 * The testing entry's builder and reader of the user repository's HTTP
 * settings (`repositories.user.http`): the builder sets them on a copy of a
 * configuration, every other key kept and the original left as it was; the
 * reader answers what a configuration holds there.
 */

import { describe, expect, it } from "vitest";
import {
	makeValidAppConfig,
	userRepositoryHttpOf,
	withUserRepositoryHttp,
} from "#/testing/index.mjs";

describe("withUserRepositoryHttp", () => {
	it("sets the user repository's http block and keeps every other key", () => {
		const base = {
			...makeValidAppConfig(),
			repositories: {
				client: { yaml: { path: "./clients.yaml" } },
				user: { yaml: { path: "./users.yaml" } },
			},
		};
		const http = { bearerToken: "t", timeout: 300, maxResponseBytes: 1024 };
		const built = withUserRepositoryHttp(base, http);
		expect(built.repositories.user).toEqual({ ...base.repositories.user, http });
		expect(built.repositories.client).toEqual(base.repositories.client);
		const { repositories: _built, ...rest } = built;
		const { repositories: _base, ...baseRest } = base;
		expect(rest).toEqual(baseRest);
	});

	it("sets it on a configuration that holds no repositories", () => {
		const http = { timeout: 300 };
		expect(withUserRepositoryHttp(makeValidAppConfig(), http).repositories).toEqual({
			user: { http },
		});
	});

	it("leaves the configuration it was handed as it was", () => {
		const base = makeValidAppConfig();
		const before = structuredClone(base);
		withUserRepositoryHttp(base, { timeout: 1 });
		expect(base).toEqual(before);
	});
});

describe("userRepositoryHttpOf", () => {
	it("answers the user repository's http block a configuration holds, and nothing where it holds none", () => {
		const http = { bearerToken: "t", timeout: 300 };
		expect(userRepositoryHttpOf(withUserRepositoryHttp(makeValidAppConfig(), http))).toEqual(http);
		expect(userRepositoryHttpOf(makeValidAppConfig())).toBeUndefined();
	});
});
