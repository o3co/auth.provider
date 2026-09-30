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
 * The builder and the reader a test sets and reads the user repository's
 * HTTP settings with (`repositories.user.http`), core's section.
 */

interface WithUserRepository {
	readonly repositories: { readonly user: Readonly<Record<string, unknown>> };
}

/**
 * A copy of `config` whose user repository's `http` block is `http`, every
 * other key of `config` kept; `config` itself is left as it was.
 */
export function withUserRepositoryHttp<C extends WithUserRepository>(
	config: C,
	http: Readonly<Record<string, unknown>>,
): C {
	return {
		...config,
		repositories: {
			...config.repositories,
			user: { ...config.repositories.user, http: { ...http } },
		},
	};
}

/** What `config` holds as the user repository's `http` block, as it holds it. */
export function userRepositoryHttpOf(config: WithUserRepository): unknown {
	return config.repositories.user.http;
}
