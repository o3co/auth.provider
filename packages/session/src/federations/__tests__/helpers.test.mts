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

// The GitHub email fetch is the GitHub adapter's (github.mts, over
// oidc.fetchProtectedResource) and is covered by its github.test.mts.
// validateRedirect / resolveCallbackRedirect are exercised through the redirect
// policy, in redirect-policy.test.mts.

import { describe, test } from "vitest";

describe("helpers", () => {
	test.todo("fetchGithubPrimaryEmail removed (I-3) — email-fetch logic covered by github.test.mts");
});
