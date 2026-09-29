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
 * `assertRelocationTombstone`: a tombstone — an old path's
 * `${?VARIABLE}` binding a `reference.conf` keeps after the path moved, so a
 * variable an operator still exports is refused rather than ignored — is for a
 * variable whose name changed with the path. One whose name is what the new
 * path is bound to would refuse the operator who set it correctly.
 */

import { describe, expect, it } from "vitest";
import { assertRelocationTombstone } from "#/testing/index.mjs";

describe("assertRelocationTombstone", () => {
	it("passes a tombstone whose variable is not the one the new path is bound to", () => {
		expect(() =>
			assertRelocationTombstone({
				variable: "OAUTH_DPOP_NONCE_LIFETIME",
				to: "dpop.nonce.lifetime",
			}),
		).not.toThrow();
	});

	it("fails a tombstone whose variable is the new path's own: it would refuse an operator who set it right", () => {
		expect(() =>
			assertRelocationTombstone({
				variable: "REDIS_CONSENT_STORE_KEY_PREFIX",
				to: "redis-consent-store.keyPrefix",
			}),
		).toThrow(/REDIS_CONSENT_STORE_KEY_PREFIX.*redis-consent-store\.keyPrefix/);
	});
});
