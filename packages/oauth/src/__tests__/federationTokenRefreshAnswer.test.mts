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

import type { FederationTokens } from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import { readRefreshAnswer } from "#/routes/federationTokenRefreshAnswer.mjs";

// A verdict a newer core may add: the route must not store what it does not know.
vi.mock("@o3co/auth-provider-core", async (importOriginal) => ({
	...(await importOriginal<typeof import("@o3co/auth-provider-core")>()),
	readUpstreamTokenLifetime: () => ({ verdict: "a_verdict_this_route_does_not_know" }),
}));

const stored: FederationTokens = {
	accessToken: "stored-at",
	refreshToken: "stored-rt",
	idToken: undefined,
	expiresAt: new Date(Date.now() - 1000),
	tokenType: "Bearer",
	scope: undefined,
	grantedScope: undefined,
	obtainedAt: undefined,
};

describe("readRefreshAnswer — a lifetime verdict the route does not know", () => {
	it("reads it as a broken lifetime, never as an expiry to store", () => {
		const reading = readRefreshAnswer(
			{ accessToken: "new-at", refreshToken: "rotated-rt", expiresIn: 3600 },
			stored,
			{ calledAt: Date.now(), maxTokenLifetimeMs: 86_400_000 },
		);

		expect(reading.lifetimeIsBroken).toBe(true);
		expect(reading.derivedExpiry).toBeNull();
		expect(reading.rotatedRefreshToken).toBe("rotated-rt");
	});
});
