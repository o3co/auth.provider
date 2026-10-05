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
 * An upstream refresh answer whose `token_type` is far longer than any type
 * is read as a broken type, and the rotated refresh token is still read so
 * the route can record it.
 */

import type { FederationTokens } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { readRefreshAnswer } from "#/routes/federationTokenRefreshAnswer.mjs";

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

describe("readRefreshAnswer — an oversized token_type", () => {
	it("reads the type as broken and keeps the rotated refresh token, without throwing", () => {
		const reading = readRefreshAnswer(
			{
				accessToken: "new-at",
				refreshToken: "rotated-rt",
				expiresIn: 3600,
				tokenType: "a".repeat(10_000_000),
			},
			stored,
			{ calledAt: Date.now(), maxTokenLifetimeMs: 86_400_000 },
		);
		expect(reading.tokenTypeIsBroken).toBe(true);
		expect(reading.rotatedRefreshToken).toBe("rotated-rt");
	});
});
