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
 * The target ceilings read the subject token's audience once per request: the
 * ceiling, the default and the final check all use that one value.
 */

import type { PublicClient, ValidatedToken } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { TOKEN_EXCHANGE_GRANT_TYPE } from "#/grant.mjs";
import { issuedTarget, requestTargets } from "#/targetCeilings.mjs";

const client: PublicClient = {
	clientId: "client-a",
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedRedirectUris: [],
	allowedScopes: ["read"],
	allowedAudiences: ["billing", "inventory"],
	allowedGrantTypes: [TOKEN_EXCHANGE_GRANT_TYPE],
	backchannelLogoutSessionRequired: true,
	frontchannelLogoutSessionRequired: true,
	allowedAzpForFederationToken: false,
};

/** A validated subject whose `aud` answers each read with the next value, then the last. */
function subjectWithShiftingAudience(values: readonly (string | readonly string[])[]): {
	readonly subject: ValidatedToken;
	readonly reads: () => number;
} {
	let reads = 0;
	const subject = {
		sub: "user-1",
		scope: "read",
		claims: { azp: "client-a" },
		get aud() {
			const value = values[Math.min(reads, values.length - 1)];
			reads += 1;
			return value;
		},
	} as ValidatedToken;
	return { subject, reads: () => reads };
}

describe("target ceilings — the subject token's audience is read once", () => {
	it("issues the default the ceiling was built from, never a later value", () => {
		const { subject, reads } = subjectWithShiftingAudience(["billing", "inventory"]);
		const targets = requestTargets({}, {}, client, subject);
		if ("result" in targets) throw new Error(`refused: ${JSON.stringify(targets.result)}`);
		expect([...targets.subjectAudienceSet]).toEqual(["billing"]);
		expect(issuedTarget({}, client, subject, targets, undefined)).toEqual({
			audienceForToken: "billing",
		});
		expect(reads()).toBe(1);
	});

	it("refuses the client's id by default when the first read did not carry it", () => {
		const { subject } = subjectWithShiftingAudience([["billing", "inventory"], "client-a"]);
		const targets = requestTargets({}, {}, client, subject);
		if ("result" in targets) throw new Error(`refused: ${JSON.stringify(targets.result)}`);
		expect(issuedTarget({}, client, subject, targets, undefined)).toEqual({
			result: {
				status: 400,
				error: "invalid_target",
				errorDescription: "audience_widening_not_allowed: client-a",
			},
		});
	});

	it("reads an array audience as a copy, so changing the array afterwards changes nothing", () => {
		const aud = ["billing"];
		const subject = { sub: "user-1", scope: "read", claims: {}, aud } as ValidatedToken;
		const targets = requestTargets({}, {}, client, subject);
		if ("result" in targets) throw new Error(`refused: ${JSON.stringify(targets.result)}`);
		aud[0] = "inventory";
		expect(issuedTarget({}, client, subject, targets, undefined)).toEqual({
			audienceForToken: "billing",
		});
	});
});
