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

import { describe, expect, it } from "vitest";
import {
	type FederationGrant,
	type FederationGrantAuthorization,
	type FederationGrantBase,
	hasFederationGrantAuthorization,
} from "#/federation-grants/types.mjs";

const at = new Date("2026-09-18T00:00:00.000Z");

const base: FederationGrantBase = {
	id: "g-1",
	subject: "u-1",
	clientId: "agent",
	connection: "okta-calendar",
	createdAt: at,
	version: 1,
};

const authorization: FederationGrantAuthorization = {
	identityRevision: "i",
	authorizationRevision: "a",
	upstream: { issuer: "https://dev-1.okta.test", subject: "00u-alice" },
	scopes: ["openid"],
	consent: { at, sid: "sid-1", scopes: ["openid"] },
	authorizedAt: at,
	expiresAt: new Date(at.getTime() + 86_400_000),
	resource: undefined,
};

describe("FederationGrant — the shapes the union admits (#593, D1)", () => {
	it("admits a grant revoked while pending, which has no authorization to keep", () => {
		const grant: FederationGrant = {
			...base,
			status: "revoked",
			revocation: { by: "subject", at },
		};
		expect(hasFederationGrantAuthorization(grant)).toBe(false);
	});

	it("admits a grant revoked after it was authorized, with every authorization field", () => {
		const grant: FederationGrant = {
			...base,
			...authorization,
			lastUsedAt: undefined,
			ineligible: undefined,
			refreshFailure: undefined,
			status: "revoked",
			revocation: { by: "client", at },
		};
		expect(hasFederationGrantAuthorization(grant)).toBe(true);
		if (hasFederationGrantAuthorization(grant)) {
			expect(grant.expiresAt.getTime()).toBeGreaterThan(grant.consent.at.getTime());
		}
	});

	it("refuses, at compile time, a revoked grant with only some of the authorization fields", () => {
		// Without the `never` members on the never-authorized shape this
		// compiled, `hasFederationGrantAuthorization` answered true for it, and
		// `grant.expiresAt.getTime()` threw at run time.
		// @ts-expect-error — `consent` without the rest is neither revoked shape
		const partial: FederationGrant = {
			...base,
			status: "revoked",
			revocation: { by: "client", at },
			consent: authorization.consent,
		};
		expect(partial.status).toBe("revoked");
	});

	it("refuses, at compile time, a pending grant that carries authorization fields", () => {
		// @ts-expect-error — a pending grant has not been authorized
		const pending: FederationGrant = { ...base, ...authorization, status: "pending" };
		expect(pending.status).toBe("pending");
	});

	it("does not take an explicitly undefined consent for an authorization", () => {
		// The limit of the type, pinned: without `exactOptionalPropertyTypes`,
		// which this repository does not enable, `consent?: never` still admits
		// `consent: undefined` — so this compiles, with no cast. `"consent" in
		// grant` is true for such a record; the narrowing must not be.
		const junk: FederationGrant = {
			...base,
			status: "revoked",
			revocation: { by: "client", at },
			consent: undefined,
		};
		expect(hasFederationGrantAuthorization(junk)).toBe(false);
	});
});
