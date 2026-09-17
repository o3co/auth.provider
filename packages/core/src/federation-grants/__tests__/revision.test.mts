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
	federationGrantAuthorizationRevision as authorizationRevision,
	federationGrantIdentityRevision as identityRevision,
} from "#/federation-grants/revision.mjs";
import type { FederationGrantConnection } from "#/federation-grants/types.mjs";

const base: FederationGrantConnection = {
	name: "okta-calendar",
	federation: "okta",
	upstreamIssuer: "https://dev-1.okta.test",
	upstreamClientId: "0oa-calendar",
	scopes: ["openid", "offline_access", "calendar.read"],
	resource: "https://api.example/calendar",
	authorizationParams: { prompt: "consent", audience: "calendar" },
	boundary: "prod-eu",
	maxAccessTokenLifetime: 3600,
};

const changed = (patch: Partial<FederationGrantConnection>): FederationGrantConnection => ({
	...base,
	...patch,
});

describe("connection revisions (#593, D4)", () => {
	describe("the persisted format", () => {
		// These two strings are stored on every grant. If a refactor changes what
		// is hashed — the tag, the field order, the algorithm, the encoding —
		// every grant reads as `connection_identity_changed`, which is terminal,
		// and every user loses their delegations. Relative assertions cannot see
		// that; only a known answer can. To change the format on purpose, bump
		// the version in the tag and migrate.
		it("has not changed", () => {
			expect(identityRevision(base)).toBe("wY0fnCik4Pv3TRzT9PJsIIauHR9v9lv9qrEwGmuXaT8");
			expect(authorizationRevision(base)).toBe("vnuJi32na_EWlWJnaWm2RC83JtO0qrywKPD_XIMbCtA");
		});
	});

	describe("identityRevision", () => {
		it("is a stable fingerprint of the upstream issuer and client", () => {
			expect(identityRevision(base)).toMatch(/^[A-Za-z0-9_-]{43}$/);
			expect(identityRevision(base)).toBe(identityRevision({ ...base }));
		});

		it("changes with the upstream issuer, and with the upstream client", () => {
			expect(identityRevision(changed({ upstreamIssuer: "https://dev-2.okta.test" }))).not.toBe(
				identityRevision(base),
			);
			expect(identityRevision(changed({ upstreamClientId: "0oa-other" }))).not.toBe(
				identityRevision(base),
			);
		});

		it("ignores everything that is not identity", () => {
			const same = changed({
				name: "renamed",
				federation: "okta-2",
				scopes: ["openid"],
				resource: undefined,
				authorizationParams: undefined,
				boundary: "staging",
				maxAccessTokenLifetime: 60,
				allowScopeSubsets: false,
			});
			expect(identityRevision(same)).toBe(identityRevision(base));
		});

		it("cannot be collided by moving characters between the two fields", () => {
			const a = changed({ upstreamIssuer: "https://idp.test/a", upstreamClientId: "b" });
			const b = changed({ upstreamIssuer: "https://idp.test/", upstreamClientId: "ab" });
			expect(identityRevision(a)).not.toBe(identityRevision(b));
		});
	});

	describe("authorizationRevision", () => {
		it("is a stable fingerprint, and differs from the identity one", () => {
			expect(authorizationRevision(base)).toMatch(/^[A-Za-z0-9_-]{43}$/);
			expect(authorizationRevision(base)).not.toBe(identityRevision(base));
		});

		it("changes with each field that says what is asked for, and where", () => {
			const before = authorizationRevision(base);
			expect(authorizationRevision(changed({ resource: "https://api.example/files" }))).not.toBe(
				before,
			);
			expect(authorizationRevision(changed({ resource: undefined }))).not.toBe(before);
			expect(authorizationRevision(changed({ boundary: "staging" }))).not.toBe(before);
			expect(
				authorizationRevision(changed({ scopes: [...base.scopes, "calendar.write"] })),
			).not.toBe(before);
			expect(
				authorizationRevision(
					changed({ authorizationParams: { prompt: "consent", audience: "files" } }),
				),
			).not.toBe(before);
			expect(authorizationRevision(changed({ authorizationParams: undefined }))).not.toBe(before);
		});

		it("changes when the scopes are narrowed: asking again is always safe", () => {
			expect(authorizationRevision(changed({ scopes: ["openid", "offline_access"] }))).not.toBe(
				authorizationRevision(base),
			);
		});

		it("does not depend on the order scopes or parameters are written in", () => {
			const reordered = changed({
				scopes: ["calendar.read", "openid", "offline_access"],
				authorizationParams: { audience: "calendar", prompt: "consent" },
			});
			expect(authorizationRevision(reordered)).toBe(authorizationRevision(base));
		});

		it("does not count a scope listed twice as a change", () => {
			expect(authorizationRevision(changed({ scopes: [...base.scopes, "openid"] }))).toBe(
				authorizationRevision(base),
			);
		});

		it("treats no parameters and an empty parameter map alike", () => {
			expect(authorizationRevision(changed({ authorizationParams: {} }))).toBe(
				authorizationRevision(changed({ authorizationParams: undefined })),
			);
		});

		it("cannot be collided by moving characters between fields or list entries", () => {
			expect(authorizationRevision(changed({ scopes: ["a b"] }))).not.toBe(
				authorizationRevision(changed({ scopes: ["a", "b"] })),
			);
			expect(
				authorizationRevision(changed({ resource: "https://r.test/x", boundary: "y" })),
			).not.toBe(authorizationRevision(changed({ resource: "https://r.test/", boundary: "xy" })));
			expect(authorizationRevision(changed({ authorizationParams: { a: "b=c" } }))).not.toBe(
				authorizationRevision(changed({ authorizationParams: { "a=b": "c" } })),
			);
		});

		it("ignores identity, and the settings that are enforced at every disclosure instead", () => {
			const same = changed({
				name: "renamed",
				federation: "okta-2",
				upstreamIssuer: "https://dev-2.okta.test",
				upstreamClientId: "0oa-other",
				// D5 and D10 judge every token against the CURRENT maximum, so a
				// tightened value takes effect on the next call. Putting it here
				// would turn a configuration slip into a reconnect for every user.
				maxAccessTokenLifetime: 60,
				allowScopeSubsets: false,
			});
			expect(authorizationRevision(same)).toBe(authorizationRevision(base));
		});
	});
});
