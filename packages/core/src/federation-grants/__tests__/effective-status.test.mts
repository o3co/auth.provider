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
	coveredByRevocationBoundary,
	type EffectiveFederationGrantStatusContext,
	effectiveFederationGrantStatus,
} from "#/federation-grants/effective-status.mjs";
import {
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
} from "#/federation-grants/revision.mjs";
import type {
	AuthorizedFederationGrant,
	FederationGrant,
	FederationGrantConnection,
} from "#/federation-grants/types.mjs";

const DAY = 86_400_000;
const CONSENT = new Date("2026-09-18T00:00:00.000Z");
const INVALID = new Date(Number.NaN);
const at = (ms: number) => new Date(CONSENT.getTime() + ms);

const connection: FederationGrantConnection = {
	name: "okta-calendar",
	federation: "okta",
	upstreamIssuer: "https://dev-1.okta.test",
	upstreamClientId: "0oa-calendar",
	scopes: ["openid", "offline_access", "calendar.read"],
	boundary: "prod-eu",
	maxAccessTokenLifetime: 3600,
};

const active: AuthorizedFederationGrant = {
	id: "g-1",
	status: "active",
	subject: "u-1",
	clientId: "agent",
	connection: "okta-calendar",
	createdAt: CONSENT,
	version: 3,
	identityRevision: federationGrantIdentityRevision(connection),
	authorizationRevision: federationGrantAuthorizationRevision(connection),
	upstream: { issuer: "https://dev-1.okta.test", subject: "00u-alice" },
	scopes: connection.scopes,
	consent: { at: CONSENT, sid: "sid-1", scopes: connection.scopes },
	authorizedAt: at(60_000),
	expiresAt: at(30 * DAY),
};

const needsUser: FederationGrant = { ...active, status: "reauthorization_required" };

const context: EffectiveFederationGrantStatusContext = {
	now: at(DAY),
	connection,
	maxExpiresInMs: 90 * DAY,
	grantsBoundary: null,
	revocationSkewMs: 1_000,
	credentials: "ok",
};

describe("coveredByRevocationBoundary (#593, D13)", () => {
	it("covers a consent given before the boundary, and one given at it", () => {
		expect(coveredByRevocationBoundary(at(-1), CONSENT, 0)).toBe(true);
		expect(coveredByRevocationBoundary(CONSENT, CONSENT, 0)).toBe(true);
		expect(coveredByRevocationBoundary(at(1), CONSENT, 0)).toBe(false);
	});

	it("adds the skew allowance, inclusively", () => {
		expect(coveredByRevocationBoundary(at(1_000), CONSENT, 1_000)).toBe(true);
		expect(coveredByRevocationBoundary(at(1_001), CONSENT, 1_000)).toBe(false);
	});

	it("reads a negative allowance as none: it must never pull the boundary back", () => {
		expect(coveredByRevocationBoundary(CONSENT, CONSENT, -5_000)).toBe(true);
		expect(coveredByRevocationBoundary(at(-1), CONSENT, -5_000)).toBe(true);
	});

	it("covers nothing when the subject has no boundary in force", () => {
		expect(coveredByRevocationBoundary(CONSENT, null, 1_000)).toBe(false);
	});

	it("throws on a value it cannot compare, and answers neither way", () => {
		// "Not covered" would switch the backstop off — for every grant, if the
		// skew is what is wrong. "Covered" would revoke durably on a corrupt
		// value. Neither is a finding: it is an outage, and the caller answers 503.
		expect(() => coveredByRevocationBoundary(CONSENT, INVALID, 1_000)).toThrow(RangeError);
		expect(() => coveredByRevocationBoundary(INVALID, CONSENT, 1_000)).toThrow(RangeError);
		expect(() => coveredByRevocationBoundary(CONSENT, CONSENT, Number.NaN)).toThrow(RangeError);
		expect(() => coveredByRevocationBoundary(INVALID, null, 1_000)).toThrow(RangeError);
	});
});

describe("effectiveFederationGrantStatus (#593, D1)", () => {
	it("is active when nothing stands in the way", () => {
		expect(effectiveFederationGrantStatus(active, context)).toEqual({ status: "active" });
	});

	it("reports the stored states as they are", () => {
		const pending: FederationGrant = {
			id: "g-0",
			status: "pending",
			subject: "u-1",
			clientId: "agent",
			connection: "okta-calendar",
			createdAt: CONSENT,
			version: 1,
		};
		expect(effectiveFederationGrantStatus(pending, context)).toEqual({ status: "pending" });

		const revoked: FederationGrant = {
			...active,
			status: "revoked",
			revocation: { by: "client", at: at(DAY) },
		};
		expect(effectiveFederationGrantStatus(revoked, context)).toEqual({
			status: "revoked",
			reason: "client",
		});

		const revokedWhilePending: FederationGrant = {
			...pending,
			status: "revoked",
			revocation: { by: "subject", at: at(DAY) },
		};
		expect(effectiveFederationGrantStatus(revokedWhilePending, context)).toEqual({
			status: "revoked",
			reason: "subject",
		});

		expect(effectiveFederationGrantStatus(needsUser, context)).toEqual({
			status: "reauthorization_required",
			reason: "upstream_invalid_grant",
		});
	});

	it("does not apply the backstop to a pending grant: it has no consent to date", () => {
		const pending: FederationGrant = {
			id: "g-0",
			status: "pending",
			subject: "u-1",
			clientId: "agent",
			connection: "okta-calendar",
			createdAt: CONSENT,
			version: 1,
		};
		expect(
			effectiveFederationGrantStatus(pending, { ...context, grantsBoundary: at(10 * DAY) }),
		).toEqual({ status: "pending" });
	});

	it("reads expiry off the clock, and says which bound ended the grant", () => {
		expect(effectiveFederationGrantStatus(active, { ...context, now: at(30 * DAY) })).toEqual({
			status: "expired",
			reason: "consented_lifetime",
		});
		expect(
			effectiveFederationGrantStatus(active, {
				...context,
				now: at(20 * DAY),
				maxExpiresInMs: 10 * DAY,
			}),
		).toEqual({ status: "expired", reason: "operator_maximum" });
	});

	it("treats a consent the grants boundary covers as revoked by the backstop", () => {
		expect(
			effectiveFederationGrantStatus(active, { ...context, grantsBoundary: at(1_000) }),
		).toEqual({ status: "revoked", reason: "backstop" });
		expect(
			effectiveFederationGrantStatus(active, { ...context, grantsBoundary: at(-5_000) }),
		).toEqual({ status: "active" });
	});

	it("lets an unreadable boundary surface as an error, not as a status", () => {
		expect(() =>
			effectiveFederationGrantStatus(active, { ...context, grantsBoundary: INVALID }),
		).toThrow(RangeError);
	});

	it("reads a changed upstream identity as terminal, and any other connection change as a reauthorization", () => {
		const newClient = { ...connection, upstreamClientId: "0oa-rotated" };
		expect(effectiveFederationGrantStatus(active, { ...context, connection: newClient })).toEqual({
			status: "connection_identity_changed",
		});

		const newBoundary = { ...connection, boundary: "staging" };
		expect(effectiveFederationGrantStatus(active, { ...context, connection: newBoundary })).toEqual(
			{ status: "reauthorization_required", reason: "connection_changed" },
		);
	});

	it("reports a credential that does not open under the current key ring", () => {
		expect(
			effectiveFederationGrantStatus(active, { ...context, credentials: "unreadable" }),
		).toEqual({ status: "reauthorization_required", reason: "credential_unreadable" });
	});

	describe("an upstream that stopped issuing eligible tokens", () => {
		const starved: AuthorizedFederationGrant = {
			...active,
			ineligible: { reason: "scope_exceeded", at: at(DAY - 60_000), judgedAgainst: 3600 },
		};

		it("is reported for as long as the marker stands", () => {
			expect(effectiveFederationGrantStatus(starved, context)).toEqual({
				status: "upstream_token_ineligible",
				reason: "scope_exceeded",
			});
		});

		it("is still reported after the retry interval: the grant must never read as active while it cannot yield a token", () => {
			expect(effectiveFederationGrantStatus(starved, { ...context, now: at(10 * DAY) })).toEqual({
				status: "upstream_token_ineligible",
				reason: "scope_exceeded",
			});
		});

		it("is void once the operator changes the maximum it was judged against", () => {
			expect(
				effectiveFederationGrantStatus(starved, {
					...context,
					connection: { ...connection, maxAccessTokenLifetime: 7200 },
				}),
			).toEqual({ status: "active" });
		});

		it("gives way to what a reauthorization mends, since that clears the marker too", () => {
			expect(
				effectiveFederationGrantStatus(starved, { ...context, credentials: "unreadable" }),
			).toEqual({ status: "reauthorization_required", reason: "credential_unreadable" });
		});
	});

	describe("a maximum no token can satisfy", () => {
		// A hand-built config bypasses the schema (#448). Under such a maximum
		// `judgeUpstreamAccessToken` refuses every token, so the grant cannot
		// yield one, and D9 says such a grant never reads as `active`.
		const unusable = [Number.NaN, undefined as unknown as number, 0, -1, Number.POSITIVE_INFINITY];
		const under = (maxAccessTokenLifetime: number) => ({
			...context,
			connection: { ...connection, maxAccessTokenLifetime },
		});

		it("reads as ineligible before any refresh has found that out", () => {
			for (const bad of unusable) {
				expect(effectiveFederationGrantStatus(active, under(bad))).toEqual({
					status: "upstream_token_ineligible",
					reason: "lifetime_over_maximum",
				});
			}
		});

		it("names the maximum, whatever an older marker was left for: that is what /token answers", () => {
			const starved: AuthorizedFederationGrant = {
				...active,
				ineligible: { reason: "scope_exceeded", at: at(DAY - 60_000), judgedAgainst: 3600 },
			};
			for (const bad of unusable) {
				expect(effectiveFederationGrantStatus(starved, under(bad))).toEqual({
					status: "upstream_token_ineligible",
					reason: "lifetime_over_maximum",
				});
			}
		});

		it("still gives way to everything above it in the order", () => {
			expect(
				effectiveFederationGrantStatus(active, {
					...under(Number.NaN),
					credentials: "unreadable",
				}),
			).toEqual({ status: "reauthorization_required", reason: "credential_unreadable" });
		});
	});

	describe("a connection that is no longer configured", () => {
		// The operator removed `federationGrants.connections.<name>`. Nothing can
		// be compared with a connection that is not there, and nothing about the
		// grant has changed: putting the entry back restores it.
		const removed = { ...context, connection: undefined };

		it("is reported as such: not as a changed identity, which removing an entry does not establish", () => {
			expect(effectiveFederationGrantStatus(active, removed)).toEqual({
				status: "connection_not_configured",
			});
			expect(effectiveFederationGrantStatus(needsUser, removed)).toEqual({
				status: "connection_not_configured",
			});
		});

		it("gives way to every terminal fact: a configuration remedy must not be offered for a grant that is over", () => {
			const revoked: FederationGrant = {
				...active,
				status: "revoked",
				revocation: { by: "client", at: at(DAY) },
			};
			expect(effectiveFederationGrantStatus(revoked, removed)).toEqual({
				status: "revoked",
				reason: "client",
			});
			expect(
				effectiveFederationGrantStatus(active, { ...removed, grantsBoundary: at(1_000) }),
			).toEqual({ status: "revoked", reason: "backstop" });
			expect(effectiveFederationGrantStatus(active, { ...removed, now: at(30 * DAY) })).toEqual({
				status: "expired",
				reason: "consented_lifetime",
			});
		});

		it("does not concern a pending grant, which is compared with nothing yet", () => {
			const pending: FederationGrant = {
				id: "g-0",
				status: "pending",
				subject: "u-1",
				clientId: "agent",
				connection: "okta-calendar",
				createdAt: CONSENT,
				version: 1,
			};
			expect(effectiveFederationGrantStatus(pending, removed)).toEqual({ status: "pending" });
		});
	});

	describe("order — what cannot be undone is reported first", () => {
		const everything: EffectiveFederationGrantStatusContext = {
			...context,
			now: at(30 * DAY),
			grantsBoundary: at(1_000),
			connection: { ...connection, upstreamClientId: "0oa-rotated", boundary: "staging" },
			credentials: "unreadable",
		};

		it("a stored revocation hides everything else", () => {
			const revoked: FederationGrant = {
				...active,
				status: "revoked",
				revocation: { by: "operator", at: at(DAY) },
			};
			expect(effectiveFederationGrantStatus(revoked, everything)).toEqual({
				status: "revoked",
				reason: "operator",
			});
		});

		it("the backstop comes before expiry: a revocation must not be reported as mere expiry", () => {
			expect(effectiveFederationGrantStatus(active, everything)).toEqual({
				status: "revoked",
				reason: "backstop",
			});
		});

		it("then the terminal expiry, then the identity change, then what a reauthorization can mend", () => {
			expect(
				effectiveFederationGrantStatus(active, { ...everything, grantsBoundary: null }),
			).toEqual({ status: "expired", reason: "consented_lifetime" });
			expect(
				effectiveFederationGrantStatus(active, {
					...everything,
					grantsBoundary: null,
					now: at(DAY),
				}),
			).toEqual({ status: "connection_identity_changed" });
			expect(
				effectiveFederationGrantStatus(active, {
					...everything,
					grantsBoundary: null,
					now: at(DAY),
					connection: { ...connection, boundary: "staging" },
				}),
			).toEqual({ status: "reauthorization_required", reason: "connection_changed" });
		});

		describe("a grant that already needs the user", () => {
			it("is still revoked by the backstop", () => {
				expect(
					effectiveFederationGrantStatus(needsUser, { ...context, grantsBoundary: at(1_000) }),
				).toEqual({ status: "revoked", reason: "backstop" });
			});

			it("reads as expired once it has expired: /reauthorize refuses an expired grant", () => {
				expect(
					effectiveFederationGrantStatus(needsUser, { ...context, now: at(30 * DAY) }),
				).toEqual({ status: "expired", reason: "consented_lifetime" });
			});

			it("reads as an identity change when the upstream client changed: a reauthorization could never pass its account check", () => {
				expect(
					effectiveFederationGrantStatus(needsUser, {
						...context,
						connection: { ...connection, upstreamClientId: "0oa-rotated" },
					}),
				).toEqual({ status: "connection_identity_changed" });
			});
		});
	});
});
