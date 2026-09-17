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

import { federationGrantIneligibilityStands } from "./eligibility.mjs";
import { federationGrantExpiryState } from "./lifetime.mjs";
import {
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
} from "./revision.mjs";
import type {
	EffectiveFederationGrantStatus,
	FederationGrant,
	FederationGrantConnection,
} from "./types.mjs";

/**
 * Whether a subject's revocation boundary covers an instant (#593, D13): a
 * grant's consent against the grants boundary, and a session's authentication
 * against the sessions boundary (D7).
 *
 * For a grant it is the consent that is compared. Not a token's `iat`: a token
 * minted from a surviving grant is always fresh. And not `authorizedAt`: the
 * consent precedes the callback by up to ten minutes, and a callback that
 * lands just after the boundary must not hide a consent given before it.
 *
 * Inclusive, with the allowance the token check in `jwt/verify.mts` gives the
 * same boundary (`subjectRevocationSkewMs`, one second) — and not the
 * five-minute `clockSkewMs`, which would refuse the re-login a revocation
 * sends the user to. A negative allowance reads as none. `null` is a subject
 * with no boundary in force.
 *
 * A value that cannot be compared is thrown, and answered neither way. "Not
 * covered" would switch the backstop off — for every grant at once, if the
 * allowance is what is wrong, since `Math.max(0, NaN)` is NaN. "Covered"
 * would revoke durably because of a corrupt value. It is an outage, and the
 * caller answers 503, as `verifyJwt` does for a boundary it cannot read.
 */
export function coveredByRevocationBoundary(
	instant: Date,
	boundary: Date | null,
	skewMs: number,
): boolean {
	if (Number.isNaN(instant.getTime())) {
		throw new RangeError("coveredByRevocationBoundary: the instant is not a valid date");
	}
	if (boundary === null) return false;
	if (Number.isNaN(boundary.getTime())) {
		throw new RangeError("coveredByRevocationBoundary: the boundary is not a valid date");
	}
	if (!Number.isFinite(skewMs)) {
		throw new RangeError("coveredByRevocationBoundary: skewMs must be a finite number");
	}
	return instant.getTime() <= boundary.getTime() + Math.max(0, skewMs);
}

export interface EffectiveFederationGrantStatusContext {
	readonly now: Date;
	/** The connection as it is configured now. */
	readonly connection: FederationGrantConnection;
	/** `federationGrants.maxExpiresIn` as it is configured now, in milliseconds. */
	readonly maxExpiresInMs: number;
	/** The subject's grants boundary; `null` when none is in force. */
	readonly grantsBoundary: Date | null;
	readonly revocationSkewMs: number;
	/**
	 * Whether the sealed credential authenticates under the current key ring.
	 * Only consulted for a grant that is stored as `active`: every other stored
	 * state has had its credential deleted (D2), and an `active` grant with no
	 * credential record at all is `"unreadable"`.
	 */
	readonly credentials: "ok" | "unreadable";
}

/**
 * What a caller is told about a grant (#593, D1). Computed on every read and
 * never persisted: undoing a configuration change, or restoring a key,
 * restores the grant. Only a revocation and an upstream `invalid_grant` are
 * facts about the grant itself, and only those are stored.
 *
 * The order is from what cannot be undone to what can, so that a client is
 * never sent to a remedy that cannot work:
 *
 * 1. a stored revocation;
 * 2. the backstop, before expiry, so that a revocation which never reached the
 *    record is not reported as a mere expiry — and for a grant that already
 *    needs the user too, since the boundary ends that one as well. Not for a
 *    `pending` grant: it has no consent to date, and D7 already demands a
 *    session that authenticated after the boundary;
 * 3. expiry, the terminal bound first (`federationGrantExpiryState`);
 * 4. a changed upstream identity, which no reauthorization can mend — before
 *    the stored `invalid_grant`, because `/reauthorize` refuses such a grant;
 * 5. what a reauthorization does mend: a stored `invalid_grant`, a changed
 *    connection, a credential that does not open;
 * 6. an upstream that stopped issuing eligible tokens, for as long as the
 *    marker stands. After what a reauthorization mends, since a
 *    reauthorization clears the marker as well.
 *
 * This is the order D10's steps are reported in, which is not the order the
 * ADR lists them: it puts the backstop before expiry.
 *
 * A key that is missing from the ring is not a status. It is an outage, and
 * the caller answers 503 before it gets here. So is a boundary that cannot be
 * compared: `coveredByRevocationBoundary` throws.
 */
export function effectiveFederationGrantStatus(
	grant: FederationGrant,
	context: EffectiveFederationGrantStatusContext,
): EffectiveFederationGrantStatus {
	if (grant.status === "revoked") return { status: "revoked", reason: grant.revocation.by };
	if (grant.status === "pending") return { status: "pending" };

	if (
		coveredByRevocationBoundary(grant.consent.at, context.grantsBoundary, context.revocationSkewMs)
	) {
		return { status: "revoked", reason: "backstop" };
	}

	const expiry = federationGrantExpiryState(grant, context.now, context.maxExpiresInMs);
	if (expiry !== "live") return { status: "expired", reason: expiry };

	if (grant.identityRevision !== federationGrantIdentityRevision(context.connection)) {
		return { status: "connection_identity_changed" };
	}
	if (grant.status === "reauthorization_required") {
		return { status: "reauthorization_required", reason: "upstream_invalid_grant" };
	}
	if (grant.authorizationRevision !== federationGrantAuthorizationRevision(context.connection)) {
		return { status: "reauthorization_required", reason: "connection_changed" };
	}
	if (context.credentials === "unreadable") {
		return { status: "reauthorization_required", reason: "credential_unreadable" };
	}

	if (
		grant.ineligible !== undefined &&
		federationGrantIneligibilityStands(grant.ineligible, context.connection.maxAccessTokenLifetime)
	) {
		return { status: "upstream_token_ineligible", reason: grant.ineligible.reason };
	}
	return { status: "active" };
}
