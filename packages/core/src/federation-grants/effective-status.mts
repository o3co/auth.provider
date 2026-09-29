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

import {
	federationGrantIneligibilityStands,
	federationGrantInteractionCode,
	isUsableMaxUpstreamAccessTokenLifetime,
} from "./eligibility.mjs";
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
 * Whether a subject's revocation boundary covers an instant: a grant's consent
 * against the grants boundary, or a session's authentication against the
 * sessions boundary. For a grant the consent is compared, not a token's `iat`
 * (a token from a surviving grant is always fresh) nor `authorizedAt` (a
 * callback just after the boundary must not hide a consent given before it).
 *
 * Inclusive, with the allowance `jwt/verify.mts` gives the same boundary
 * (`subjectRevocationSkewMs`), not the five-minute `clockSkewMs`, which would
 * refuse the re-login a revocation sends the user to. A negative allowance
 * reads as none; `null` is no boundary in force.
 *
 * @throws RangeError for a value that cannot be compared. Neither answer is
 * safe: "not covered" switches the backstop off (for every grant, if the
 * allowance is NaN), and "covered" revokes durably over a corrupt value. The
 * caller answers 503, as `verifyJwt` does.
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
	/**
	 * The connection as it is configured now; `undefined` when the operator has
	 * removed it. That is reported as `connection_not_configured`, after every
	 * terminal fact and before anything that needs a connection to compare with.
	 */
	readonly connection: FederationGrantConnection | undefined;
	/** `federationGrants.maxExpiresIn` as it is configured now, in milliseconds. */
	readonly maxExpiresInMs: number;
	/** The subject's grants boundary; `null` when none is in force. */
	readonly grantsBoundary: Date | null;
	readonly revocationSkewMs: number;
	/**
	 * Whether the sealed credential authenticates under the current key ring.
	 * Only consulted for a grant stored as `active`: every other stored state
	 * has had its credential deleted, and an `active` grant with no credential
	 * record is `"unreadable"`.
	 */
	readonly credentials: "ok" | "unreadable";
}

/**
 * What a caller is told about a grant. Computed on every read and never
 * persisted, so undoing a configuration change or restoring a key restores the
 * grant; only a revocation and an upstream `invalid_grant` are stored.
 *
 * Ordered from what cannot be undone to what can, so a client is never sent to
 * a remedy that cannot work:
 *
 * 1. a stored revocation;
 * 2. the backstop, before expiry so an unrecorded revocation is not reported as
 *    an expiry (not for `pending`, which has no consent to date);
 * 3. expiry, the terminal bound first (`federationGrantExpiryState`);
 * 4. a connection no longer configured: restorable, so after what is not, and
 *    not a changed identity;
 * 5. a changed upstream identity, which no reauthorization mends (before a
 *    stored `invalid_grant`, since `/reauthorize` refuses such a grant);
 * 6. what a reauthorization mends: a stored `invalid_grant`, a changed
 *    connection, an unreadable credential, an upstream interaction code;
 * 7. a grant that cannot yield a token: an unsatisfiable
 *    `maxAccessTokenLifetime` (what `/token` answers, whatever an older marker
 *    says), then a standing ineligibility marker, which reauthorization clears.
 *
 * The backstop comes before expiry, unlike the federation-grants ADR's
 * listing. A key missing from the ring is an outage, not a status: the caller
 * passes `"unreadable"` and answers 503 where this would say
 * `credential_unreadable`, which masks nothing ahead of it. An incomparable
 * boundary throws (`coveredByRevocationBoundary`).
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

	const connection = context.connection;
	if (connection === undefined) return { status: "connection_not_configured" };

	if (grant.identityRevision !== federationGrantIdentityRevision(connection)) {
		return { status: "connection_identity_changed" };
	}
	if (grant.status === "reauthorization_required") {
		return { status: "reauthorization_required", reason: "upstream_invalid_grant" };
	}
	if (grant.authorizationRevision !== federationGrantAuthorizationRevision(connection)) {
		return { status: "reauthorization_required", reason: "connection_changed" };
	}
	if (context.credentials === "unreadable") {
		return { status: "reauthorization_required", reason: "credential_unreadable" };
	}
	// The upstream asked for the user: a refusal stamped with an interaction
	// code, read for as long as it stands. Its backoff fields are not consulted
	// (waiting mends nothing), and it precedes the checks below, which waiting
	// might mend.
	const interaction = federationGrantInteractionCode(grant.refreshFailure);
	if (interaction !== undefined) {
		return { status: "reauthorization_required", reason: `upstream_${interaction}` };
	}

	const maximum = connection.maxAccessTokenLifetime;
	if (!isUsableMaxUpstreamAccessTokenLifetime(maximum)) {
		return { status: "upstream_token_ineligible", reason: "lifetime_over_maximum" };
	}
	if (
		grant.ineligible !== undefined &&
		federationGrantIneligibilityStands(grant.ineligible, maximum)
	) {
		return { status: "upstream_token_ineligible", reason: grant.ineligible.reason };
	}
	return { status: "active" };
}
