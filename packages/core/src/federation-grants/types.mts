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
 * Federation grants: the record of one user's consent that one client may
 * obtain upstream access tokens through one connection, within stated
 * scopes, until a stated time. Design and rationale: ADR
 * 2026-09-17-federation-grants-offline-delegation.
 *
 * "Grant" never means an OAuth grant type (`src/grants/`), hence the
 * `FederationGrant` prefix. Unlike `federation-tokens/` (session-bound,
 * deleted at logout), a grant outlives the session.
 *
 * Milliseconds carry `Ms` in the name; seconds are noted where declared.
 */

/** Who ended a grant. `backstop` is the subject boundary check, made durable on the first touch. */
export type FederationGrantRevokedBy =
	| "client"
	| "subject"
	| "operator"
	| "logout_policy"
	| "backstop";

/** What every grant has from the moment the backend lodges its first intent. */
export interface FederationGrantBase {
	/** Opaque, 256 bits, base64url. A reference, not a credential: it authorizes nothing by itself. */
	readonly id: string;
	/** The local owner. */
	readonly subject: string;
	/** The owning client — the one confidential client that may use this grant. */
	readonly clientId: string;
	readonly connection: string;
	readonly createdAt: Date;
	/** Bumped by every status or credential change; the guard of the store's writes. */
	readonly version: number;
}

/** What the user was shown and agreed to, and the session it was agreed through. */
export interface FederationGrantConsent {
	readonly at: Date;
	readonly sid: string;
	readonly scopes: readonly string[];
}

/**
 * What an activation writes, and only an activation replaces: the fields
 * that decide who may obtain what, until when. A store binds all of them
 * (with `id`, `subject`, `clientId`, `connection`) into the sealed
 * credential's authenticated envelope, so tampering makes the credential
 * unreadable instead of widening the grant.
 *
 * Every field is a required key (`resource` is `undefined` where none), so
 * a copy that dropped the audience restriction is a compile error.
 */
export interface FederationGrantAuthorization {
	/** Fingerprint of the connection's upstream issuer and client at consent. */
	readonly identityRevision: string;
	/** Fingerprint of what the connection asks for and where. */
	readonly authorizationRevision: string;
	readonly upstream: { readonly issuer: string; readonly subject: string };
	/** RFC 8707, from the connection; `undefined` when it names none. */
	readonly resource: string | undefined;
	/** Granted by the upstream at authorization, within `consent.scopes`. A refresh never changes it. */
	readonly scopes: readonly string[];
	readonly consent: FederationGrantConsent;
	readonly authorizedAt: Date;
	/** `consent.at` plus the consented lifetime. Fixed at consent; a refresh never moves it. */
	readonly expiresAt: Date;
}

/**
 * What changes while a grant is in use, outside any activation and outside
 * the authenticated envelope: none of it decides what the grant allows.
 *
 * Each is a required key, `undefined` where there is none: losing
 * `ineligible` or `refreshFailure` in a copy would let the upstream be asked
 * (and the refresh token rotated) on every request instead of after the
 * interval. A write that spreads the old record clears one explicitly
 * (`refreshFailure: undefined`); the contract suite, not the compiler,
 * holds those writes.
 */
export interface FederationGrantUsage {
	readonly lastUsedAt: Date | undefined;
	/** Left by a refresh whose token could not be disclosed. */
	readonly ineligible: FederationGrantIneligibilityMarker | undefined;
	/** Left by a refresh that failed. Cleared by whatever replaces or ends the credentials. */
	readonly refreshFailure: FederationGrantRefreshFailure | undefined;
}

/**
 * How a refresh failed, as a later look needs to know it:
 *
 * - `unavailable` — outage or unreadable answer: may have been processed.
 * - `rate_limited` — a 429: not processed.
 * - `rejected` — a known error code that does not end the credentials: a
 *   configuration fault, until an operator acts.
 */
export type FederationGrantRefreshFailureKind = "unavailable" | "rate_limited" | "rejected";

/**
 * What a refresh reports of its failure. The store counts.
 *
 * The optional fields say `| undefined` so that a stored stamp, which names
 * both, is still accepted where a report is under
 * `exactOptionalPropertyTypes`.
 */
export interface FederationGrantRefreshFailureInput {
	readonly at: Date;
	readonly kind: FederationGrantRefreshFailureKind;
	/** The upstream's `Retry-After`, in seconds, as the classifier bounded it. */
	readonly retryAfterSeconds?: number | undefined;
	/** For `rejected`: the error code, one this provider knows. */
	readonly upstreamCode?: string | undefined;
}

/**
 * Non-secret, and outside the authenticated envelope. Without it every
 * request needing a refresh would ask a failing upstream again. The report's
 * fields are required keys (a lost `retryAfterSeconds` would retry before
 * the upstream said to), plus the store's count.
 */
export interface FederationGrantRefreshFailure {
	readonly at: Date;
	readonly kind: FederationGrantRefreshFailureKind;
	/** The upstream's `Retry-After`, in seconds, as the classifier bounded it. */
	readonly retryAfterSeconds: number | undefined;
	/** For `rejected`: the error code, one this provider knows. */
	readonly upstreamCode: string | undefined;
	/** Failures in a row, counted by the store: `1` for the first. */
	readonly count: number;
}

export interface FederationGrantRevocation {
	readonly status: "revoked";
	readonly revocation: { readonly by: FederationGrantRevokedBy; readonly at: Date };
}

/**
 * No authorization field and no usage field may carry a value. That is as far
 * as the type goes: without `exactOptionalPropertyTypes`, which this
 * repository does not enable, `consent?: never` still admits an explicit
 * `consent: undefined`. `hasFederationGrantAuthorization` therefore tests the
 * value and not the key.
 */
type NeverAuthorized = {
	readonly [K in keyof (FederationGrantAuthorization & FederationGrantUsage)]?: never;
};

export type PendingFederationGrant = FederationGrantBase &
	NeverAuthorized & { readonly status: "pending" };

export type AuthorizedFederationGrant = FederationGrantBase &
	FederationGrantAuthorization &
	FederationGrantUsage & { readonly status: "active" | "reauthorization_required" };

/**
 * Two shapes, and nothing in between. A grant revoked after it was authorized
 * keeps every authorization field; one revoked while `pending` never had any,
 * and its type forbids them. A single shape with optional fields would admit a
 * record carrying `consent` without `expiresAt`, and the narrowing below would
 * then promise fields that are not there.
 */
export type RevokedFederationGrant =
	| (FederationGrantBase &
			FederationGrantAuthorization &
			FederationGrantUsage &
			FederationGrantRevocation)
	| (FederationGrantBase & NeverAuthorized & FederationGrantRevocation);

/** The stored record. `expired` is not a stored status: it is read off the clock. */
export type FederationGrant =
	| PendingFederationGrant
	| AuthorizedFederationGrant
	| RevokedFederationGrant;

/** Narrows a revoked grant to the one that was authorized before it was revoked. */
export function hasFederationGrantAuthorization<G extends FederationGrant>(
	grant: G,
): grant is G & FederationGrantAuthorization {
	return (grant as { consent?: unknown }).consent !== undefined;
}

/**
 * A connection as the domain rules need it: the `federation-grants.connections.<name>`
 * entry, joined with the upstream issuer and client ID of the federation it
 * points at. Reading it from configuration is the package's job.
 */
export interface FederationGrantConnection {
	readonly name: string;
	/** Key under `core.federations`. */
	readonly federation: string;
	/**
	 * The issuer exactly as `core.federations.<name>.issuer` is configured — not the
	 * string a discovery document happens to return. It goes into a persisted
	 * fingerprint, and what goes into that must only change when an operator
	 * changes it.
	 */
	readonly upstreamIssuer: string;
	readonly upstreamClientId: string;
	/** The ceiling an intent may ask within. */
	readonly scopes: readonly string[];
	readonly resource?: string;
	readonly authorizationParams?: Readonly<Record<string, string>>;
	/** Names the environment. Required, so that isolation between environments is not opt-in. */
	readonly boundary: string;
	/** Seconds. What turns residual access into a number the operator chose. */
	readonly maxAccessTokenLifetime: number;
	/** `false`: every intent gets the full scope set (for IdPs that accumulate consent). Default `true`. */
	readonly allowScopeSubsets?: boolean;
	/**
	 * `callbackURL`, exactly as configured: where the upstream returns the
	 * browser at the end of a connect flow. Optional here because spending
	 * a grant never needs it; a deployment that creates grants is refused at
	 * boot without it, and acquisition takes the connection as
	 * `FederationGrantAcquisitionConnection`, where it is required.
	 */
	readonly callbackUri?: string;
	/**
	 * The id_token claims the connect callback asks the adapter for and hands
	 * the Store beside the subject — what a Store matches a person on across
	 * registrations where `sub` is pairwise (Entra's `tid` and `oid`). The
	 * package's resolver always sets it (`[]` when unset). In neither
	 * revision: it changes what the account-binding check can see, not what
	 * was consented to.
	 */
	readonly identityClaims?: readonly string[];
}

export type FederationGrantIneligibilityReason =
	| "no_finite_lifetime"
	| "lifetime_over_maximum"
	| "scope_exceeded"
	/** Not a bearer token: a route with no proof key cannot present a sender-constrained one. */
	| "token_type_unsupported"
	/**
	 * The adapter reported a refresh without a usable access token, or with a
	 * field of the wrong type. The refresh token it came with is kept all the
	 * same, and the marker keeps a broken adapter from rotating on every request.
	 */
	| "malformed_token_response";

/**
 * Non-secret, and outside the authenticated envelope. Without it a grant whose
 * upstream keeps answering with ineligible tokens would take the lock, call
 * the upstream and rotate the refresh token on every request.
 */
export interface FederationGrantIneligibilityMarker {
	readonly reason: FederationGrantIneligibilityReason;
	readonly at: Date;
	/** Seconds: the `maxAccessTokenLifetime` it was judged against. A different current value voids the marker. */
	readonly judgedAgainst: number;
}

export type FederationGrantReauthorizationReason =
	| "upstream_invalid_grant"
	| "connection_changed"
	| "credential_unreadable"
	// The upstream asked for the user: the refresh was refused
	// with one of the four interaction codes, and the credential is kept.
	| "upstream_interaction_required"
	| "upstream_login_required"
	| "upstream_consent_required"
	| "upstream_account_selection_required";

export type FederationGrantExpiredReason = "consented_lifetime" | "operator_maximum";

/**
 * What a caller is told about a grant, computed on every read and never
 * persisted, so that undoing a configuration change or restoring a key
 * restores the grant.
 */
export type EffectiveFederationGrantStatus =
	| { readonly status: "pending" }
	| { readonly status: "active" }
	| { readonly status: "expired"; readonly reason: FederationGrantExpiredReason }
	| { readonly status: "revoked"; readonly reason: FederationGrantRevokedBy }
	/** The operator removed the connection's entry. Putting it back restores the grant. */
	| { readonly status: "connection_not_configured" }
	| { readonly status: "connection_identity_changed" }
	| {
			readonly status: "reauthorization_required";
			readonly reason: FederationGrantReauthorizationReason;
	  }
	| {
			readonly status: "upstream_token_ineligible";
			readonly reason: FederationGrantIneligibilityReason;
	  };

/**
 * What the sealed credential record holds. `accessToken` is `undefined` when
 * an ineligible token was withheld, and is a required key so a copy cannot
 * drop it (which would force a refresh on every request). Expiry is derived
 * (`obtainedAt` + `issuedLifetime`), never stored separately.
 */
export interface FederationGrantCredentials {
	readonly refreshToken: string;
	readonly accessToken:
		| {
				readonly value: string;
				readonly tokenType: string;
				readonly obtainedAt: Date;
				/** Seconds, as the upstream issued it — not what remains of it. */
				readonly issuedLifetime: number;
				/** What this token carries. A refresh response that omits `scope` means the grant's scopes (RFC 6749 §6). */
				readonly scopes: readonly string[];
		  }
		| undefined;
}

// ---------------------------------------------------------------------------
// The typed result of `retrieveFederationGrantToken`.
// ---------------------------------------------------------------------------

export type FederationGrantUnavailableReason =
	| "upstream"
	| "storage"
	| "lock_timeout"
	/**
	 * This call's refresh was overtaken — its guarded write lost, or what it
	 * wrote was replaced before the last look — and what is stored now is
	 * nothing to answer with.
	 */
	| "concurrent_update"
	| "key_unavailable";

/**
 * What went wrong where a retrieval turned a cause into a typed answer, or
 * dropped one. For a logger; never for a response — the error may be an
 * upstream's, and carry what the upstream echoed.
 */
export interface FederationGrantRetrievalFailure {
	readonly during:
		| "boundary"
		| "open"
		| "status"
		| "backstop_revoke"
		| "lock"
		| "release"
		| "upstream"
		| "mark"
		| "write"
		| "touch"
		| "audit"
		| "background"
		| "refresh";
	readonly error: unknown;
	readonly grantId: string;
	readonly correlationId: string;
	/**
	 * How many attempts this failure stands for, when more than one: a retried
	 * write reports each distinct kind of failure (its name and code) once,
	 * with the last error of that kind and how many attempts failed so.
	 */
	readonly attempts?: number;
}

/**
 * One typed result for a token retrieval; one HTTP mapping is derived from
 * it. Each code is its own object, so a reason cannot be attached to a code
 * that has none.
 */
export type FederationGrantDenial =
	| { readonly code: "grant_not_found" }
	| { readonly code: "authorization_pending" }
	| { readonly code: "grant_expired"; readonly reason: FederationGrantExpiredReason }
	| { readonly code: "grant_revoked"; readonly reason: FederationGrantRevokedBy }
	| { readonly code: "connection_identity_changed" }
	| {
			readonly code: "reauthorization_required";
			readonly reason: FederationGrantReauthorizationReason;
	  }
	| { readonly code: "access_denied"; readonly reason: "connection_not_permitted" }
	| {
			readonly code: "invalid_request";
			/** Which assertion failed: both answer 400, and an `error_description` wants to say which. */
			readonly reason: "connection_mismatch" | "min_ttl_out_of_range";
	  }
	| { readonly code: "invalid_scope" | "invalid_target" }
	| {
			readonly code: "upstream_token_ineligible";
			readonly reason: FederationGrantIneligibilityReason;
			readonly retryAfterSeconds?: number;
	  }
	| {
			readonly code: "upstream_rejected";
			readonly reason: string;
			/** Present when answered from the stamp of a failed refresh. */
			readonly retryAfterSeconds?: number;
	  }
	| {
			readonly code: "rate_limited";
			readonly reason: "provider" | "upstream";
			readonly retryAfterSeconds?: number;
	  }
	| {
			readonly code: "temporarily_unavailable";
			readonly reason: FederationGrantUnavailableReason;
			readonly retryAfterSeconds?: number;
			/**
			 * The reported failure this answer was turned from (the same object
			 * handed to `report`), so the route logs the outage once with its
			 * cause. Absent when nothing was thrown (missing key, missed deadline,
			 * standing backoff, contention).
			 *
			 * Not enumerable: a spread, `JSON.stringify` or a response built from
			 * the answer never carries it.
			 */
			readonly failure?: FederationGrantRetrievalFailure;
	  };

export type FederationGrantTokenResult =
	| {
			readonly ok: true;
			readonly accessToken: string;
			readonly tokenType: string;
			/** Seconds. Clamped to the grant's remaining life: a cache hint, never enforcement. */
			readonly expiresIn: number;
			/** What this token carries. */
			readonly scopes: readonly string[];
			/**
			 * Whether this is a token the call itself fetched from the upstream. It
			 * is `false` for a cached token, for somebody else's refresh, and for
			 * the token the grant had when this call's refresh brought nothing
			 * usable.
			 */
			readonly refreshed: boolean;
	  }
	| ({ readonly ok: false } & FederationGrantDenial);
