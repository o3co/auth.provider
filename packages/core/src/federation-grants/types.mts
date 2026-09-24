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
 * Federation grants (#593): the record of one user's consent that one client
 * may obtain upstream access tokens through one connection, within stated
 * scopes, until a stated time. The design, and the reasons for every rule
 * here, are in `docs/adr/2026-09-17-federation-grants-offline-delegation.md`;
 * "D<n>" below names a decision in it.
 *
 * "Grant" here never means an OAuth grant type (`src/grants/`), which is why
 * every name this directory exports says `FederationGrant`. It sits next to
 * `federation-tokens/`, which stays what it is: the session-bound record that
 * logout deletes.
 *
 * Durations carry their unit in the name where it is milliseconds (`…Ms`);
 * a bare number of seconds is said to be one where it is declared.
 */

/** Who ended a grant. `backstop` is D13's boundary check, made durable on the first touch. */
export type FederationGrantRevokedBy =
	| "client"
	| "subject"
	| "operator"
	| "logout_policy"
	| "backstop";

/** What every grant has from the moment the backend lodges its first intent (D1, D6). */
export interface FederationGrantBase {
	/** Opaque, 256 bits, base64url. A reference, not a credential: it authorizes nothing by itself. */
	readonly id: string;
	/** The local owner. */
	readonly subject: string;
	/** The owning client — the one confidential client that may use this grant. */
	readonly clientId: string;
	readonly connection: string;
	readonly createdAt: Date;
	/** Bumped by every status or credential change; the guard of D2's writes. */
	readonly version: number;
}

/** What the user was shown and agreed to, and the session it was agreed through (D8). */
export interface FederationGrantConsent {
	readonly at: Date;
	readonly sid: string;
	readonly scopes: readonly string[];
}

/**
 * What an activation writes, and only an activation replaces (D2).
 *
 * These are the fields that decide who may obtain what, until when. A store
 * puts every one of them, with the grant's `id`, `subject`, `clientId` and
 * `connection`, into the authenticated envelope of the sealed credential
 * (D16), so that rewriting one in storage makes the credential unreadable
 * instead of widening the grant. Keeping them in a type of their own is what
 * gives an adapter that list.
 *
 * Every field is a required key (#626): `resource` holds `undefined` where the
 * connection names none, so a copy that forgot it — and asked the upstream
 * for a token without the audience the connection narrows it to — is a
 * compile error.
 */
export interface FederationGrantAuthorization {
	/** Fingerprint of the connection's upstream issuer and client at consent (D4). */
	readonly identityRevision: string;
	/** Fingerprint of what the connection asks for and where (D4). */
	readonly authorizationRevision: string;
	readonly upstream: { readonly issuer: string; readonly subject: string };
	/** RFC 8707, from the connection; `undefined` when it names none. */
	readonly resource: string | undefined;
	/** Granted by the upstream at authorization, within `consent.scopes`. A refresh never changes it. */
	readonly scopes: readonly string[];
	readonly consent: FederationGrantConsent;
	readonly authorizedAt: Date;
	/** `consent.at` plus the consented lifetime. Fixed at consent; a refresh never moves it (D3). */
	readonly expiresAt: Date;
}

/**
 * What changes while a grant is in use, outside any activation and outside the
 * authenticated envelope: neither field decides what the grant allows.
 *
 * Each is a required key, `undefined` where there is none (#626). Two
 * decide how often the upstream is asked: a copy that lost `ineligible` would
 * take the lock and rotate the refresh token on every request again (D5), and
 * one that lost `refreshFailure` would ask a failing upstream again at once
 * (D12). Naming the key makes a copy built field by field that forgot one a
 * compile error. A write that spreads the old record and clears one says so
 * by convention (`refreshFailure: undefined`): the compiler cannot tell a
 * clear left out from a value meant to be kept, so the contract suite is
 * what holds those writes.
 */
export interface FederationGrantUsage {
	readonly lastUsedAt: Date | undefined;
	/** Left by a refresh whose token could not be disclosed (D5). */
	readonly ineligible: FederationGrantIneligibilityMarker | undefined;
	/** Left by a refresh that failed (D12). Cleared by whatever replaces or ends the credentials. */
	readonly refreshFailure: FederationGrantRefreshFailure | undefined;
}

/**
 * How a refresh failed, as far as a later look needs to know: what to answer
 * meanwhile, and how long to wait before the upstream is asked again.
 *
 * - `unavailable` — an outage, a connection that failed, an answer nobody
 *   could read: the request may have been processed, and its answer lost.
 * - `rate_limited` — a 429: the request was not processed.
 * - `rejected` — an error code this provider knows, other than the ones that
 *   end the credentials: a configuration fault, until an operator acts.
 */
export type FederationGrantRefreshFailureKind = "unavailable" | "rate_limited" | "rejected";

/**
 * What a refresh reports of its failure. The store counts.
 *
 * The optional fields say `| undefined` so that a stored stamp, which names
 * both (#626), is still accepted where a report is — as it was when the stamp
 * extended this type — for a consumer compiling with
 * `exactOptionalPropertyTypes`.
 */
export interface FederationGrantRefreshFailureInput {
	readonly at: Date;
	readonly kind: FederationGrantRefreshFailureKind;
	/** The upstream's `Retry-After`, in seconds, as the classifier bounded it. */
	readonly retryAfterSeconds?: number | undefined;
	/** For `rejected`: the error code, one this provider knows (D18). */
	readonly upstreamCode?: string | undefined;
}

/**
 * Non-secret, and outside the authenticated envelope (D16). Without it every
 * request that needs a refresh would ask a failing upstream again (D12).
 *
 * The report's fields, each a required key (#626) — a stamp that lost
 * `retryAfterSeconds` would ask the upstream again before it said to — and
 * the store's count.
 */
export interface FederationGrantRefreshFailure {
	readonly at: Date;
	readonly kind: FederationGrantRefreshFailureKind;
	/** The upstream's `Retry-After`, in seconds, as the classifier bounded it. */
	readonly retryAfterSeconds: number | undefined;
	/** For `rejected`: the error code, one this provider knows (D18). */
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

/** The stored record. `expired` is not a stored status: it is read off the clock (D1, D3). */
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
 * A connection as the domain rules need it: the `federationGrants.connections.<name>`
 * entry, joined with the upstream issuer and client ID of the federation it
 * points at (D4). Reading it from configuration is the package's job.
 */
export interface FederationGrantConnection {
	readonly name: string;
	/** Key under `federations`. */
	readonly federation: string;
	/**
	 * The issuer exactly as `federations.<name>.issuer` is configured — not the
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
	/** Seconds. What turns residual access into a number the operator chose (D5, D15). */
	readonly maxAccessTokenLifetime: number;
	/** `false`: every intent gets the full scope set (D19). Default `true`. */
	readonly allowScopeSubsets?: boolean;
	/**
	 * `callbackURL`, exactly as configured: where the upstream returns the
	 * browser at the end of a connect flow (D7). Optional here because spending
	 * a grant never needs it; a deployment that creates grants is refused at
	 * boot without it, and acquisition takes the connection as
	 * `FederationGrantAcquisitionConnection`, where it is required.
	 */
	readonly callbackUri?: string;
	/**
	 * #611: the id_token claims the connect callback asks the adapter for and
	 * hands the Store beside the subject — what a Store matches a person on
	 * across registrations where `sub` is pairwise (Entra's `tid` and `oid`).
	 * The package's resolver always sets it (`[]` when unset). In neither
	 * revision: it changes what check 5 can see, not what was consented to.
	 */
	readonly identityClaims?: readonly string[];
}

export type FederationGrantIneligibilityReason =
	| "no_finite_lifetime"
	| "lifetime_over_maximum"
	| "scope_exceeded"
	/** Not a bearer token: a route with no proof key cannot present a sender-constrained one (D5). */
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
 * the upstream and rotate the refresh token on every request (D5).
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
	// The upstream asked for the user (#616, D11): the refresh was refused
	// with one of the four interaction codes, and the credential is kept.
	| "upstream_interaction_required"
	| "upstream_login_required"
	| "upstream_consent_required"
	| "upstream_account_selection_required";

export type FederationGrantExpiredReason = "consented_lifetime" | "operator_maximum";

/**
 * What a caller is told about a grant, computed on every read and never
 * persisted, so that undoing a configuration change or restoring a key
 * restores the grant (D1).
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
 * What the sealed credential record holds (D5, D16). The access token may be
 * `undefined`: an ineligible one is withheld and never written. Its expiry is
 * not stored: it is `obtainedAt` plus `issuedLifetime`, and a second copy
 * would be a second thing that could disagree with what the eligibility rule
 * judged.
 *
 * `accessToken` is a required key (#626): a copy that forgot it would read as
 * a withheld token and send every request to the upstream for a refresh.
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
// The typed result of `retrieveFederationGrantToken` (D11).
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
 * One typed result for a token retrieval; one HTTP mapping is derived from it
 * (D11). The ADR's table lists codes with their reasons; here each code is an
 * object, so that a reason cannot be attached to a code that has none.
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
			/** Present when answered from the stamp of a failed refresh (D12). */
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
	  };

export type FederationGrantTokenResult =
	| {
			readonly ok: true;
			readonly accessToken: string;
			readonly tokenType: string;
			/** Seconds. Clamped to the grant's remaining life: a cache hint, never enforcement (D10, D15). */
			readonly expiresIn: number;
			/** What this token carries. */
			readonly scopes: readonly string[];
			/**
			 * Whether this is a token the call itself fetched from the upstream. It
			 * is `false` for a cached token, for somebody else's refresh, and for
			 * the token the grant had when this call's refresh brought nothing
			 * usable (D5).
			 */
			readonly refreshed: boolean;
	  }
	| ({ readonly ok: false } & FederationGrantDenial);
