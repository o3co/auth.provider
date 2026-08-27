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
import type { SenderConstraint } from "../grants/senderConstraint.mjs";

/**
 * RFC 6749 §2.3 / RFC 7591 §2 client authentication method at the token endpoint.
 *
 * - `"client_secret_basic"`: HTTP Basic `Authorization` header (§2.3.1)
 * - `"client_secret_post"`: form-encoded body parameters (§2.3.1)
 * - `"none"`: public client (no secret; PKCE/S256 mandatory per RFC 9700 §2.1.1)
 */
export type TokenEndpointAuthMethod = "client_secret_basic" | "client_secret_post" | "none";

export interface Client {
	readonly clientId: string;
	/**
	 * Token-endpoint authentication method. REQUIRED — the schema rejects
	 * client entries that omit it; deployments upgrading from v0.5.0 must add
	 * the field explicitly per the v0.5.1 migration guide.
	 *
	 * Public clients (`"none"`) MUST present PKCE/S256 at `/authorize`;
	 * confidential clients (`"client_secret_basic"` / `"client_secret_post"`)
	 * MUST present a `clientSecret` and use the matching transport at `/token`.
	 */
	readonly tokenEndpointAuthMethod: TokenEndpointAuthMethod;
	/**
	 * Required when `tokenEndpointAuthMethod` is `"client_secret_basic"` or
	 * `"client_secret_post"`. MUST be absent (`undefined`) when the method is
	 * `"none"`. The `ClientEntrySchema` superRefine enforces both directions.
	 */
	readonly clientSecret?: string;
	readonly allowedRedirectUris: readonly string[];
	readonly allowedScopes: readonly string[];
	/**
	 * Audience URIs this client may receive tokens for.
	 *
	 * Consumers:
	 * - Token Exchange (RFC 8693) `audience` parameter selection — when this
	 *   list is empty or undefined, only the client's own `clientId` is
	 *   accepted as an audience target.
	 * - `client_credentials` grant default `aud` claim — selects the first
	 *   entry (`allowedAudiences[0]`); when absent, falls back to the issuer
	 *   (and ultimately omits `aud` when no issuer is configured).
	 */
	readonly allowedAudiences?: readonly string[];
	/**
	 * Grant types this client is explicitly permitted to use.
	 *
	 * Enforced **centrally** by `isGrantTypeAllowed` — once at `/oauth/token`
	 * grant dispatch, before the concrete handler runs, and at `/authorize`
	 * against `authorization_code` — so every current and future grant
	 * inherits the check rather than opting in (#268). The central rule:
	 *
	 * - `undefined` (absent) → **no restriction**. Absence means the
	 *   registration declared no policy, not that it declared an empty one;
	 *   denying here would revoke every grant from every registration written
	 *   before this field existed.
	 * - `[]` (empty) → every grant is denied. An empty allowlist names no
	 *   grant type, so none can match it.
	 * - non-empty array → a grant is allowed iff its `grant_type` string
	 *   appears in the list, compared exactly.
	 *
	 * Two grants layer a **stricter** rule on top and deny by absence, so
	 * that machine-to-machine access is never acquired by omission:
	 * `client_credentials` (`grants/clientCredentials.mts`) and the WebAuthn
	 * grant (`@o3co/auth-provider-webauthn`). The rules compose to the
	 * stricter of the pair — either can reject, and only the absent case
	 * distinguishes them.
	 */
	readonly allowedGrantTypes?: readonly string[];
	// NEW (TODO-F-5): Logout metadata.
	readonly postLogoutRedirectUris?: readonly string[];
	readonly backchannelLogoutUri?: string;
	// default: true (includes sid in logout_token) — intentional deviation from OIDC Back-Channel
	// Logout 1.0 §2.2 spec default of false, to default to the safer behavior. See ClientEntrySchema.
	readonly backchannelLogoutSessionRequired?: boolean;
	readonly frontchannelLogoutUri?: string;
	// default: true (includes sid in frontchannel logout iframe URL) — intentional deviation from OIDC
	// Front-Channel Logout 1.0 spec default of false, to default to the safer behavior. See ClientEntrySchema.
	readonly frontchannelLogoutSessionRequired?: boolean;
	// NEW (TODO-F-6): Federation-token access opt-in.
	/**
	 * When true, this client MAY call POST /oauth/federation/:name/token to
	 * retrieve the user's upstream federation access_token. Deny-by-default
	 * (deny-by-absence); must be explicitly opted in per client.
	 *
	 * Why default false: federation access_tokens grant access to the user's
	 * external resources (Google Calendar, GitHub API, etc.) — high blast
	 * radius. Opt-in prevents accidentally granting this power to a generic
	 * OAuth client registration that only needs auth.
	 */
	readonly allowedAzpForFederationToken?: boolean;
	/**
	 * Sender-constraint requirement for this client. See Wave 2 Token-
	 * binding Cluster spec §4.8. Surfaces through `PublicClient` (via
	 * `Omit`) and `AuthenticatedClient` (via the `/token` route's
	 * projection).
	 */
	readonly senderConstrained?: SenderConstraint;
}

export interface User {
	readonly id: string;
	readonly username: string;
	readonly [key: string]: unknown;
}

/**
 * Data persisted in the code record at /authorize time.
 *
 * `consumeByCode` (atomic single-use) is the sole authenticity gate; `client_id`
 * and `redirect_uri` embedded in the record replace the session-based identity
 * gates removed in v0.5.1 (see CHANGELOG for the historical context — the
 * design rationale is the D-1 code-repository rewrite shipped in that release).
 *
 * Breaking change for custom CodeRepository implementations: `client_id` and
 * `redirect_uri` are now required. The compile-time guard
 * `Parameters<CodeRepository["createCode"]>[0]` makes any implementation that
 * misses either field fail typecheck at the destructure site.
 */
export interface CodeData {
	readonly client_id: string; // required — replaces the session.code_client_id gate
	readonly redirect_uri: string; // required — closes IH-4 vacuous-pass (RFC 6749 §4.1.3)
	readonly code_challenge?: string;
	readonly code_challenge_method?: string;
	// NEW (TODO-F-3): OIDC authorize → token round-trip state.
	// These fields are persisted at /authorize and read at /token.
	readonly nonce?: string;
	readonly sid?: string;
}

export interface Code extends CodeData {
	readonly code: string;
	readonly expiresIn?: number;
	readonly grantedScope?: readonly string[];
	readonly grantedAudience?: readonly string[];
}
