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
	 * A grant handler that declares `requiresExplicitGrantAllowlist` on its
	 * `GrantHandler` contract composes a **stricter** rule on top: dispatch
	 * denies by absence for that grant, so machine-to-machine access is
	 * never acquired by omission (#326). `client_credentials`
	 * (`grants/clientCredentials.mts`) and the WebAuthn grant
	 * (`@o3co/auth-provider-webauthn`) declare it. Both rules are enforced
	 * at dispatch — either can reject, and only the absent case
	 * distinguishes them; no handler carries its own copy of the check.
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
	/**
	 * Whether this client is first-party — i.e. operated by the same
	 * organisation as this authorization server, and trusted to receive the
	 * user's identity without the user being asked (#267).
	 *
	 * `GET /authorize` mints an authorization code as soon as the session is
	 * authenticated, with no consent step. That is defensible in a pure
	 * first-party OP and only there: a forced top-level navigation from an
	 * attacker's page makes a logged-in victim's browser mint a code, bound to
	 * the victim's session, delivered to the named client's registered
	 * `redirect_uri`. Registering one semi-trusted client turns the endpoint
	 * into an account-linking vector.
	 *
	 * So the assumption is now enforced rather than assumed: `/authorize`
	 * refuses any client that is not `true` here — one with no `firstParty`
	 * field and one carrying an explicit `false` alike. There is no opt-out:
	 * the one-time `oauth.authorize.allowUnmarkedClients` migration flag that
	 * admitted unmarked registrations (#317) was removed in #330, and a config
	 * still setting it fails at boot with migration instructions.
	 *
	 * This does **not** make `/authorize` safe against forced navigation for a
	 * client that *is* first-party — that is the accepted model, and the
	 * user-interaction step which changes it is consent (#284). What the flag
	 * closes is the escalation: a client that should never have been trusted
	 * with a silent code cannot be registered into that position by accident.
	 */
	readonly firstParty?: boolean;
	/**
	 * Whether this client may use the RFC 7636 `plain` PKCE challenge method
	 * (#273).
	 *
	 * PKCE is mandatory for every authorization-code client and `S256` is the
	 * only method the authorization server accepts — there is no server-wide
	 * setting that admits `plain`, because a deployment-wide one would quietly
	 * cover every client at once. This flag is the ONLY way to reach it, and it
	 * is deliberately per client: admitting `plain` is a named exception for a
	 * named registration, visible in the client record itself.
	 *
	 * `plain` stores the verifier as the challenge, so anything that can read
	 * the authorization request (browser history, a proxy log, a referrer)
	 * learns the verifier too and PKCE stops proving anything. Set this only
	 * for a legacy client that genuinely cannot compute SHA-256, and treat it
	 * as a migration deadline rather than a configuration.
	 *
	 * Absent and `false` are the same: S256 only. Like `firstParty`, the check
	 * is a strict `=== true`, so an uncoerced `"true"` from YAML or an
	 * environment variable does not widen the policy.
	 *
	 * Surfaces through `PublicClient` (via `Omit`) and `AuthenticatedClient`
	 * (via the `/token` route's projection) so `/authorize` and `/token` read
	 * the same value.
	 */
	readonly allowPlainPkce?: boolean;
}

/**
 * A user as returned by a {@link UserRepository}.
 *
 * The claim-bearing fields below are the ones `extractUserClaims` reads when
 * seeding a session's claims envelope, and they mirror `UserSessionClaims`
 * exactly. They are declared rather than left to the index signature because a
 * Store is reached across an untyped boundary — `HttpUserRepository` parses
 * JSON — and until #297 the only thing telling an implementer that
 * `emailVerified` was a *boolean* was the runtime `typeof` check that silently
 * dropped it when it wasn't.
 *
 * `email_verified` in an issued token is Store-owned state that auth.provider
 * only reflects. Issuing the verification token, delivering it, and flipping
 * the state belong to the Store; this library reads the result and binds it
 * into the artifact (responsibility #4).
 *
 * The index signature stays: a Store may carry custom claims beyond these, and
 * a consumer may map them through a custom claim filter.
 */
export interface User {
	readonly id: string;
	readonly username: string;
	/** Surfaced as the `email` claim under the `email` scope. */
	readonly email?: string;
	/**
	 * Surfaced as the OIDC `email_verified` claim under the `email` scope.
	 *
	 * `false` and absent are **not** the same, and both reach relying parties
	 * distinguishably: `false` says the Store tracks verification and this
	 * address is not verified; absence says the Store does not model it at all.
	 * A non-boolean is dropped rather than forwarded, so a truthy string cannot
	 * become an affirmative claim in a signed token.
	 */
	readonly emailVerified?: boolean;
	/** Surfaced as the `name` claim under the `profile` scope. */
	readonly name?: string;
	/** Surfaced as the `picture` claim under the `profile` scope. */
	readonly picture?: string;
	/** Surfaced as the non-standard `groups` claim under the `groups` scope. */
	readonly groups?: readonly string[];
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
