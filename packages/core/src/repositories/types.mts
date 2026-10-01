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
 * - `"private_key_jwt"`: a JWT the client signs with its own private key
 *   (RFC 7523 §2.2 / OIDC Core §9), verified under the keys registered as
 *   `jwks` or published at `jwksUri`. No shared secret anywhere.
 * - `"none"`: public client (no secret; PKCE/S256 mandatory per RFC 9700 §2.1.1)
 */
export type TokenEndpointAuthMethod =
	| "client_secret_basic"
	| "client_secret_post"
	| "private_key_jwt"
	| "none";

export interface Client {
	readonly clientId: string;
	/**
	 * Token-endpoint authentication method. Required: the schema rejects client
	 * entries that omit it.
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
	/**
	 * The client's public signing keys for `private_key_jwt`, inline (RFC 7591
	 * `jwks`). Exactly one of `jwks` / `jwksUri` when the method is
	 * `"private_key_jwt"`; neither for any other method. Public material: it
	 * rides along on `PublicClient`.
	 */
	readonly jwks?: { readonly keys: ReadonlyArray<Readonly<Record<string, unknown>>> };
	/**
	 * Where the client publishes those keys (RFC 7591 `jwks_uri`): `https`, or
	 * `http` on a loopback host. Fetched and cached at verification time, so
	 * rotating a key is a publish, not a re-registration.
	 */
	readonly jwksUri?: string;
	readonly allowedRedirectUris: readonly string[];
	readonly allowedScopes: readonly string[];
	/**
	 * What an omitted `scope` parameter grants. Absent: a scope-omitting request
	 * is refused with `invalid_scope` whenever `allowedScopes` is non-empty
	 * (deny-by-absence), so forgetting `scope` never yields the maximum grant. A
	 * client whose `allowedScopes` is empty is unaffected.
	 */
	readonly defaultScopes?: readonly string[];
	/**
	 * Audience URIs this client may receive tokens for.
	 *
	 * Consumers:
	 * - Token Exchange (RFC 8693) `audience` selection: when this list is empty
	 *   or absent, only the client's own `clientId` is accepted.
	 * - Every issuing grant's default `aud`: the first entry, with a
	 *   `grantPolicy` narrowing within the list. An absent list falls back to
	 *   the client id for a user-bound token and to the issuer for a client-only
	 *   one (`client_credentials`); see `AuthenticatedClient.allowedAudiences`
	 *   in `../grants/types.mts`.
	 * - Introspection's audience pin: an authenticated caller may ask about
	 *   tokens whose `aud` is in `allowedAudiences ∪ {clientId}`.
	 */
	readonly allowedAudiences?: readonly string[];
	/**
	 * Grant types this client is explicitly permitted to use.
	 *
	 * Enforced centrally by `isGrantTypeAllowed`, at `/oauth/token` grant
	 * dispatch before the handler runs and at `/authorize` against
	 * `authorization_code`, so every grant inherits the check:
	 *
	 * - absent: no restriction. The registration declared no policy; denying
	 *   would revoke every grant from registrations that predate the field.
	 * - `[]`: every grant is denied.
	 * - non-empty: a grant is allowed iff its `grant_type` is listed, compared
	 *   exactly.
	 *
	 * A grant that declares `requiresExplicitGrantAllowlist` (`client_credentials`,
	 * the WebAuthn grant) is denied by absence instead, so machine-to-machine
	 * access is never acquired by omission. Both rules run at dispatch; no
	 * handler carries its own copy of the check.
	 */
	readonly allowedGrantTypes?: readonly string[];
	// Logout metadata.
	readonly postLogoutRedirectUris?: readonly string[];
	readonly backchannelLogoutUri?: string;
	// default: true (includes sid in logout_token) — intentional deviation from OIDC Back-Channel
	// Logout 1.0 §2.2 spec default of false, to default to the safer behavior. See ClientEntrySchema.
	readonly backchannelLogoutSessionRequired?: boolean;
	readonly frontchannelLogoutUri?: string;
	// default: true (includes sid in frontchannel logout iframe URL) — intentional deviation from OIDC
	// Front-Channel Logout 1.0 spec default of false, to default to the safer behavior. See ClientEntrySchema.
	readonly frontchannelLogoutSessionRequired?: boolean;
	/**
	 * When true, this client MAY call POST /oauth/federation/:name/token to
	 * retrieve the user's upstream federation access_token. Deny by absence:
	 * such a token reaches the user's external resources (Google Calendar,
	 * GitHub API, ...), so a client registered only for auth must not get this
	 * by accident.
	 */
	readonly allowedAzpForFederationToken?: boolean;
	/**
	 * The federation grant connections this client may spend a grant on. Absent
	 * or empty means none, so no existing registration is opted in silently.
	 * Deny-by-absence and exact names, not a wildcard or pattern, for the reason
	 * {@link allowedAzpForFederationToken} is opt-in: a grant hands a client the
	 * user's access at an upstream, and the blast radius of a mistake is every
	 * user who ever connected.
	 */
	readonly allowedFederationGrantConnections?: readonly string[];
	/**
	 * Where the connect flow may return to for this client. Absent or empty
	 * means nowhere, and {@link allowedRedirectUris} is never inherited: the two
	 * flows end in different places, and a worker that only spends grants never
	 * performs the browser flow. Held to the same rules as any redirect URI.
	 */
	readonly federationGrantRedirectUris?: readonly string[];
	/**
	 * Sender-constraint requirement for this client. Surfaces through
	 * `PublicClient` (via `Omit`) and `AuthenticatedClient` (via the `/token`
	 * route's projection).
	 */
	readonly senderConstrained?: SenderConstraint;
	/**
	 * Whether this client is first-party: operated by the same organisation as
	 * this authorization server, and trusted to receive the user's identity
	 * without the user being asked.
	 *
	 * `GET /authorize` mints a code as soon as the session is authenticated,
	 * with no consent step. That is defensible only for a first-party client: a
	 * forced top-level navigation from an attacker's page makes a logged-in
	 * victim's browser mint a code delivered to the client's registered
	 * `redirect_uri`, so registering one semi-trusted client would turn the
	 * endpoint into an account-linking vector.
	 *
	 * `/authorize` therefore refuses any client that is not `true` here (absent
	 * or `false` alike), with no opt-out. This does not protect a first-party
	 * client against forced navigation (the accepted model; consent is what
	 * changes it); it stops an untrusted client from being registered into that
	 * position by accident.
	 */
	readonly firstParty?: boolean;
	/**
	 * Human-readable name of the client (RFC 7591 `client_name`), shown on the
	 * consent page a client that is not first-party is routed through.
	 */
	readonly clientName?: string;
	/**
	 * URL of the client's home page (RFC 7591 `client_uri`), shown on the
	 * consent page beside the name.
	 */
	readonly clientUri?: string;
	/**
	 * Whether this client may use the RFC 7636 `plain` PKCE challenge method.
	 *
	 * PKCE is mandatory for every authorization-code client and `S256` is the
	 * only method otherwise accepted. There is deliberately no server-wide
	 * switch: admitting `plain` is a named exception for a named registration,
	 * visible in the client record.
	 *
	 * `plain` stores the verifier as the challenge, so anything that can read
	 * the authorization request (browser history, a proxy log, a referrer)
	 * learns the verifier and PKCE proves nothing. Set this only for a legacy
	 * client that cannot compute SHA-256, as a migration deadline.
	 *
	 * Absent and `false` both mean S256 only. Like `firstParty`, the check is a
	 * strict `=== true`, so an uncoerced `"true"` from YAML or an environment
	 * variable does not widen the policy. Surfaces through `PublicClient` and
	 * `AuthenticatedClient` so `/authorize` and `/token` read the same value.
	 */
	readonly allowPlainPkce?: boolean;
}

/**
 * A user as returned by a {@link UserRepository}, published by **the Store**:
 * auth.provider's term for the consumer's upstream user service, the system of
 * record for identity, credentials and email-verification state. auth.provider
 * reads Store-published state and causes a write there only through the two
 * optional relays its own flows need (`UserRepository.linkFederatedIdentity`
 * and `markMfaEnrolled`); `HttpUserRepository` in
 * `@o3co/auth-provider-foundation` is the shipped client. This is the term's
 * definition site (see docs/design-vocabulary.md in the repository).
 *
 * The claim-bearing fields mirror `UserSessionClaims` and are what
 * `extractUserClaims` reads when seeding a session's claims envelope. They are
 * declared rather than left to the index signature because a Store is reached
 * across an untyped boundary (`HttpUserRepository` parses JSON).
 * `email_verified` in a token only reflects Store-owned state: issuing,
 * delivering and applying the verification belong to the Store.
 *
 * `mfaEnrolled` is not a claim: it is the MFA enrollment witness, read by the
 * MFA package and never stamped on a token. The index signature carries
 * custom claims, which a consumer may map through a custom claim filter.
 *
 * A `User` is plain data: its own enumerable data properties, holding
 * primitives, arrays and objects whose prototype is `Object.prototype` or
 * `null` — what JSON parses to. A login refuses anything else with a
 * `RangeError` (a `500`): a copy would lose a field an accessor, a prototype
 * or a non-enumerable property holds, and read the witness as not enrolled.
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
	/**
	 * The MFA enrollment witness: whether this user has enrolled a second
	 * factor, as the Store answers it on `authenticate`. It lives outside the
	 * factor store so that losing that store does not read as "never enrolled",
	 * which would let whoever holds the password bind their own authenticator.
	 * Read it only through `readMfaEnrollmentWitness`; the provider writes it
	 * through `UserRepository.markMfaEnrolled` where the repository has it. See
	 * the MFA ADR (2026-09-25-multi-factor-authentication), D12.
	 */
	readonly mfaEnrolled?: boolean;
	readonly [key: string]: unknown;
}

/**
 * Data persisted in the code record at /authorize time.
 *
 * `consumeByCode` (atomic single-use) is the sole authenticity gate; the
 * record's `client_id` and `redirect_uri` bind the code to its client.
 *
 * Every field is a required key, holding `undefined` where `/authorize`
 * recorded nothing. `/token` reads the record back without deciding anything
 * again, and a repository copies it field by field; a required key makes a
 * copy that forgets `nonce`, `acr` or `sid` a compile error at the object
 * literal, instead of an id_token silently missing the claim.
 */
export interface CodeData {
	readonly client_id: string;
	readonly redirect_uri: string; // must match at /token (RFC 6749 §4.1.3)
	readonly code_challenge: string | undefined;
	readonly code_challenge_method: string | undefined;
	// OIDC authorize → token round-trip state.
	readonly nonce: string | undefined;
	readonly sid: string | undefined;
	/** The acr `/authorize` satisfied for this request; the id_token's `acr`. */
	readonly acr: string | undefined;
}

export interface Code extends CodeData {
	readonly code: string;
	readonly expiresIn: number | undefined;
	readonly grantedScope: readonly string[] | undefined;
	readonly grantedAudience: readonly string[] | undefined;
}
