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

export interface Client {
	clientId: string;
	clientSecret: string;
	allowedRedirectUris: string[];
	allowedScopes: string[];
	/**
	 * Audience URIs that this client may request in Token Exchange (RFC 8693)
	 * `audience` parameter. Empty or undefined means only the client's own
	 * clientId is allowed as audience. Not used outside Token Exchange.
	 */
	allowedAudiences?: string[];
	// NEW (TODO-F-5): Logout metadata.
	postLogoutRedirectUris?: string[];
	backchannelLogoutUri?: string;
	// default: true (includes sid in logout_token) — intentional deviation from OIDC Back-Channel
	// Logout 1.0 §2.2 spec default of false, to default to the safer behavior. See ClientEntrySchema.
	backchannelLogoutSessionRequired?: boolean;
	frontchannelLogoutUri?: string;
	// default: true (includes sid in frontchannel logout iframe URL) — intentional deviation from OIDC
	// Front-Channel Logout 1.0 spec default of false, to default to the safer behavior. See ClientEntrySchema.
	frontchannelLogoutSessionRequired?: boolean;
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
	allowedAzpForFederationToken?: boolean;
}

export interface User {
	id: string;
	username: string;
	[key: string]: unknown;
}

/**
 * Data persisted in the code record at /authorize time.
 *
 * `consumeByCode` (atomic single-use) is the sole authenticity gate; `client_id`
 * and `redirect_uri` embedded in the record replace the session-based identity
 * gates removed in v0.5.1 (see CHANGELOG and the D-1 spec at
 * `auth/.claude/superpowers/specs/2026-05-05-d1-code-repository-rewrite.md`).
 *
 * Breaking change for custom CodeRepository implementations: `client_id` and
 * `redirect_uri` are now required. The compile-time guard
 * `Parameters<CodeRepository["createCode"]>[0]` makes any implementation that
 * misses either field fail typecheck at the destructure site.
 */
export interface CodeData {
	client_id: string; // required — replaces the session.code_client_id gate
	redirect_uri: string; // required — closes IH-4 vacuous-pass (RFC 6749 §4.1.3)
	code_challenge?: string;
	code_challenge_method?: string;
	// NEW (TODO-F-3): OIDC authorize → token round-trip state.
	// These fields are persisted at /authorize and read at /token.
	nonce?: string;
	sid?: string;
}

export interface Code extends CodeData {
	code: string;
	expiresIn?: number;
	grantedScope?: readonly string[];
	grantedAudience?: readonly string[];
}
