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
}

export interface User {
	id: string;
	username: string;
	[key: string]: unknown;
}

export interface CodeData {
	code_challenge?: string;
	code_challenge_method?: string;
	redirect_uri?: string;
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
