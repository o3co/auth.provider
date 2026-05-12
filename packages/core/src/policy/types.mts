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

import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";

export interface GrantPolicyRequest {
	readonly grantType: string;
	readonly clientId?: string;
	readonly subject?: string;
	readonly requestedScope?: readonly string[];
	readonly requestedAudience?: readonly string[];
	readonly originalScope?: readonly string[];
	readonly subjectTokenType?: string;
	readonly actorTokenType?: string;
	readonly resource?: readonly string[];
	readonly extras?: Record<string, unknown>;
}

export interface GrantPolicyContext {
	readonly ip?: string;
	readonly userAgent?: string;
	readonly issuer: string;
}

export type GrantPolicyDecision =
	| {
			readonly outcome: "allow";
			readonly grantedScope?: readonly string[];
			readonly grantedAudience?: readonly string[];
	  }
	| {
			readonly outcome: "deny";
			readonly error: string;
			readonly errorDescription?: string;
	  };

/**
 * Adapter primitive for grant-policy hooks.
 *
 * NOTE: this name previously coexisted with a contributes-map placeholder
 * (`type GrantPolicyHook = unknown`) at
 * `packages/core/src/modules/manifest/contributes-map.mts`. The v0.5.1
 * AS-7 collision resolution renamed that placeholder to
 * `GrantPolicyHookContribution`, freeing this name for the canonical
 * interface; the `*Base` deprecation alias previously exposed alongside
 * was removed.
 */
export interface GrantPolicyHook {
	readonly kind: string;
	evaluate(request: GrantPolicyRequest, ctx: GrantPolicyContext): Promise<GrantPolicyDecision>;
}

export type GrantPolicyHookFactory = AdapterFactory<GrantPolicyHook>;

// ---------------------------------------------------------------------------
// ComponentMap slot declaration (per A2-α §6.1)
//
// `grantPolicy` is an optional component consumed by oauthModule routes
// (POST /oauth/token grantPolicy.evaluate gate). When absent, grant
// authorization proceeds with the default policy (allow-all).
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly grantPolicy?: GrantPolicyHook;
	}
}
