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

/**
 * What a policy returns. `outcome` must be exactly `"allow"` or `"deny"`:
 * any other value, or a value that is not such a record, is an invalid
 * decision, answered `500 server_error` and never allowed
 * (`readGrantPolicyDecision`). Each field is read once, into a plain copy
 * the provider acts on; a field that throws when read makes the decision
 * invalid.
 */
export type GrantPolicyDecision =
	| {
			readonly outcome: "allow";
			readonly grantedScope?: readonly string[];
			readonly grantedAudience?: readonly string[];
	  }
	| {
			readonly outcome: "deny";
			/**
			 * The OAuth `error` the refusal carries. At `/oauth/token` it is
			 * sent only when it is a token-endpoint code (RFC 6749 §5.2's, or
			 * `invalid_target`), and answered `invalid_grant` otherwise
			 * (`policyDenied`). At
			 * `/oauth/authorize` it must be an RFC 6749 error code,
			 * `1*NQSCHAR` (`isWellFormedErrorCode`), and is answered
			 * `access_denied` otherwise.
			 */
			readonly error: string;
			/**
			 * Sent as `error_description`, held to the same characters. One
			 * that is empty or not a string is not sent: `/oauth/token` sends
			 * no description, and `/oauth/authorize` its own default.
			 * `/oauth/token` drops one outside those characters.
			 */
			readonly errorDescription?: string;
	  };

/** Adapter primitive for grant-policy hooks. */
export interface GrantPolicyHook {
	readonly kind: string;
	evaluate(request: GrantPolicyRequest, ctx: GrantPolicyContext): Promise<GrantPolicyDecision>;
}

export type GrantPolicyHookFactory = AdapterFactory<GrantPolicyHook>;

// ---------------------------------------------------------------------------
// ComponentMap slot: `grantPolicy`, the optional gate every bundled
// token-minting path consults when it is wired. A grant handler a deployment
// contributes must call `evaluateGrantPolicy` itself. Absent, grant
// authorization allows all.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly grantPolicy?: GrantPolicyHook;
	}
}
