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

import type {
	GrantPolicyContext,
	GrantPolicyDecision,
	GrantPolicyHook,
	GrantPolicyRequest,
} from "../policy/types.mjs";
import type { GrantError } from "./types.mjs";

/**
 * The `allow` half of a {@link GrantPolicyDecision}, handed back so a caller
 * can read `grantedAudience` after the scope step has been applied.
 */
export type GrantPolicyAllow = Extract<GrantPolicyDecision, { outcome: "allow" }>;

export type GrantPolicyOutcome =
	| { readonly ok: true; readonly scopes: readonly string[]; readonly decision: GrantPolicyAllow }
	| { readonly ok: false; readonly result: GrantError };

/**
 * A decision the policy was not entitled to make — a scope or an audience
 * outside the ceiling the grant handed it (#520).
 *
 * `500 server_error`, not a 4xx. The request was well formed and the caller
 * did nothing wrong; the deployment's own policy code did, and an error that
 * says otherwise sends the wrong person looking. RFC 6749 §5.2 defines no
 * server-side code for the token endpoint, and the peers that met the same
 * gap answer the same way — node-oidc-provider, Keycloak and Spring
 * Authorization Server all return `server_error` there. A 5xx is also what an
 * operator's alerting watches: a broken policy filed among client mistakes is
 * a broken policy nobody notices.
 *
 * `deny` is not this — a policy that refuses is doing its job, and its answer
 * goes out as its own `400`. A policy that throws is `503
 * temporarily_unavailable`: an outage, not a fault.
 */
export function policyOutOfBounds(errorDescription: string): GrantError {
	return { status: 500, error: "server_error", errorDescription };
}

/**
 * Evaluate `grantPolicy` for a token grant, fail-closed (CP-18), and apply
 * its scope decision to the grant's already-narrowed effective scope.
 *
 * One home for the three rules every minting path applies, so the next grant
 * consults the policy by calling this rather than by knowing the folklore:
 *
 * - **A policy that throws is `503 temporarily_unavailable`**, never allow.
 *   Policy is a security boundary; failing open would grant the pre-policy
 *   ceiling, which is exactly what the policy exists to prevent.
 * - **`deny` is `400` with the policy's own error** and description.
 * - **`grantedScope` may only narrow.** It is re-validated against
 *   `effectiveScopes` — the request as already narrowed to every ceiling the
 *   grant knows — and not against a broader allowlist: a policy returning a
 *   scope the caller did not ask for is scope expansion even when the client
 *   would have been allowed it, and is answered by {@link policyOutOfBounds}.
 *   An empty array is honoured as "strip all" (CP-15). Absent, the effective
 *   scopes stand.
 *
 * `grantedAudience` is left on `decision` for the caller to hand to
 * {@link boundPolicyAudience} together with the ceiling its grant applies.
 */
export async function evaluateGrantPolicy(
	grantPolicy: GrantPolicyHook,
	request: GrantPolicyRequest,
	context: GrantPolicyContext,
	effectiveScopes: readonly string[],
): Promise<GrantPolicyOutcome> {
	let decision: GrantPolicyDecision;
	try {
		decision = await grantPolicy.evaluate(request, context);
	} catch {
		return {
			ok: false,
			result: {
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: "policy evaluation unavailable",
			},
		};
	}
	if (decision.outcome === "deny") {
		return {
			ok: false,
			result: {
				status: 400,
				error: decision.error,
				errorDescription: decision.errorDescription,
			},
		};
	}
	if (decision.grantedScope === undefined) {
		return { ok: true, scopes: effectiveScopes, decision };
	}
	if (!Array.isArray(decision.grantedScope)) {
		// #521: a JS policy returning a string passes a truthiness check, and
		// `.filter` would then throw a TypeError that dispatch does not catch —
		// fail-closed, but ungraceful. Refuse it as what it is.
		return { ok: false, result: policyOutOfBounds("policy returned a non-array grantedScope") };
	}
	const requestedSet = new Set(effectiveScopes);
	const exceeded = decision.grantedScope.filter((s) => !requestedSet.has(s));
	if (exceeded.length > 0) {
		return {
			ok: false,
			result: policyOutOfBounds(
				`policy returned scopes exceeding requested scope: ${exceeded.join(" ")}`,
			),
		};
	}
	return { ok: true, scopes: decision.grantedScope, decision };
}

export type PolicyAudienceOutcome =
	| { readonly ok: true; readonly audience: string | null }
	| { readonly ok: false; readonly result: GrantError };

/**
 * Apply the policy's audience decision within `ceiling` — the audiences the
 * grant may mint for, or `undefined` when nothing supplies one.
 *
 * Policy may narrow, never originate (#520):
 *
 * - No `grantedAudience`, or an empty one, is no decision: `audience` is
 *   `null` and the grant's own default applies.
 * - With no ceiling — no authenticated client, so no `allowedAudiences` — an
 *   audience from the policy has nothing to narrow within and is refused.
 *   This is the answer every scope ceiling gives a scope with nothing to
 *   bound it, and closes the one path a policy could once use to put ANY
 *   audience on a token.
 * - An entry outside the ceiling is refused: a buggy or compromised policy
 *   must not mint a token that a resource server the client was never
 *   registered for would accept.
 * - Otherwise the first entry is the audience. `generateToken` carries one
 *   `aud`; multi-audience tokens are out of scope for every grant that calls
 *   this.
 *
 * Both refusals are {@link policyOutOfBounds}: the policy exceeded its
 * authority, the caller did not.
 */
export function boundPolicyAudience(
	decision: GrantPolicyAllow,
	ceiling: readonly string[] | undefined,
): PolicyAudienceOutcome {
	const granted = decision.grantedAudience;
	if (granted === undefined) return { ok: true, audience: null };
	if (!Array.isArray(granted)) {
		// #521: the same guard as the scope half — a string would reach `.filter`.
		return { ok: false, result: policyOutOfBounds("policy returned a non-array grantedAudience") };
	}
	if (granted.length === 0) return { ok: true, audience: null };
	if (ceiling === undefined) {
		return {
			ok: false,
			result: policyOutOfBounds(
				"policy returned an audience but no authenticated client supplies an allowedAudiences ceiling",
			),
		};
	}
	const allowed = new Set(ceiling);
	const exceeded = granted.filter((a) => !allowed.has(a));
	if (exceeded.length > 0) {
		return {
			ok: false,
			result: policyOutOfBounds(
				`policy returned audiences outside client allowedAudiences: ${exceeded.join(" ")}`,
			),
		};
	}
	return { ok: true, audience: granted[0] ?? null };
}
