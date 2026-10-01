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

import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { loggableError } from "../logging/loggableError.mjs";
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

/** The `deny` half of a {@link GrantPolicyDecision}. */
export type GrantPolicyDeny = Extract<GrantPolicyDecision, { outcome: "deny" }>;

/**
 * A policy's decision as the provider acts on it ({@link readGrantPolicyDecision}):
 * its `verdict`, `allow` or `deny`, or `invalid` with the answer every caller
 * gives one.
 */
export type GrantPolicyReading =
	| { readonly verdict: "allow"; readonly decision: GrantPolicyAllow }
	| { readonly verdict: "deny"; readonly decision: GrantPolicyDeny }
	| {
			readonly verdict: "invalid";
			/** `500 server_error` with a fixed description: nothing the policy returned is quoted. */
			readonly result: GrantError & { readonly errorDescription: string };
	  };

/** The scopes a policy's `grantedScope` may reach, and what to call them in a refusal. */
export interface PolicyScopeCeiling {
	readonly scopes: readonly string[];
	readonly name: string;
}

export type GrantPolicyOutcome =
	| { readonly ok: true; readonly scopes: readonly string[]; readonly decision: GrantPolicyAllow }
	| { readonly ok: false; readonly result: GrantError };

/**
 * A decision the policy was not entitled to make: a scope or an audience
 * outside the ceiling the grant handed it.
 *
 * `500 server_error`, not a 4xx: the caller did nothing wrong, the
 * deployment's policy code did, and a 5xx is what an operator's alerting
 * watches. RFC 6749 §5.2 defines no server-side code for the token endpoint;
 * node-oidc-provider, Keycloak and Spring Authorization Server also answer
 * `server_error` here.
 *
 * Not `deny` (a policy doing its job, answered `400`), nor a policy that
 * throws (`503 temporarily_unavailable`, an outage).
 */
export function policyOutOfBounds(errorDescription: string): GrantError {
	return { status: 500, error: "server_error", errorDescription };
}

/**
 * Core's answer to a grant policy that throws: `503 temporarily_unavailable`
 * with a fixed description that quotes nothing the policy threw. The policy
 * could not answer, as a store that cannot be read could not.
 */
export function policyUnavailable(): GrantError & { readonly errorDescription: string } {
	return {
		status: 503,
		error: "temporarily_unavailable",
		errorDescription: "policy evaluation unavailable",
	};
}

/**
 * Logs a grant policy that threw — it could not answer, and the request is
 * refused `503 temporarily_unavailable` — as `grant_policy_unavailable` at
 * error level, with the grant type, the policy's `kind`, the caller's `site`
 * when it is not a token grant, and the error's projection — on core's console
 * logger when `logger` is absent. A policy that calls out to a decision
 * service fails the way a store does, and is answered and logged the same way.
 */
export function logGrantPolicyUnavailable(
	logger: Pick<Logger, "error"> | undefined,
	context: { readonly grantType: string; readonly policy: string; readonly site?: string },
	cause: unknown,
): void {
	(logger ?? consoleLogger).error(
		{
			...(context.site !== undefined ? { site: context.site } : {}),
			grantType: context.grantType,
			policy: context.policy,
			err: loggableError(cause),
		},
		"grant_policy_unavailable",
	);
}

/**
 * The one reading of what a grant policy returned. Only an `outcome` that is
 * exactly `"allow"` allows, and only one that is exactly `"deny"` refuses;
 * anything else — another string or case, no `outcome`, a value that is not
 * an object, a field that throws when read — is `invalid`, never allow.
 *
 * The decision handed back is a plain copy, each field read once —
 * `outcome`, `grantedScope` and `grantedAudience` for allow, `outcome`,
 * `error` and `errorDescription` for deny, an array copied element by
 * element — so a getter or a proxy cannot answer the caller's check one
 * value and its use another. Callers act on the copy alone.
 *
 * An invalid decision is the deployment's policy at fault, not the caller, and
 * not an outage: `500 server_error`, as {@link policyOutOfBounds} answers.
 * It is logged once as `grant_policy_decision_invalid` at error level, with
 * the grant type, the policy's `kind` and the caller's `site` when it is not
 * a token grant — never the decision itself — on core's console logger when
 * `logger` is absent.
 */
export function readGrantPolicyDecision(
	decision: unknown,
	logger: Pick<Logger, "error"> | undefined,
	context: { readonly grantType: string; readonly policy: string; readonly site?: string },
): GrantPolicyReading {
	const reading = snapshotOf(decision);
	if (reading !== undefined) return reading;
	(logger ?? consoleLogger).error(
		{
			...(context.site !== undefined ? { site: context.site } : {}),
			grantType: context.grantType,
			policy: context.policy,
		},
		"grant_policy_decision_invalid",
	);
	return {
		verdict: "invalid",
		result: { status: 500, error: "server_error", errorDescription: "policy_decision_invalid" },
	};
}

/**
 * `decision` as an allow or a deny, each field read once into a plain copy;
 * `undefined` when it is neither or a field throws when read.
 */
function snapshotOf(
	decision: unknown,
): Exclude<GrantPolicyReading, { readonly verdict: "invalid" }> | undefined {
	if (typeof decision !== "object" || decision === null) return undefined;
	const fields = decision as Readonly<Record<string, unknown>>;
	try {
		const outcome = fields.outcome;
		if (outcome === "allow") {
			const grantedScope = copied(fields.grantedScope);
			const grantedAudience = copied(fields.grantedAudience);
			return {
				verdict: outcome,
				decision: {
					outcome,
					...(grantedScope !== undefined ? { grantedScope } : {}),
					...(grantedAudience !== undefined ? { grantedAudience } : {}),
				} as GrantPolicyAllow,
			};
		}
		if (outcome === "deny") {
			const error = fields.error;
			const errorDescription = fields.errorDescription;
			return {
				verdict: outcome,
				decision: {
					outcome,
					error,
					...(errorDescription !== undefined ? { errorDescription } : {}),
				} as GrantPolicyDeny,
			};
		}
	} catch {
		// A field that throws when read is a decision that cannot be read.
	}
	return undefined;
}

/** An array as a plain array of its elements; any other value as it is. */
function copied(value: unknown): unknown {
	return Array.isArray(value) ? Array.from(value) : value;
}

/** The rest of {@link evaluateGrantPolicy}'s inputs. */
export interface EvaluateGrantPolicyOptions {
	/** A ceiling wider than `effectiveScopes` (the refresh grant's original grant). */
	readonly scopeCeiling?: PolicyScopeCeiling;
	/**
	 * Where a policy that throws (`grant_policy_unavailable`) or returns an
	 * invalid decision (`grant_policy_decision_invalid`) is logged. Required
	 * as a key, not as a value: a grant that has no logger passes `undefined`
	 * and says so, and one that forgets fails to compile. `undefined` writes
	 * both lines to core's console logger.
	 */
	readonly logger: Pick<Logger, "error"> | undefined;
}

/**
 * Evaluate `grantPolicy` for a token grant, fail-closed, and apply its scope
 * decision to the grant's already-narrowed effective scope. The rules every
 * minting path applies:
 *
 * - **A policy that throws is `503 temporarily_unavailable`**
 *   ({@link policyUnavailable}), never allow: failing open would grant the
 *   pre-policy ceiling the policy exists to narrow. Logged as
 *   `grant_policy_unavailable` ({@link logGrantPolicyUnavailable}).
 * - **A decision that is neither `allow` nor `deny` is `500 server_error`**,
 *   never allow ({@link readGrantPolicyDecision}).
 * - **`deny` is `400` with the policy's own error** and description.
 * - **`grantedScope` may only narrow.** It is checked against the ceiling
 *   (by default `effectiveScopes`, the request already narrowed to every
 *   ceiling the grant knows), not a broader allowlist: a scope the caller did
 *   not ask for is expansion even when the client would have been allowed
 *   it ({@link policyOutOfBounds}). An empty array strips all; absent, the
 *   effective scopes stand.
 *
 * `grantedAudience` stays on `decision` for the caller to pass to
 * {@link boundPolicyAudience}. `options.scopeCeiling` is for `refresh_token`,
 * whose `grantedScope` may reach anything in the original grant (RFC 6749 §6).
 */
export async function evaluateGrantPolicy(
	grantPolicy: GrantPolicyHook,
	request: GrantPolicyRequest,
	context: GrantPolicyContext,
	effectiveScopes: readonly string[],
	options: EvaluateGrantPolicyOptions,
): Promise<GrantPolicyOutcome> {
	const { logger } = options;
	const scopeCeiling = options.scopeCeiling ?? {
		scopes: effectiveScopes,
		name: "requested scope",
	};
	let answer: unknown;
	try {
		answer = await grantPolicy.evaluate(request, context);
	} catch (err) {
		logGrantPolicyUnavailable(
			logger,
			{ grantType: request.grantType, policy: grantPolicy.kind },
			err,
		);
		return { ok: false, result: policyUnavailable() };
	}
	const reading = readGrantPolicyDecision(answer, logger, {
		grantType: request.grantType,
		policy: grantPolicy.kind,
	});
	if (reading.verdict === "invalid") return { ok: false, result: reading.result };
	if (reading.verdict === "deny") {
		return {
			ok: false,
			result: {
				status: 400,
				error: reading.decision.error,
				errorDescription: reading.decision.errorDescription,
			},
		};
	}
	const { decision } = reading;
	if (decision.grantedScope === undefined) {
		return { ok: true, scopes: effectiveScopes, decision };
	}
	if (!Array.isArray(decision.grantedScope)) {
		// A JS policy's string passes a truthiness check, and `.filter` would then
		// throw a TypeError dispatch does not catch. Refuse it as what it is.
		return { ok: false, result: policyOutOfBounds("policy returned a non-array grantedScope") };
	}
	const ceilingSet = new Set(scopeCeiling.scopes);
	const exceeded = decision.grantedScope.filter((s) => !ceilingSet.has(s));
	if (exceeded.length > 0) {
		return {
			ok: false,
			result: policyOutOfBounds(
				`policy returned scopes exceeding ${scopeCeiling.name}: ${exceeded.join(" ")}`,
			),
		};
	}
	return { ok: true, scopes: decision.grantedScope, decision };
}

export type PolicyAudienceOutcome =
	| { readonly ok: true; readonly audience: string | null }
	| { readonly ok: false; readonly result: GrantError };

/**
 * Apply the policy's audience decision within `ceiling`: the audiences the
 * grant may mint for, or `undefined` when nothing supplies one. Policy may
 * narrow, never originate:
 *
 * - No `grantedAudience`, or an empty one, is no decision: `audience` is
 *   `null` and the grant's own default applies.
 * - With no ceiling (no authenticated client, so no `allowedAudiences`), a
 *   policy audience has nothing to narrow within and is refused, as a scope
 *   with no ceiling would be. Otherwise a policy could put ANY audience on a
 *   token.
 * - An entry outside the ceiling is refused: a buggy or compromised policy
 *   must not mint a token for a resource server the client was never
 *   registered for.
 * - Otherwise the first entry is the audience; `generateToken` carries one
 *   `aud`.
 *
 * Both refusals are {@link policyOutOfBounds}.
 */
export function boundPolicyAudience(
	decision: GrantPolicyAllow,
	ceiling: readonly string[] | undefined,
): PolicyAudienceOutcome {
	const granted = decision.grantedAudience;
	if (granted === undefined) return { ok: true, audience: null };
	if (!Array.isArray(granted)) {
		// The same guard as the scope half: a string would reach `.filter`.
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
