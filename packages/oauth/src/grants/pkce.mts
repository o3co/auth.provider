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

import type { Logger } from "@o3co/auth-provider-core";

/** RFC 7636 §4.2 — SHA-256 challenge. The only method this AS admits by default. */
export const PKCE_METHOD_S256 = "S256";
/** RFC 7636 §4.2 — the verifier itself. Reachable only through a per-client opt-in. */
export const PKCE_METHOD_PLAIN = "plain";

/**
 * What an absent `code_challenge_method` means.
 *
 * RFC 7636 §4.3 defines the parameter as OPTIONAL and defaulting to `plain`,
 * so absence is a *request for plain* and is resolved as one here. Since
 * `plain` is not in a client's method list unless the operator opted that
 * client in, an omitted method is refused at the request boundary.
 *
 * Reading absence as `S256` instead would be worse, not stricter: a client
 * that computed its challenge the RFC 7636 way (challenge = verifier) would
 * be accepted at `/authorize` and then fail the digest comparison at
 * `/token` — a code doomed at redemption, which is exactly the class of bug
 * #273 exists to remove.
 */
export const PKCE_METHOD_ABSENT_DEFAULT = PKCE_METHOD_PLAIN;

const S256_ONLY: readonly string[] = Object.freeze([PKCE_METHOD_S256]);
const S256_AND_PLAIN: readonly string[] = Object.freeze([PKCE_METHOD_S256, PKCE_METHOD_PLAIN]);

/**
 * The resolved PKCE policy — the ONE object `/authorize` (through
 * `ResolvedOAuthOptions.pkce`) and `/token` (through the authorization grant's
 * own `resolveOAuthOptions` call) both read.
 *
 * Before #273 there were three sources of truth: `pkce.required`,
 * `pkce.supportedMethods` / `pkce.defaultMethod`, and the legacy `requireS256`
 * boolean that only the token endpoint honoured. `/authorize` could therefore
 * mint a `plain` code that `/token` refused, and a confidential client could
 * skip PKCE altogether.
 */
export interface ResolvedPkceOptions {
	/**
	 * Always `true`, and typed as the literal so no code path can branch on a
	 * `false` that cannot occur.
	 *
	 * OAuth 2.1 §4.1.1 and RFC 9700 §2.1.1 require PKCE of **every**
	 * authorization-code client, confidential ones included: the client secret
	 * proves who is redeeming the code, not that the redeemer is the party the
	 * code was issued to. Without a verifier, an authorization code captured
	 * from the redirect (browser history, referrer, a compromised or
	 * open-redirecting hop) is replayable by anyone who can also authenticate
	 * as the client — which includes the client's own compromised backend and
	 * every mix-up/injection attack RFC 9700 §4.5 catalogues.
	 */
	readonly required: true;
	/**
	 * The methods admitted for a client that carries no explicit opt-in:
	 * `["S256"]`, always. This is deliberately NOT operator-tunable — see
	 * `resolvePkceOptions`. Per-client widening goes through
	 * `pkceMethodsForClient`.
	 */
	readonly supportedMethods: readonly string[];
}

const PKCE_OPTIONS: ResolvedPkceOptions = Object.freeze({
	required: true as const,
	supportedMethods: S256_ONLY,
});

/**
 * The client-registration fields the PKCE policy reads. Structural on purpose:
 * `PublicClient` (at `/authorize`) and `AuthenticatedClient` (at `/token`) are
 * different projections of the same registration, and both satisfy this.
 */
export interface PkceClientView {
	readonly allowPlainPkce?: boolean;
}

/**
 * The challenge methods this client may use: the resolved policy's baseline,
 * widened by the client's own opt-in.
 *
 * Both endpoints call this with the SAME resolved `policy` — `/authorize`
 * from `ResolvedOAuthOptions.pkce`, `/token` from its own
 * `resolveOAuthOptions` call over the same config — and with the same client
 * registration. That is what makes a code minted by `/authorize` redeemable
 * at `/token` by construction rather than by two implementations agreeing.
 *
 * `plain` is reachable **only** here, and only for a registration that carries
 * a literal `allowPlainPkce: true`. There is no global default and no
 * server-wide allowlist that can produce it, so admitting `plain` is always a
 * named, per-client, operator decision that is visible in the client record —
 * not a deployment-wide setting that quietly covers every client at once.
 *
 * The strict `=== true` matches the `firstParty` / `requireEmailVerified`
 * convention: a YAML or environment value that never passed a boolean schema
 * (`"true"`, `1`) must not widen a security policy.
 */
export const pkceMethodsForClient = (
	policy: ResolvedPkceOptions,
	client: PkceClientView | null | undefined,
): readonly string[] => {
	if (client?.allowPlainPkce !== true) return policy.supportedMethods;
	// The opt-in is additive, and `plain` is the only thing it can add. The
	// `includes` guard keeps the result stable if the baseline ever grows.
	return policy.supportedMethods.includes(PKCE_METHOD_PLAIN)
		? policy.supportedMethods
		: policy.supportedMethods === S256_ONLY
			? S256_AND_PLAIN
			: Object.freeze([...policy.supportedMethods, PKCE_METHOD_PLAIN]);
};

/**
 * Keys that used to shape PKCE policy and no longer do. Order is the order
 * they are reported in, so the warning reads the same for a given config.
 */
const INERT_PKCE_KEYS: readonly string[] = Object.freeze([
	// Legacy boolean (B-7 era). Only `/token` honoured it, and it meant
	// "narrow supportedMethods to S256" — which is now unconditional.
	"requireS256",
	// Superseded by `ResolvedPkceOptions.required`, which cannot be false.
	"required",
	// Superseded by `PKCE_METHOD_ABSENT_DEFAULT` (RFC 7636 §4.3).
	"defaultMethod",
	// Superseded by `pkceMethodsForClient` — per client, not per deployment.
	"supportedMethods",
]);

/**
 * Resolves the PKCE policy from the untyped `oauth.grants.authorization_code.pkce`
 * block — which is to say: ignores it, and says so.
 *
 * Every knob that block used to carry could only ever *weaken* the policy
 * (turn PKCE off, or admit `plain` server-wide), so #273 removes them rather
 * than re-validating them. A config that still sets one is not a boot failure:
 * the stale value is inert and the resulting behaviour is strictly stronger
 * than what the operator asked for, so failing closed would take a deployment
 * down over a key that is now harmless. It is warned about instead, once, at
 * router composition — the same altitude `resolveOAuthOptions` resolves
 * everything else at, so an operator sees one boot-time line rather than one
 * per request.
 *
 * The previous `resolvePkceSupportedMethods` helper (TS-4) is gone with the
 * knob it validated: its whole job was to stop an operator-typed
 * `supportedMethods` array from silently widening the allowlist, and there is
 * no longer an operator-typed allowlist to widen.
 */
export const resolvePkceOptions = (
	pkceConfig: Record<string, unknown> | undefined,
	logger?: Logger,
): ResolvedPkceOptions => {
	if (pkceConfig) {
		const ignoredKeys = INERT_PKCE_KEYS.filter((key) => pkceConfig[key] !== undefined);
		if (ignoredKeys.length > 0) {
			// Object-first call shape per the F5 D-4 Logger convention.
			logger?.warn(
				{ ignoredKeys },
				// The message names the outcome, not the keys, so an operator
				// grepping logs for why `plain` stopped working finds it.
				"pkce_config_ignored_s256_is_mandatory",
			);
		}
	}
	return PKCE_OPTIONS;
};
