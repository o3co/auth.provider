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

/** RFC 7636 §4.2 — SHA-256 challenge. The only method this AS admits by default. */
export const PKCE_METHOD_S256 = "S256";
/** RFC 7636 §4.2 — the verifier itself. Reachable only through a per-client opt-in. */
export const PKCE_METHOD_PLAIN = "plain";

/**
 * What an absent `code_challenge_method` means: a request for `plain` (RFC
 * 7636 §4.3: OPTIONAL, defaulting to `plain`), refused unless the client
 * opted into `plain`. Reading absence as `S256` would accept at `/authorize`
 * a client whose challenge is its verifier and fail it at `/token`: a code
 * doomed at redemption.
 */
export const PKCE_METHOD_ABSENT_DEFAULT = PKCE_METHOD_PLAIN;

const S256_ONLY: readonly string[] = Object.freeze([PKCE_METHOD_S256]);

/**
 * The resolved PKCE policy: the one object `/authorize` (through
 * `ResolvedOAuthOptions.pkce`) and `/token` (through the authorization grant's
 * own `resolveOAuthOptions` call) both read, so they cannot disagree.
 */
export interface ResolvedPkceOptions {
	/**
	 * Always `true`, typed as the literal so nothing can branch on `false`.
	 * OAuth 2.1 §4.1.1 and RFC 9700 §2.1.1 require PKCE of every
	 * authorization-code client, confidential ones included: the client secret
	 * proves who redeems the code, not that the redeemer is the party it was
	 * issued to. Without a verifier, a code captured from the redirect is
	 * replayable by anyone who can also authenticate as the client, including
	 * through the mix-up and injection attacks of RFC 9700 §4.5.
	 */
	readonly required: true;
	/**
	 * The methods for a client without an opt-in: `["S256"]`, always, and
	 * not operator-tunable (see `resolvePkceOptions`). Per-client widening
	 * goes through `pkceMethodsForClient`.
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
 * The challenge methods this client may use: the policy's baseline, widened
 * by the client's own opt-in. Both endpoints call this with the same policy
 * and registration, so a code minted by `/authorize` is redeemable at `/token`
 * by construction.
 *
 * `plain` is reachable only here, for a registration with a literal
 * `allowPlainPkce: true`: always a per-client operator decision visible in
 * the client record, never a deployment-wide setting. The strict `=== true`
 * (as for `firstParty` / `requireEmailVerified`) keeps a value that never
 * passed a boolean schema (`"true"`, `1`) from widening a security policy.
 */
export const pkceMethodsForClient = (
	policy: ResolvedPkceOptions,
	client: PkceClientView | null | undefined,
): readonly string[] =>
	// Appended to `policy`'s baseline rather than a second constant, so the
	// widened list also comes from the one object both endpoints read.
	client?.allowPlainPkce === true
		? Object.freeze([...policy.supportedMethods, PKCE_METHOD_PLAIN])
		: policy.supportedMethods;

/**
 * The PKCE policy: required, with `S256` alone for a client without an
 * opt-in. Fixed, not configuration: every key a deployment-wide setting could
 * carry would only weaken it (turn PKCE off, or admit `plain` for every
 * client).
 */
export const resolvePkceOptions = (): ResolvedPkceOptions => PKCE_OPTIONS;
