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

import type { ValidatedToken } from "./validator/types.mjs";

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Build the `act` claim for the token being issued, per RFC 8693 §4.1.
 *
 * Canonical rules:
 * - No actor_token → no `act` on the issued token (impersonation, no trace).
 *                    We do NOT inherit `subject.act`: absence of actor_token
 *                    means the caller is not claiming to delegate for anyone.
 * - Actor provided  → `act.sub = <actor.sub>`. If the subject already had an
 *                     `act` chain, it is nested as `act.act` to preserve the
 *                     full delegation history.
 */
export function buildActClaim(args: {
	subject: ValidatedToken;
	actor: ValidatedToken | undefined;
}): Record<string, unknown> | undefined {
	const { subject, actor } = args;
	if (!actor) return undefined;

	const result: Record<string, unknown> = { sub: actor.sub };
	if (subject.act) {
		result.act = subject.act;
	}
	return result;
}

/**
 * Count an existing RFC 8693 `act` delegation chain.
 *
 * Depth 0 means no subject `act`; depth N means N nested actor records.
 * Malformed nested `act` values stop the count rather than throwing.
 */
export function countActorChainDepth(act: Readonly<Record<string, unknown>> | undefined): number {
	if (!act) return 0;
	let depth = 1;
	let current = act.act;
	while (isRecord(current)) {
		depth += 1;
		current = current.act;
	}
	return depth;
}

function mayActEntryMatches(
	actor: ValidatedToken,
	entry: Readonly<Record<string, unknown>>,
): boolean {
	const hasSub = "sub" in entry;
	const hasIss = "iss" in entry;
	if (!hasSub && !hasIss) return false;
	if (hasSub && typeof entry.sub !== "string") return false;
	if (hasIss && typeof entry.iss !== "string") return false;
	if (typeof entry.sub === "string" && entry.sub !== actor.sub) return false;
	if (typeof entry.iss === "string" && entry.iss !== actor.claims.iss) return false;
	return true;
}

/**
 * Check whether an actor satisfies a subject token's RFC 8693 `may_act` claim.
 *
 * Supported shape for v0.5.x: a single `{ sub?, iss? }` object or an array of
 * those objects. Malformed values fail closed so a bad `may_act` claim cannot
 * silently disable subject-declared delegation constraints.
 */
export function matchesMayAct(actor: ValidatedToken, mayAct: unknown): boolean {
	if (Array.isArray(mayAct)) {
		if (mayAct.length === 0) return false;
		return mayAct.some((entry) => isRecord(entry) && mayActEntryMatches(actor, entry));
	}
	if (!isRecord(mayAct)) return false;
	return mayActEntryMatches(actor, mayAct);
}

function mayActClientEntryMatches(clientId: string, entry: Readonly<Record<string, unknown>>) {
	// An entry that constrains `iss` names a party identified by the issuer of
	// a token. This request presented no token for the actor, so there is no
	// issuer to compare against and no honest answer but "no". Substituting
	// this AS's own issuer would be a guess, and the permissive one.
	if ("iss" in entry) return false;
	if (typeof entry.sub !== "string") return false;
	return entry.sub === clientId;
}

/**
 * Check whether the authenticated calling **client** satisfies a subject
 * token's RFC 8693 `may_act` claim on an *impersonation* exchange — the
 * exchange that presents no `actor_token`, where the party acting on the
 * subject's behalf is the client itself.
 *
 * Deliberately narrower than {@link matchesMayAct}, because the two compare
 * against different things. `matchesMayAct` reads an actor *token*: `sub`
 * against its subject, `iss` against its issuer. A client identity has the
 * first and structurally cannot have the second, so an `iss`-constrained
 * entry is refused rather than satisfied by an inferred value.
 *
 * `sub` is compared against `client.clientId`: for a client acting in its own
 * name that IS its subject identifier — the same value `client_credentials`
 * mints as `sub` (RFC 6749 §4.4.2) and every grant here stamps as `azp`.
 *
 * Malformed values fail closed, exactly as {@link matchesMayAct} does: a bad
 * `may_act` claim must not silently disable a subject-declared constraint.
 */
export function matchesMayActClient(clientId: string, mayAct: unknown): boolean {
	if (Array.isArray(mayAct)) {
		if (mayAct.length === 0) return false;
		return mayAct.some((entry) => isRecord(entry) && mayActClientEntryMatches(clientId, entry));
	}
	if (!isRecord(mayAct)) return false;
	return mayActClientEntryMatches(clientId, mayAct);
}
