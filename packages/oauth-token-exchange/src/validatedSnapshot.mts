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

/**
 * A validator's answer, read once into a plain, deeply frozen `ValidatedToken`
 * that every stage of the exchange reads instead of the answer: each member
 * (`sub`, `scope`, `aud`, `familyId`, `sid`, `act`, `may_act`) and each claim
 * is read exactly once, so a check and the minted token cannot see two
 * values of one member. Of `claims`, the copy holds every own enumerable
 * claim and the ones the grant reads by name (`azp`, `exp`, `iss`, `cnf`,
 * `may_act`), read even where an inherited accessor holds them. Nested
 * objects and arrays are copied the same way. A read that throws propagates:
 * the caller answers it as the validator's outage. The authentication context
 * the built-in validator verified for the answer is carried to the copy.
 */

import type { ValidatedToken } from "@o3co/auth-provider-core";
import {
	type VerifiedAuthentication,
	verifiedAuthenticationOf,
} from "./validator/selfIssuedAccessToken.mjs";

/** The claims the grant reads by name. */
const READ_CLAIMS = ["azp", "exp", "iss", "cnf", "may_act"] as const;

const authentications = new WeakMap<ValidatedToken, VerifiedAuthentication>();

/**
 * The plain, frozen copy of `answer`, or `null` when it is no answer: not an
 * object, a `sub` that is not a string, or `claims` that are not an object.
 */
export function snapshotValidated(answer: unknown): ValidatedToken | null {
	if (typeof answer !== "object" || answer === null) return null;
	const source = answer as ValidatedToken;
	const sub: unknown = source.sub;
	if (typeof sub !== "string") return null;
	const claims: unknown = source.claims;
	if (typeof claims !== "object" || claims === null) return null;

	const seen = new Map<object, unknown>();
	const copy: Record<string, unknown> = { sub };
	for (const member of ["scope", "aud", "familyId", "sid", "act", "may_act"] as const) {
		const value: unknown = source[member];
		if (value !== undefined) copy[member] = plainCopy(value, seen);
	}
	const claimsCopy: Record<string, unknown> = {};
	for (const name of new Set<string>([...Object.keys(claims), ...READ_CLAIMS])) {
		const value: unknown = (claims as Record<string, unknown>)[name];
		if (value !== undefined) claimsCopy[name] = plainCopy(value, seen);
	}
	copy.claims = Object.freeze(claimsCopy);

	const snapshot = Object.freeze(copy) as unknown as ValidatedToken;
	const authentication = verifiedAuthenticationOf(source);
	if (authentication !== undefined) authentications.set(snapshot, authentication);
	return snapshot;
}

/**
 * The authentication context the built-in validator verified for the answer
 * `snapshot` was copied from, or `undefined` when another validator gave it.
 */
export function snapshotAuthentication(
	snapshot: ValidatedToken,
): VerifiedAuthentication | undefined {
	return authentications.get(snapshot);
}

/** `value` as a plain, frozen copy: arrays element by element, objects by their own enumerable keys. */
function plainCopy(value: unknown, seen: Map<object, unknown>): unknown {
	if (typeof value !== "object" || value === null) return value;
	const copied = seen.get(value);
	if (copied !== undefined) return copied;
	if (Array.isArray(value)) {
		const out: unknown[] = [];
		seen.set(value, out);
		for (let i = 0; i < value.length; i++) out.push(plainCopy(value[i], seen));
		return Object.freeze(out);
	}
	const out: Record<string, unknown> = {};
	seen.set(value, out);
	for (const key of Object.keys(value)) {
		out[key] = plainCopy((value as Record<string, unknown>)[key], seen);
	}
	return Object.freeze(out);
}
