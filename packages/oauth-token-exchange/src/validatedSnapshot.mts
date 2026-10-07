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
 * objects and arrays are copied the same way. Every key is defined on the copy
 * as an own data property, so a key named `__proto__` is copied as a key and
 * never sets the copy's prototype. A read that throws propagates: the caller
 * answers it as the validator's outage. The authentication context the
 * built-in validator verified for the answer is carried to the copy.
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
 * Whether `answer` has the shape of an answer — an object with a string `sub`
 * and object `claims` — reading those two members once each and copying
 * nothing. A read that throws propagates.
 */
export function isValidatedShape(answer: unknown): answer is ValidatedToken {
	return answerParts(answer) !== null;
}

/**
 * The plain, frozen copy of `answer`, or `null` when it is no answer: not an
 * object, a `sub` that is not a string, or `claims` that are not an object.
 */
export function snapshotValidated(answer: unknown): ValidatedToken | null {
	const parts = answerParts(answer);
	if (parts === null) return null;
	const { source, sub, claims } = parts;

	const seen = new Map<object, unknown>();
	const copy: Record<string, unknown> = {};
	define(copy, "sub", sub);
	for (const member of ["scope", "aud", "familyId", "sid", "act", "may_act"] as const) {
		const value: unknown = source[member];
		if (value !== undefined) define(copy, member, plainCopy(value, seen));
	}
	const claimsCopy: Record<string, unknown> = {};
	for (const name of new Set<string>([...Object.keys(claims), ...READ_CLAIMS])) {
		const value: unknown = claims[name];
		if (value !== undefined) define(claimsCopy, name, plainCopy(value, seen));
	}
	define(copy, "claims", Object.freeze(claimsCopy));

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

/** An answer, its `sub` and its `claims`, each member read once; `null` when one is not of its type. */
function answerParts(answer: unknown): {
	readonly source: ValidatedToken;
	readonly sub: string;
	readonly claims: Readonly<Record<string, unknown>>;
} | null {
	if (typeof answer !== "object" || answer === null) return null;
	const source = answer as ValidatedToken;
	const sub: unknown = source.sub;
	if (typeof sub !== "string") return null;
	const claims: unknown = source.claims;
	if (typeof claims !== "object" || claims === null) return null;
	return { source, sub, claims: claims as Readonly<Record<string, unknown>> };
}

/** `key` defined on `target` as an own, enumerable data property, whatever its name. */
function define(target: object, key: string, value: unknown): void {
	Object.defineProperty(target, key, {
		value,
		enumerable: true,
		writable: false,
		configurable: false,
	});
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
		define(out, key, plainCopy((value as Record<string, unknown>)[key], seen));
	}
	return Object.freeze(out);
}
