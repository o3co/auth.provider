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
 * A login's claims envelope — what the session record's `claims` will hold
 * (`UserSessionClaims`) — as a primary carries it: one read of the object a
 * route hands in, into a plain copy frozen at every depth that shares
 * nothing with it. Not the claim a carrier is read into (`SessionClaim`,
 * `admit.mts`): these are the OIDC claims a session records.
 *
 * Two rules, one for each kind of claim:
 *
 * - A claim `UserSessionClaims` declares (`email`, `emailVerified`, `name`,
 *   `picture`, `groups`) is read by name, once, however the object holds it
 *   — own data, a getter, inherited, behind a Proxy — through the by-name
 *   plain-data copy a login's user goes through (`readPlainFields`): a list
 *   by index into a plain array, nothing else of it. When present it must
 *   be of its declared type; `null` or any other value is refused.
 * - A custom claim — each other own enumerable key — is read once and
 *   stored as its JSON form: `JSON.stringify` (a `toJSON` applies, so a
 *   `Date` becomes its ISO string; NaN and the infinities become `null`),
 *   parsed back. One whose JSON form is nothing (`undefined`, a function, a
 *   symbol) is left out, as JSON leaves it out. One whose JSON form cannot
 *   be taken (a bigint, a cycle, a `toJSON` or a getter that throws) is
 *   dropped and the login goes on; whoever holds a logger says so with
 *   `warnDroppedClaims`, naming the key and never the value. That is what a
 *   Redis-backed session store already read back of a custom claim.
 *
 * Core-internal: not exported from the package.
 */

import type { Logger } from "../logging/Logger.mjs";
import { readPlainFields } from "../repositories/userSnapshot.mjs";
import type { UserSessionClaims } from "../user-sessions/types.mjs";

/** The claims `UserSessionClaims` declares; not its index signature. */
type DeclaredClaim = keyof {
	[K in keyof UserSessionClaims as string extends K
		? never
		: number extends K
			? never
			: K]: unknown;
};

const isStringList = (value: unknown): value is readonly string[] =>
	Array.isArray(value) && value.every((entry) => typeof entry === "string");

/**
 * What each declared claim holds when present, and how a refusal says it.
 * A claim `UserSessionClaims` declares that this misses, or one it does not
 * declare, fails to compile.
 */
const DECLARED_CLAIMS: {
	readonly [K in DeclaredClaim]-?: {
		readonly holds: (value: unknown) => boolean;
		readonly as: string;
	};
} = {
	email: { holds: (value) => typeof value === "string", as: "a string" },
	emailVerified: { holds: (value) => typeof value === "boolean", as: "a boolean" },
	name: { holds: (value) => typeof value === "string", as: "a string" },
	picture: { holds: (value) => typeof value === "string", as: "a string" },
	groups: { holds: isStringList, as: "a list of strings" },
};

const DECLARED_CLAIM_NAMES = Object.keys(DECLARED_CLAIMS) as DeclaredClaim[];

const isDeclaredClaim = (key: string): boolean => Object.hasOwn(DECLARED_CLAIMS, key);

/** Why a custom claim was dropped: its JSON form could not be taken. */
export type DroppedClaimReason = "unserialisable";

/** A custom claim a reading dropped: its key and why, never its value. */
export interface DroppedClaim {
	readonly claim: string;
	readonly reason: DroppedClaimReason;
}

/** What `readLoginClaims` answers: the envelope, or why the claims are refused. */
export type LoginClaimsReading =
	| { readonly ok: true; readonly claims: UserSessionClaims }
	| { readonly ok: false; readonly refused: "not_an_object" }
	| {
			readonly ok: false;
			readonly refused: "declared_claim";
			readonly claim: string;
			readonly as: string;
	  };

/** The custom claims each envelope dropped, keyed by the envelope `readLoginClaims` answered. */
const droppedFrom = new WeakMap<UserSessionClaims, readonly DroppedClaim[]>();

/** Freezes a value `JSON.parse` answered, at every depth, in place; answers it. */
function freezeParsed(value: unknown): unknown {
	if (typeof value === "object" && value !== null) {
		for (const entry of Object.values(value)) freezeParsed(entry);
		Object.freeze(value);
	}
	return value;
}

/** What `jsonFormOf` answers: the JSON form, nothing (left out, as JSON does), or that it cannot be taken. */
type JsonForm =
	| { readonly kind: "value"; readonly value: unknown }
	| { readonly kind: "nothing" }
	| { readonly kind: "unserialisable" };

/** The JSON form of what `read` answers, parsed back and frozen: one read, one `JSON.stringify`. */
function jsonFormOf(read: () => unknown): JsonForm {
	try {
		const text = JSON.stringify(read());
		if (text === undefined) return { kind: "nothing" };
		return { kind: "value", value: freezeParsed(JSON.parse(text)) };
	} catch {
		return { kind: "unserialisable" };
	}
}

/** `copy[key] = value`, as an own data property even for `__proto__`. */
function define(copy: Record<string, unknown>, key: string, value: unknown): void {
	Object.defineProperty(copy, key, { value, enumerable: true, writable: true, configurable: true });
}

/**
 * `claims` read once into the envelope a primary carries, by the two rules
 * in this file's header. Refused: `claims` that are not an object
 * (`not_an_object`), and a declared claim that is not plain data of its
 * declared type (`declared_claim`, naming it and the type). A class instance
 * is read by the declared names and its own enumerable keys, nothing else of
 * it. A read of the object's keys or of a declared claim that throws is let
 * through as it was thrown; a custom claim whose read throws is dropped.
 */
export function readLoginClaims(claims: unknown): LoginClaimsReading {
	if (typeof claims !== "object" || claims === null || Array.isArray(claims)) {
		return { ok: false, refused: "not_an_object" };
	}
	const source = claims as Record<string, unknown>;
	const declared = readPlainFields(source, DECLARED_CLAIM_NAMES);
	if (!declared.ok) {
		const claim = declared.field;
		return { ok: false, refused: "declared_claim", claim, as: DECLARED_CLAIMS[claim].as };
	}
	for (const claim of DECLARED_CLAIM_NAMES) {
		const value = declared.copy[claim];
		if (value !== undefined && !DECLARED_CLAIMS[claim].holds(value)) {
			return { ok: false, refused: "declared_claim", claim, as: DECLARED_CLAIMS[claim].as };
		}
	}
	const copy: Record<string, unknown> = { ...declared.copy };
	const dropped: DroppedClaim[] = [];
	for (const key of Object.keys(source)) {
		if (isDeclaredClaim(key)) continue;
		const form = jsonFormOf(() => source[key]);
		if (form.kind === "value") define(copy, key, form.value);
		else if (form.kind === "unserialisable") dropped.push({ claim: key, reason: form.kind });
	}
	const envelope = Object.freeze(copy) as UserSessionClaims;
	if (dropped.length > 0) droppedFrom.set(envelope, Object.freeze(dropped));
	return { ok: true, claims: envelope };
}

/** The custom claims `readLoginClaims` dropped from `claims`, an envelope it answered; none for any other object. */
export const droppedClaimsOf = (claims: UserSessionClaims): readonly DroppedClaim[] =>
	droppedFrom.get(claims) ?? [];

/**
 * Logs `login_claim_dropped` at warn once for each custom claim
 * `readLoginClaims` dropped from `claims`: its key and the reason, never
 * its value. Nothing without a logger.
 */
export function warnDroppedClaims(logger: Logger | undefined, claims: UserSessionClaims): void {
	if (logger === undefined) return;
	for (const { claim, reason } of droppedClaimsOf(claims)) {
		logger.warn({ claim, reason }, "login_claim_dropped");
	}
}
