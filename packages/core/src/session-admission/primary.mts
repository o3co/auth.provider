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
 * The establishment vocabulary as it is checked and copied (the
 * session-admission ADR's D5): a `PrimaryAuthentication` as the login route
 * builds it, the additions a completing requirement presents, and the
 * `PrimaryContinuation` a requirement persists in its own record — the MFA
 * transaction — and presents to `resumePrimary`. Each check answers a frozen
 * deep copy, so what admission asks the requirements about, and what a store
 * records, shares nothing with the caller's object; a value the contract
 * does not admit is a `RangeError` naming what is wrong, and quoting nothing
 * but an `amr` value's marker.
 *
 * What the checks refuse is a mistake — a primary rebuilt by hand with
 * `mfaAt` set, an addition that names a primary's marker, a reserved value
 * under a requirement not named `mfa` — and what they keep honest is the
 * contract: `admitPrimary`, `resumePrimary` and `MfaTransactionStore.create`
 * all read through them.
 */

import { FEDERATED_AMR, MFA_AMR, PASSWORD_AMR } from "../grants/authenticationClaims.mjs";
import type { RecordedAuthentication } from "../user-sessions/authentication.mjs";
import type { SessionAuthentication } from "../user-sessions/types.mjs";
import { SECOND_FACTOR_AMR } from "./acr.mjs";
import type {
	CompletedRequirement,
	PrimaryAdditions,
	PrimaryAuthentication,
	PrimaryContinuation,
} from "./requirement.mjs";

/** The one requirement that may reach or add a second-factor value, or a verification time (D3). */
export const MFA_REQUIREMENT_NAME = "mfa";

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

const isNonEmptyString = (value: unknown): value is string =>
	typeof value === "string" && value.length > 0;

const isValidDate = (value: unknown): value is Date =>
	value instanceof Date && !Number.isNaN(value.getTime());

const isStringList = (value: unknown): value is readonly string[] =>
	Array.isArray(value) && value.every((entry) => typeof entry === "string");

/** A copy of `user` that shares nothing with it; a value that cannot be copied is refused. */
function copyUser(
	user: unknown,
	refuse: (what: string) => never,
): Readonly<Record<string, unknown>> {
	if (!isPlainObject(user)) return refuse("user must be an object");
	try {
		return Object.freeze(structuredClone(user));
	} catch {
		return refuse("user holds a value that cannot be copied");
	}
}

function copyAuthentication(
	value: unknown,
	refuse: (what: string) => never,
): SessionAuthentication {
	if (!isPlainObject(value)) return refuse("recorded.authentication must be an object");
	if (!isNonEmptyString(value.primary)) {
		refuse("recorded.authentication.primary must be a non-empty string");
	}
	if (value.federation !== undefined && typeof value.federation !== "string") {
		refuse("recorded.authentication.federation must be a string or absent");
	}
	if (value.upstreamAmr !== undefined && !isStringList(value.upstreamAmr)) {
		refuse("recorded.authentication.upstreamAmr must be a list of strings or absent");
	}
	// A primary is what a login path records before any second factor: one
	// that already says when a second factor was verified was rebuilt by hand.
	if (value.mfaAt !== undefined) refuse("a primary authentication records no mfaAt");
	return Object.freeze({
		primary: value.primary as string,
		federation: value.federation as string | undefined,
		upstreamAmr:
			value.upstreamAmr === undefined
				? undefined
				: Object.freeze([...(value.upstreamAmr as readonly string[])]),
		mfaAt: undefined,
	});
}

function copyRecorded(value: unknown, refuse: (what: string) => never): RecordedAuthentication {
	if (!isPlainObject(value)) return refuse("recorded must be an object");
	if (!isStringList(value.amr) || value.amr.length === 0 || !value.amr.every(isNonEmptyString)) {
		refuse("recorded.amr must be a non-empty list of non-empty strings");
	}
	const authentication = copyAuthentication(value.authentication, refuse);
	const amr = value.amr as readonly string[];
	// A password login records `pwd` alone; a second-factor value beside it
	// is what a step-up adds, never what a route hands in. A federated login
	// may carry what a trusted IdP asserted (D13).
	if (
		authentication.primary === PASSWORD_AMR &&
		amr.some((entry) => SECOND_FACTOR_AMR.has(entry))
	) {
		refuse("a password primary's amr holds no second-factor value");
	}
	return Object.freeze({ amr: Object.freeze([...amr]), authentication });
}

/**
 * `value` as a `PrimaryAuthentication` a login route builds (D5): a
 * non-empty `subject`; a `user` that can be copied; `recorded` with a
 * non-empty `amr` and an `authentication` whose `mfaAt` is not set — and no
 * second-factor value beside a password primary; a valid `authTime`; a
 * `redirectTo` that is a string or `undefined`; a `request` object whose
 * `ip` and `userAgent` are strings when present. A frozen deep copy.
 */
export function checkPrimaryAuthentication(value: unknown): PrimaryAuthentication {
	const refuse = (what: string): never => {
		throw new RangeError(`PrimaryAuthentication: ${what}`);
	};
	if (!isPlainObject(value)) return refuse("must be an object");
	if (!isNonEmptyString(value.subject)) refuse("subject must be a non-empty string");
	const user = copyUser(value.user, refuse);
	const recorded = copyRecorded(value.recorded, refuse);
	if (!isValidDate(value.authTime)) refuse("authTime must be a valid date");
	if (value.redirectTo !== undefined && typeof value.redirectTo !== "string") {
		refuse("redirectTo must be a string or absent");
	}
	if (!isPlainObject(value.request)) return refuse("request must be an object");
	const { ip, userAgent } = value.request;
	if (ip !== undefined && typeof ip !== "string") refuse("request.ip must be a string or absent");
	if (userAgent !== undefined && typeof userAgent !== "string") {
		refuse("request.userAgent must be a string or absent");
	}
	return Object.freeze({
		subject: value.subject as string,
		user,
		recorded,
		authTime: new Date((value.authTime as Date).getTime()),
		redirectTo: value.redirectTo as string | undefined,
		request: Object.freeze({
			...(ip === undefined ? {} : { ip: ip as string }),
			...(userAgent === undefined ? {} : { userAgent: userAgent as string }),
		}),
	});
}

/**
 * What a completing requirement named `requirement` may add (D5): a
 * non-empty `amr` of non-empty strings, none a primary's marker, `mfa` never
 * alone (it comes beside a factor's own value, D14); `mfaAt` a valid date or
 * absent. A second-factor value, or an `mfaAt`, under any name but `mfa` is
 * refused: a risk score or a re-consent cannot make a session meet
 * `urn:o3co:acr:mfa`. A frozen copy.
 */
export function checkPrimaryAdditions(requirement: string, value: unknown): PrimaryAdditions {
	const refuse = (what: string): never => {
		throw new RangeError(`requirement "${requirement}" adds ${what}`);
	};
	if (!isPlainObject(value)) return refuse("something that is not an object");
	const amr = value.amr;
	if (!isStringList(amr) || amr.length === 0 || !amr.every(isNonEmptyString)) {
		refuse("an amr that is not a non-empty list of non-empty strings");
	}
	const values = amr as readonly string[];
	for (const entry of values) {
		if (entry === PASSWORD_AMR || entry === FEDERATED_AMR) {
			refuse(`"${entry}", which marks a primary authentication`);
		}
	}
	if (values.every((entry) => entry === MFA_AMR)) {
		refuse(`"${MFA_AMR}" alone, which comes beside a factor's own amr values`);
	}
	if (value.mfaAt !== undefined && !isValidDate(value.mfaAt)) {
		refuse("an mfaAt that is not a valid date");
	}
	if (requirement !== MFA_REQUIREMENT_NAME) {
		if (values.some((entry) => SECOND_FACTOR_AMR.has(entry))) {
			refuse("a second-factor amr value, which only the requirement named mfa may add");
		}
		if (value.mfaAt !== undefined) {
			refuse("an mfaAt, which only the requirement named mfa may add");
		}
	}
	return Object.freeze({
		amr: Object.freeze([...values]),
		...(value.mfaAt === undefined ? {} : { mfaAt: new Date((value.mfaAt as Date).getTime()) }),
	});
}

function copyCompleted(value: unknown, refuse: (what: string) => never): CompletedRequirement {
	if (!isPlainObject(value)) return refuse("done holds an entry that is not an object");
	if (!isNonEmptyString(value.requirement)) {
		refuse("done holds an entry whose requirement is not a non-empty string");
	}
	return Object.freeze({
		requirement: value.requirement as string,
		adds: checkPrimaryAdditions(value.requirement as string, value.adds),
	});
}

/**
 * `value` as a `PrimaryContinuation` (D5): a primary (`checkPrimaryAuthentication`)
 * and `done`, a list of completed requirements each with what it added
 * (`checkPrimaryAdditions`), no name twice. A frozen deep copy: what a
 * requirement's record holds and what `resumePrimary` reads back.
 */
export function checkPrimaryContinuation(value: unknown): PrimaryContinuation {
	const refuse = (what: string): never => {
		throw new RangeError(`PrimaryContinuation: ${what}`);
	};
	if (!isPlainObject(value)) return refuse("must be an object");
	const primary = checkPrimaryAuthentication(value.primary);
	if (!Array.isArray(value.done)) return refuse("done must be a list");
	const done = value.done.map((entry) => copyCompleted(entry, refuse));
	const names = new Set(done.map((entry) => entry.requirement));
	if (names.size !== done.length) refuse("done names a requirement twice");
	return Object.freeze({ primary, done: Object.freeze(done) });
}
