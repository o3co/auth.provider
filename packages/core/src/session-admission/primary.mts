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
 * The establishment vocabulary as it is checked and copied: a
 * `PrimaryAuthentication` as core's builders make it, the additions a
 * completing requirement presents, and the `PrimaryContinuation` a
 * requirement persists and presents to `resumePrimary`, a serialisable DTO
 * with every instant as epoch milliseconds, built, checked and rehydrated
 * here. `admitPrimary`, `resumePrimary` and `MfaTransactionStore.create` all
 * read through these checks.
 *
 * Each check answers a frozen deep copy that shares nothing with the
 * caller's object; a value the contract does not admit is a `RangeError`
 * naming what is wrong and quoting nothing but an `amr` value's marker.
 *
 * A primary's `user` is a plain snapshot of the `User`, each field read by
 * name once (`userSnapshot`), and its `enrollmentFacts` are derived here from
 * that snapshot, as it is checked and as it is rehydrated, and never read
 * from what a caller hands in; a continuation carries none, and its holder
 * reads them through `enrollmentFactsOfContinuation`, the same derivation.
 */

import {
	EMAIL_OTP_AMR,
	FEDERATED_AMR,
	MFA_AMR,
	PASSWORD_AMR,
} from "../grants/authenticationClaims.mjs";
import { normaliseMailAddress } from "../mail/address.mjs";
import type { User } from "../repositories/types.mjs";
import { readMfaEnrollmentWitness } from "../repositories/UserRepository.mjs";
import type { RecordedAuthentication } from "../user-sessions/authentication.mjs";
import type {
	MailAddressFact,
	SessionAuthentication,
	SessionEnrollmentFacts,
	UserSessionClaims,
} from "../user-sessions/types.mjs";
import { SECOND_FACTOR_AMR } from "./acr.mjs";
import type {
	CompletedRequirement,
	CompletedRequirementDto,
	PrimaryAdditions,
	PrimaryAdditionsDto,
	PrimaryAuthentication,
	PrimaryAuthenticationDto,
	PrimaryContinuation,
	RegisteredRequirement,
} from "./requirement.mjs";

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

const isNonEmptyString = (value: unknown): value is string =>
	typeof value === "string" && value.length > 0;

const isValidDate = (value: unknown): value is Date =>
	value instanceof Date && !Number.isNaN(value.getTime());

const isStringList = (value: unknown): value is readonly string[] =>
	Array.isArray(value) && value.every((entry) => typeof entry === "string");

/** An instant as a continuation carries it: epoch milliseconds, a safe integer at or after the epoch. */
const isEpochMs = (value: unknown): value is number =>
	typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

/** Freezes `value` and every plain object or array it holds, in place; answers it. */
function deepFreeze<T>(value: T): T {
	if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
	Object.freeze(value);
	for (const entry of Object.values(value as Record<string, unknown>)) deepFreeze(entry);
	return value;
}

/** What `plainCopy` and `copyByName` throw for a value that is not plain data. */
class NotPlainData extends Error {}

/**
 * `value` copied as plain data — a primitive; an array; or an object whose
 * prototype is `Object.prototype` or `null` — frozen at every depth and
 * sharing nothing with it. Every own property must be an enumerable data
 * property under a string key, read once from its descriptor, so no accessor
 * of the object runs (a Proxy's traps are read once); anything else throws
 * `NotPlainData`. `copies` keeps a shared or
 * cyclic reference one copy.
 */
function plainCopy(value: unknown, copies: Map<object, unknown>): unknown {
	if (value === null) return null;
	switch (typeof value) {
		case "string":
		case "number":
		case "boolean":
		case "bigint":
		case "undefined":
			return value;
		case "object":
			break;
		default:
			throw new NotPlainData();
	}
	const source = value as object;
	const known = copies.get(source);
	if (known !== undefined) return known;
	const isArray = Array.isArray(source);
	const prototype = Reflect.getPrototypeOf(source);
	if (
		isArray ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null
	) {
		throw new NotPlainData();
	}
	const copy: object = isArray ? [] : {};
	copies.set(source, copy);
	for (const key of Reflect.ownKeys(source)) {
		if (typeof key !== "string") throw new NotPlainData();
		const descriptor = Reflect.getOwnPropertyDescriptor(source, key);
		if (descriptor === undefined || !Object.hasOwn(descriptor, "value")) throw new NotPlainData();
		if (isArray && key === "length") {
			(copy as unknown[]).length = descriptor.value as number;
			continue;
		}
		if (descriptor.enumerable !== true) throw new NotPlainData();
		Object.defineProperty(copy, key, {
			value: plainCopy(descriptor.value, copies),
			enumerable: true,
			writable: true,
			configurable: true,
		});
	}
	return Object.freeze(copy);
}

/**
 * `user` copied as plain data, frozen at every depth and sharing nothing
 * with it (`plainCopy`); `undefined` for a value that is not an object, or
 * holds anything but plain data — a field an accessor, a prototype or a
 * non-enumerable property holds would be lost from the copy.
 */
export function frozenUserCopy(user: unknown): Readonly<Record<string, unknown>> | undefined {
	if (!isPlainObject(user)) return undefined;
	try {
		return plainCopy(user, new Map()) as Readonly<Record<string, unknown>>;
	} catch {
		return undefined;
	}
}

/**
 * The fields `User` declares, which a login reads by name however the
 * object holds them. A field `User` declares that this list misses fails
 * to compile below.
 */
const USER_FIELDS = [
	"id",
	"username",
	"email",
	"emailVerified",
	"name",
	"picture",
	"groups",
	"mfaEnrolled",
] as const;

type DeclaredUserField = keyof {
	[K in keyof User as string extends K ? never : number extends K ? never : K]: unknown;
};
type UnreadUserField = Exclude<DeclaredUserField, (typeof USER_FIELDS)[number]>;
const everyDeclaredFieldRead: [UnreadUserField] extends [never] ? true : UnreadUserField = true;
void everyDeclaredFieldRead;

const DECLARED_USER_FIELDS: ReadonlySet<string> = new Set(USER_FIELDS);

/** Whether `key` is an array index as an array's own property names spell one. */
const isArrayIndex = (key: string): boolean =>
	/^(0|[1-9][0-9]*)$/.test(key) && Number(key) < 2 ** 32 - 1;

/** What `copies` holds for an object `copyByName` found not plain data. */
const NOT_PLAIN: unique symbol = Symbol("not plain data");

/**
 * `value` copied by name as plain data, frozen at every depth and sharing
 * nothing with it: a primitive as it is; an array (`Array.isArray`), each of
 * its own indices read once, and its `length`; an object whose prototype is
 * `Object.prototype` or `null`, each own enumerable string key read once.
 * Every read is an ordinary one, so an accessor runs and a throw is let
 * through as it was thrown. Anything else (a class instance, a `Date`, a
 * `Map`, a function, a symbol) throws `NotPlainData`. `copies` keeps a
 * shared or cyclic reference one copy, read once, and remembers an object
 * found not plain data, so it is not read again.
 */
function copyByName(value: unknown, copies: Map<object, unknown>): unknown {
	if (value === null) return null;
	switch (typeof value) {
		case "string":
		case "number":
		case "boolean":
		case "bigint":
		case "undefined":
			return value;
		case "object":
			break;
		default:
			throw new NotPlainData();
	}
	const source = value as Record<string, unknown>;
	const known = copies.get(source);
	if (known === NOT_PLAIN) throw new NotPlainData();
	if (known !== undefined) return known;
	// An array is read by index whatever its prototype — an ORM's list type
	// included — and copied as a plain one.
	const isArray = Array.isArray(source);
	if (!isArray) {
		const prototype = Reflect.getPrototypeOf(source);
		if (prototype !== Object.prototype && prototype !== null) {
			copies.set(source, NOT_PLAIN);
			throw new NotPlainData();
		}
	}
	const copy: Record<string, unknown> = isArray ? ([] as unknown as Record<string, unknown>) : {};
	copies.set(source, copy);
	const keys = isArray
		? Object.getOwnPropertyNames(source).filter(isArrayIndex)
		: Object.keys(source);
	try {
		for (const key of keys) {
			Object.defineProperty(copy, key, {
				value: copyByName(source[key], copies),
				enumerable: true,
				writable: true,
				configurable: true,
			});
		}
	} catch (err) {
		// A copy a cyclic reference already took stays frozen plain data.
		Object.freeze(copy);
		if (err instanceof NotPlainData) copies.set(source, NOT_PLAIN);
		throw err;
	}
	if (isArray) (copy as unknown as unknown[]).length = (source as unknown as unknown[]).length;
	return Object.freeze(copy);
}

/**
 * The plain snapshot a login takes of `user`, its one read of it. Each field
 * `User` declares is read by name, once, however the object holds it — own
 * data, an accessor, inherited, as a class instance or an ORM entity holds
 * it — then each other own enumerable string-keyed field, by name, once. A
 * field read as `undefined` is left out. Frozen at every depth, sharing
 * nothing with `user`: every fact a login derives is read from it.
 *
 * Refused, quoting nothing of it: a `user` that is not an object, an `id`
 * that is not a non-empty string, and a declared field holding what is not
 * plain data (`copyByName`) — left out, the witness would read as not
 * enrolled. Another field holding what is not plain data (a `Date`, a `Map`,
 * an instance) is left out of the snapshot. A field that refers back to the
 * user is not plain data. A read that throws is let
 * through as it was thrown: never read as a witness or an address.
 */
function userSnapshot(
	user: unknown,
	refuse: (what: string) => never,
): Readonly<Record<string, unknown>> {
	if (!isPlainObject(user)) return refuse("user must be an object");
	const snapshot: Record<string, unknown> = {};
	// One map for every field: an object two fields share is read once. The
	// user is a record, not a value: a field that refers back to it is not
	// plain data, and the user is not read again.
	const copies = new Map<object, unknown>([[user, NOT_PLAIN]]);
	const keep = (key: string, value: unknown): void => {
		Object.defineProperty(snapshot, key, {
			value,
			enumerable: true,
			writable: true,
			configurable: true,
		});
	};
	for (const field of USER_FIELDS) {
		const value = user[field];
		if (value === undefined) continue;
		try {
			keep(field, copyByName(value, copies));
		} catch (err) {
			if (!(err instanceof NotPlainData)) throw err;
			refuse(`user.${field} must be plain data: a primitive, an array or a plain object`);
		}
	}
	if (!isNonEmptyString(snapshot.id)) refuse("user.id must be a non-empty string");
	for (const key of Object.keys(user)) {
		if (DECLARED_USER_FIELDS.has(key)) continue;
		const value = user[key];
		if (value === undefined) continue;
		try {
			keep(key, copyByName(value, copies));
		} catch (err) {
			if (!(err instanceof NotPlainData)) throw err;
		}
	}
	return Object.freeze(snapshot);
}

/**
 * What `email` says of a first binding: `none` when it is absent, `null` or
 * empty; `address` when `normaliseMailAddress` reads one address; else
 * `unreadable`.
 */
function mailAddressFactOf(email: unknown): MailAddressFact {
	if (email === undefined || email === null || email === "") return "none";
	return normaliseMailAddress(email) === undefined ? "unreadable" : "address";
}

/**
 * What a session records of its login's `user` for a first binding: the
 * witness as `readMfaEnrollmentWitness` reads it, and what its `email` is
 * (`mailAddressFactOf`) — never the address. Frozen.
 */
export function enrollmentFactsOf(user: Readonly<Record<string, unknown>>): SessionEnrollmentFacts {
	return Object.freeze({
		witness: readMfaEnrollmentWitness(user),
		mailAddress: mailAddressFactOf(user.email),
	});
}

/** A deep copy of `claims` — the session record's `claims` to be — that shares nothing with it, frozen at every depth. */
function copyClaims(claims: unknown, refuse: (what: string) => never): UserSessionClaims {
	if (!isPlainObject(claims)) return refuse("claims must be an object");
	try {
		return deepFreeze(structuredClone(claims)) as UserSessionClaims;
	} catch {
		return refuse("claims hold a value that cannot be copied");
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
	// may carry what a trusted IdP asserted.
	if (
		authentication.primary === PASSWORD_AMR &&
		amr.some((entry) => SECOND_FACTOR_AMR.has(entry))
	) {
		refuse("a password primary's amr holds no second-factor value");
	}
	return Object.freeze({ amr: Object.freeze([...amr]), authentication });
}

/** The fields a primary and its DTO share, checked and copied; `authTime` is the caller's to add, and the facts a primary's. */
function copyPrimaryFields(
	value: Record<string, unknown>,
	refuse: (what: string) => never,
): Omit<PrimaryAuthentication, "authTime" | "enrollmentFacts"> {
	if (!isNonEmptyString(value.subject)) refuse("subject must be a non-empty string");
	const user = userSnapshot(value.user, refuse);
	const claims = copyClaims(value.claims, refuse);
	const recorded = copyRecorded(value.recorded, refuse);
	if (value.redirectTo !== undefined && typeof value.redirectTo !== "string") {
		refuse("redirectTo must be a string or absent");
	}
	if (!isPlainObject(value.request)) return refuse("request must be an object");
	const { ip, userAgent } = value.request;
	if (ip !== undefined && typeof ip !== "string") refuse("request.ip must be a string or absent");
	if (userAgent !== undefined && typeof userAgent !== "string") {
		refuse("request.userAgent must be a string or absent");
	}
	return {
		subject: value.subject as string,
		user,
		claims,
		recorded,
		redirectTo: value.redirectTo as string | undefined,
		request: Object.freeze({
			...(ip === undefined ? {} : { ip: ip as string }),
			...(userAgent === undefined ? {} : { userAgent: userAgent as string }),
		}),
	};
}

/**
 * `value` as a `PrimaryAuthentication` core's builders make: `recorded` has
 * a non-empty `amr`, no `mfaAt`, and no second-factor value beside a
 * password primary; `user` is read into its snapshot (`userSnapshot`) and
 * `claims` must be copyable. A frozen deep copy, its `enrollmentFacts`
 * derived from the snapshot.
 */
export function checkPrimaryAuthentication(value: unknown): PrimaryAuthentication {
	const refuse = (what: string): never => {
		throw new RangeError(`PrimaryAuthentication: ${what}`);
	};
	if (!isPlainObject(value)) return refuse("must be an object");
	const fields = copyPrimaryFields(value, refuse);
	if (!isValidDate(value.authTime)) refuse("authTime must be a valid date");
	return Object.freeze({
		...fields,
		enrollmentFacts: enrollmentFactsOf(fields.user),
		authTime: new Date((value.authTime as Date).getTime()),
	});
}

/** `value` as a `PrimaryAuthenticationDto`: the same, with `authTimeMs` epoch milliseconds. A frozen deep copy. */
function checkPrimaryAuthenticationDto(value: unknown): PrimaryAuthenticationDto {
	const refuse = (what: string): never => {
		throw new RangeError(`PrimaryContinuation: primary ${what}`);
	};
	if (!isPlainObject(value)) return refuse("must be an object");
	const fields = copyPrimaryFields(value, refuse);
	if (!isEpochMs(value.authTimeMs)) refuse("authTimeMs must be epoch milliseconds");
	return Object.freeze({ ...fields, authTimeMs: value.authTimeMs as number });
}

/** A primary rehydrated from its DTO: `authTime` a `Date` at `authTimeMs`, `enrollmentFacts` derived from its `user`. Frozen. */
export function primaryFromDto(dto: PrimaryAuthenticationDto): PrimaryAuthentication {
	const { authTimeMs, ...fields } = dto;
	return Object.freeze({
		...fields,
		enrollmentFacts: enrollmentFactsOf(fields.user),
		authTime: new Date(authTimeMs),
	});
}

/**
 * The enrollment facts of the login `continuation` carries, derived from its
 * `user` exactly as its rehydration derives them: for the requirement that
 * holds it and decides a first binding before resuming the login. Facts the
 * continuation carries are not read. A continuation `checkPrimaryContinuation`
 * cannot read is a `RangeError`, as it is for `resumePrimary`.
 */
export function enrollmentFactsOfContinuation(
	continuation: PrimaryContinuation,
): SessionEnrollmentFacts {
	const primary: PrimaryAuthentication = primaryFromDto(
		checkPrimaryContinuation(continuation).primary,
	);
	return primary.enrollmentFacts;
}

/** The completing requirement as registered: its name and its declaration, read once. */
export type CompletingRequirement = Pick<RegisteredRequirement, "name" | "secondFactorAuthority">;

/**
 * What `requirement` may add as it completes: an `amr` of non-empty strings,
 * none a primary's marker, `mfa` never alone; `mfaAt` never beside an empty
 * `amr`. A second factor from the second-factor authority alone, and from it
 * a verified one (`checkSecondFactor`). A frozen copy.
 */
export function checkPrimaryAdditions(
	requirement: CompletingRequirement,
	value: unknown,
): PrimaryAdditions {
	const refuse = (what: string): never => {
		throw new RangeError(`requirement "${requirement.name}" adds ${what}`);
	};
	if (!isPlainObject(value)) return refuse("something that is not an object");
	const amr = checkAddedAmr(value, refuse);
	if (value.mfaAt !== undefined && !isValidDate(value.mfaAt)) {
		refuse("an mfaAt that is not a valid date");
	}
	const hasMfaAt = value.mfaAt !== undefined;
	if (requirement.secondFactorAuthority === true) {
		if (!addsSecondFactor(amr, hasMfaAt)) {
			refuse(
				"no second factor: a completion by the second-factor authority is a verified second factor",
			);
		}
	} else {
		if (amr.some((entry) => SECOND_FACTOR_AMR.has(entry))) {
			refuse("a second-factor amr value, which only the second-factor authority may add");
		}
		if (hasMfaAt) refuse("an mfaAt, which only the second-factor authority may add");
	}
	checkSecondFactor(amr, hasMfaAt, refuse);
	return Object.freeze({
		amr,
		...(value.mfaAt === undefined ? {} : { mfaAt: new Date((value.mfaAt as Date).getTime()) }),
	});
}

/** Whether an addition carries a second factor: a second-factor `amr` value, or `mfaAt`. */
const addsSecondFactor = (amr: readonly string[], hasMfaAt: boolean): boolean =>
	hasMfaAt || amr.some((entry) => SECOND_FACTOR_AMR.has(entry));

/**
 * A second factor added, whoever adds it, is a verified one: a second-factor
 * `amr` value of the factor's own (not `mfa`), `mfa` beside it (only the
 * email code may leave it out, the MFA ADR's D14), and `mfaAt`; an `mfaAt`
 * beside an empty `amr` verified nothing.
 */
function checkSecondFactor(
	amr: readonly string[],
	hasMfaAt: boolean,
	refuse: (what: string) => never,
): void {
	if (amr.length === 0 && hasMfaAt) {
		refuse(
			"an mfaAt beside an empty amr: a completion that adds no value verified no second factor",
		);
	}
	if (!addsSecondFactor(amr, hasMfaAt)) return;
	const factorValues = amr.filter((entry) => entry !== MFA_AMR);
	if (!factorValues.some((entry) => SECOND_FACTOR_AMR.has(entry))) {
		refuse("no second factor's own amr value: a second factor added is a verified one");
	}
	if (!amr.includes(MFA_AMR) && !factorValues.every((entry) => entry === EMAIL_OTP_AMR)) {
		refuse(`no "${MFA_AMR}" beside a factor that adds it: only the email code's may leave it out`);
	}
	if (!hasMfaAt) refuse("no mfaAt: a second factor added says when it was verified");
}

/** The `amr` rules every addition is held to, whoever adds it, in both forms. */
function checkAddedAmr(
	value: Record<string, unknown>,
	refuse: (what: string) => never,
): readonly string[] {
	const amr = value.amr;
	// Empty is allowed: a requirement that reaches nothing completes its
	// ceremony adding no value.
	if (!isStringList(amr) || !amr.every(isNonEmptyString)) {
		refuse("an amr that is not a list of non-empty strings");
	}
	const values = amr as readonly string[];
	for (const entry of values) {
		if (entry === PASSWORD_AMR || entry === FEDERATED_AMR) {
			refuse(`"${entry}", which marks a primary authentication`);
		}
	}
	if (values.length > 0 && values.every((entry) => entry === MFA_AMR)) {
		refuse(`"${MFA_AMR}" alone, which comes beside a factor's own amr values`);
	}
	return Object.freeze([...values]);
}

/**
 * `value` as a `PrimaryAdditionsDto` read back from a continuation: the `amr`
 * rules, `mfaAtMs` epoch milliseconds, and a second factor added a verified
 * one. Whether `requirement` may add one is `resumePrimary`'s to check.
 */
function checkPrimaryAdditionsDto(requirement: string, value: unknown): PrimaryAdditionsDto {
	const refuse = (what: string): never => {
		throw new RangeError(`requirement "${requirement}" adds ${what}`);
	};
	if (!isPlainObject(value)) return refuse("something that is not an object");
	const amr = checkAddedAmr(value, refuse);
	if (value.mfaAtMs !== undefined && !isEpochMs(value.mfaAtMs)) {
		refuse("an mfaAtMs that is not epoch milliseconds");
	}
	checkSecondFactor(amr, value.mfaAtMs !== undefined, refuse);
	return Object.freeze({
		amr,
		...(value.mfaAtMs === undefined ? {} : { mfaAtMs: value.mfaAtMs as number }),
	});
}

/** Additions rehydrated from their DTO: `mfaAt` a `Date` at `mfaAtMs`. Frozen. */
export function additionsFromDto(dto: PrimaryAdditionsDto): PrimaryAdditions {
	return Object.freeze({
		amr: Object.freeze([...dto.amr]),
		...(dto.mfaAtMs === undefined ? {} : { mfaAt: new Date(dto.mfaAtMs) }),
	});
}

function copyCompleted(value: unknown, refuse: (what: string) => never): CompletedRequirementDto {
	if (!isPlainObject(value)) return refuse("done holds an entry that is not an object");
	if (!isNonEmptyString(value.requirement)) {
		refuse("done holds an entry whose requirement is not a non-empty string");
	}
	return Object.freeze({
		requirement: value.requirement as string,
		adds: checkPrimaryAdditionsDto(value.requirement as string, value.adds),
	});
}

/**
 * `value` as a `PrimaryContinuation`: a primary DTO and `done`, the
 * completed requirements with what each added — a second factor a verified
 * one, added by one entry at most — no name twice, every instant epoch
 * milliseconds. A frozen deep copy: what a requirement's record holds and
 * what `resumePrimary` reads back. Which requirement declares the
 * second-factor authority it does not know: `resumePrimary` checks that.
 */
export function checkPrimaryContinuation(value: unknown): PrimaryContinuation {
	const refuse = (what: string): never => {
		throw new RangeError(`PrimaryContinuation: ${what}`);
	};
	if (!isPlainObject(value)) return refuse("must be an object");
	const primary = checkPrimaryAuthenticationDto(value.primary);
	if (!Array.isArray(value.done)) return refuse("done must be a list");
	const done = value.done.map((entry) => copyCompleted(entry, refuse));
	const names = new Set(done.map((entry) => entry.requirement));
	if (names.size !== done.length) refuse("done names a requirement twice");
	// One requirement may add a second factor, and a name completes once.
	const adding = done.filter((entry) =>
		addsSecondFactor(entry.adds.amr, entry.adds.mfaAtMs !== undefined),
	);
	if (adding.length > 1) {
		refuse(
			"done holds more than one completion that adds a second factor: only the second-factor authority adds one, and it completes once",
		);
	}
	const interruptedBy = value.interruptedBy;
	if (!isNonEmptyString(interruptedBy)) {
		refuse("interruptedBy must name the requirement whose ceremony it waits on");
	}
	return Object.freeze({
		primary,
		done: Object.freeze(done),
		interruptedBy: interruptedBy as string,
	});
}

/**
 * The continuation admission answers an interruption with: the primary as
 * the route built it — without its `enrollmentFacts`, which a rehydration
 * derives again — and every completed requirement's additions, as the
 * serialisable DTO. Frozen.
 */
export function continuationOf(
	primary: PrimaryAuthentication,
	done: readonly CompletedRequirement[],
	interruptedBy: string,
): PrimaryContinuation {
	const { authTime, enrollmentFacts: _derivedAgain, ...fields } = primary;
	return Object.freeze({
		interruptedBy,
		primary: Object.freeze({ ...fields, authTimeMs: authTime.getTime() }),
		done: Object.freeze(
			done.map((entry) =>
				Object.freeze({
					requirement: entry.requirement,
					adds: Object.freeze({
						amr: Object.freeze([...entry.adds.amr]),
						...(entry.adds.mfaAt === undefined ? {} : { mfaAtMs: entry.adds.mfaAt.getTime() }),
					}),
				}),
			),
		),
	});
}
