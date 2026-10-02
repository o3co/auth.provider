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
 * `readDeviceAuthorization`: the one reading of a `DeviceAuthorization` a
 * `DeviceCodeStore` answers, into a plain copy whose every field holds what
 * `DeviceAuthorization` declares, or a refusal naming the field that does
 * not. A consumer reads nothing of the store's object but this copy, so a
 * field that throws when read, or holds the wrong type, is a refusal it
 * answers rather than an error it lets escape.
 */

import { isStorableExpiry } from "../adapters/expiry.mjs";
import { isScopeToken } from "../federations/scope.mjs";
import { wellFormedAmr } from "../grants/authenticationClaims.mjs";
import { isRecordableInstant } from "./approval.mjs";
import type { DeviceAuthorization, DeviceAuthorizationStatus } from "./types.mjs";

/** What `readDeviceAuthorization` answers: the copy, or why the record is refused. */
export type DeviceAuthorizationReading =
	| { readonly ok: true; readonly authorization: DeviceAuthorization }
	| { readonly ok: false; readonly refused: "not_an_object" }
	| {
			readonly ok: false;
			readonly refused: "malformed";
			readonly field: keyof DeviceAuthorization;
	  };

/** A field whose value is not what `DeviceAuthorization` declares for it. */
const MALFORMED: unique symbol = Symbol("malformed");

/** Every value `DeviceAuthorizationStatus` admits: `satisfies` fails the build when the type gains or loses one. */
const STATUSES = {
	pending: true,
	approved: true,
	denied: true,
} as const satisfies Record<DeviceAuthorizationStatus, true>;

const nonEmptyString = (value: unknown): string | typeof MALFORMED =>
	typeof value === "string" && value.length > 0 ? value : MALFORMED;

/**
 * A list of RFC 6749 §3.3 scope-tokens (`isScopeToken`), each index read
 * once, as a frozen copy: an entry holding a space would name a second scope
 * once the list is joined. A hole is not a scope-token.
 */
const scopeList = (value: unknown): readonly string[] | typeof MALFORMED => {
	if (!Array.isArray(value)) return MALFORMED;
	const copy: string[] = [];
	const length = value.length;
	for (let index = 0; index < length; index++) {
		const entry: unknown = value[index];
		if (typeof entry !== "string" || !isScopeToken(entry)) return MALFORMED;
		copy.push(entry);
	}
	return Object.freeze(copy);
};

/** `rule`'s answer, or `undefined` for a field holding none. */
const optional =
	<T,>(rule: (value: unknown) => T | typeof MALFORMED) =>
	(value: unknown): T | undefined | typeof MALFORMED =>
		value === undefined ? undefined : rule(value);

/** Whole epoch milliseconds at or after the epoch that a `Date` holds, as a store records an instant. */
const recordedInstant = (value: unknown): number | typeof MALFORMED =>
	typeof value === "number" &&
	isRecordableInstant(value) &&
	!Number.isNaN(new Date(value).getTime())
		? value
		: MALFORMED;

/**
 * How each field `DeviceAuthorization` declares is read: handed a thunk that
 * reads it once, answering its value or `MALFORMED`. A thunk that throws is
 * `MALFORMED` too, except where a rule says otherwise. A field the type
 * gains, or loses, fails to compile here.
 */
const FIELDS: {
	readonly [K in keyof DeviceAuthorization]-?: (
		read: () => unknown,
	) => DeviceAuthorization[K] | typeof MALFORMED;
} = {
	userCode: (read) => nonEmptyString(read()),
	clientId: (read) => nonEmptyString(read()),
	requestedScope: (read) => optional(scopeList)(read()),
	// The rule a store's `create` holds an expiry to; a fractional one is valid.
	expiresAtMs: (read) => {
		const value = read();
		return typeof value === "number" && isStorableExpiry(value) ? value : MALFORMED;
	},
	intervalSeconds: (read) => {
		const value = read();
		return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : MALFORMED;
	},
	status: (read) => {
		const value = read();
		return typeof value === "string" && Object.hasOwn(STATUSES, value)
			? (value as DeviceAuthorizationStatus)
			: MALFORMED;
	},
	subject: (read) => optional(nonEmptyString)(read()),
	grantedScope: (read) => optional(scopeList)(read()),
	approvedAtMs: (read) => optional(recordedInstant)(read()),
	// An `amr` that cannot be read — a throwing read included — is none:
	// "cannot tell", which stamps no `amr`.
	amr: (read) => {
		try {
			const amr = wellFormedAmr(read());
			return amr === undefined ? undefined : Object.freeze(amr);
		} catch {
			return undefined;
		}
	},
	authTimeMs: (read) => optional(recordedInstant)(read()),
};

const FIELD_NAMES = Object.keys(FIELDS) as (keyof DeviceAuthorization)[];

/** Whether `value` is an object other than a list; one whose shape cannot be checked (a revoked Proxy) is not. */
const isRecordShaped = (value: unknown): value is object => {
	if (typeof value !== "object" || value === null) return false;
	try {
		return !Array.isArray(value);
	} catch {
		return false;
	}
};

/**
 * `record` read into a `DeviceAuthorization`: each declared field read by
 * name, once, however the object holds it — own data, an accessor,
 * inherited, a class instance — and nothing else of it. The copy has every
 * key, `undefined` where the record holds none, and is frozen at every depth,
 * sharing nothing with `record`.
 *
 * Refused: a `record` that is not an object, or whose shape cannot be
 * checked (`not_an_object`); a field whose
 * read throws or whose value is not what the type declares (`malformed`,
 * naming it). A scope is a list of RFC 6749 §3.3 scope-tokens. An expiry is
 * held to `isStorableExpiry`; an approval instant and an authentication time
 * to whole epoch milliseconds at or after the epoch that a `Date` holds, as
 * `recordableDeviceApproval` records one. Neither is read against a clock
 * here: that is the consumer's. An `amr` that is not a non-empty list of non-empty strings, or cannot be
 * read, is read as none rather than refused.
 */
export function readDeviceAuthorization(record: unknown): DeviceAuthorizationReading {
	if (!isRecordShaped(record)) return { ok: false, refused: "not_an_object" };
	const source = record as Record<string, unknown>;
	const copy: Record<string, unknown> = {};
	for (const field of FIELD_NAMES) {
		let value: unknown;
		try {
			value = FIELDS[field](() => source[field]);
		} catch {
			value = MALFORMED;
		}
		if (value === MALFORMED) return { ok: false, refused: "malformed", field };
		copy[field] = value;
	}
	return { ok: true, authorization: Object.freeze(copy) as unknown as DeviceAuthorization };
}
