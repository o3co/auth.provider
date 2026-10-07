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
 * that every stage of the exchange reads instead of the answer, so a check
 * and the minted token cannot see two values of one member.
 *
 * What is copied, at each level: the members the stages read by name, own or
 * inherited, read whether or not `in` reports them, and kept whenever `in`
 * reports them (even with no value) or the read answers a value — the
 * answer's `sub`, `scope`, `aud`, `familyId`, `sid`, `act`, `may_act` and
 * `claims`; of `claims`, `azp`, `exp`, `iss`, `cnf` and `may_act`; of `cnf`,
 * the confirmation members (`jkt`, `x5t#S256`); of each `may_act` entry, `sub`
 * and `iss`; of each `act`, its nested `act` — and, below the answer itself,
 * every own enumerable key. So the copy holds every member a stage can read
 * off the answer, and is never looser than it. Where a stage reads a record
 * (the answer, `claims`, `cnf`, a `may_act` entry, `act`), an array is no
 * answer: an array's named members would not be copied. A `may_act` entry
 * reporting neither `sub` nor `iss` to `in`, which delegation therefore
 * matches with nothing, is copied as a value that matches nothing.
 *
 * Every member of an object is read at most once, however many paths reach
 * the object (an alias, a cycle): the reads are kept per object, and a copy
 * is registered before its members are copied. Every key is defined on the
 * copy as an own data property, so a key named `__proto__` is copied as a key
 * and never sets the copy's prototype. A read that throws propagates: the
 * caller answers it as the validator's outage. The authentication context the
 * built-in validator verified for the answer is carried to the copy.
 */

import type { ValidatedToken } from "@o3co/auth-provider-core";
import {
	type VerifiedAuthentication,
	verifiedAuthenticationOf,
} from "./validator/selfIssuedAccessToken.mjs";

/**
 * What a stage reads of an object: the members it reads by name, whether its
 * own enumerable keys are copied too, what it reads of a member, and of each
 * element of an array.
 */
interface Reads {
	/** Whether the position holds a record: an array there is no answer. */
	readonly record: boolean;
	/**
	 * Whether its reader tests the named members with `in`: a record that
	 * reports none of them is copied as one that matches nothing.
	 */
	readonly presence?: boolean;
	readonly names: readonly string[];
	readonly ownKeys: boolean;
	readonly of: Readonly<Record<string, Reads>>;
	readonly each?: Reads;
}

/** Below what a stage reads by name: own enumerable keys, nothing by name. */
const ANY: Reads = { record: false, names: [], ownKeys: true, of: {} };

/** A `may_act` entry: `sub` and `iss`, read by name (`in` and access) by delegation. */
const MAY_ACT_ENTRY: Reads = {
	record: true,
	presence: true,
	names: ["sub", "iss"],
	ownKeys: true,
	of: {},
};
/** A `may_act`: one entry, or an array of them. */
const MAY_ACT: Reads = { ...MAY_ACT_ENTRY, record: false, each: MAY_ACT_ENTRY };
/** A `cnf`: the members core's confirmation matcher reads. */
const CNF: Reads = { record: true, names: ["jkt", "x5t#S256"], ownKeys: true, of: {} };
/** An `act` chain: the nested `act` the chain-depth count follows. */
const ACT: Reads = { record: true, names: ["act"], ownKeys: true, of: {} };
(ACT.of as Record<string, Reads>).act = ACT;
/** The claims the grant reads by name. */
const CLAIMS: Reads = {
	record: true,
	names: ["azp", "exp", "iss", "cnf", "may_act"],
	ownKeys: true,
	of: { cnf: CNF, may_act: MAY_ACT },
};
/** The answer: its members, by name alone. */
const ANSWER: Reads = {
	record: true,
	names: ["sub", "scope", "aud", "familyId", "sid", "act", "may_act", "claims"],
	ownKeys: false,
	of: { act: ACT, may_act: MAY_ACT, claims: CLAIMS },
};

const authentications = new WeakMap<ValidatedToken, VerifiedAuthentication>();

/**
 * The copy of a `may_act` entry that reports neither `sub` nor `iss`: not a
 * record, so delegation matches no actor or client against it, as it matches
 * none against the entry.
 */
const MATCHES_NOTHING: readonly never[] = Object.freeze([]);

/** Thrown inside a copy where a record position holds an array: the answer is no answer. */
class NotARecord extends Error {}

/**
 * Whether `answer` has the shape of an answer — a record (an object that is
 * not an array) with a string `sub` and record `claims` — reading those two
 * members once each and copying nothing. A read that throws propagates.
 */
export function isValidatedShape(answer: unknown): answer is ValidatedToken {
	return hasAnswerShape(answer, new Reader());
}

/**
 * The plain, frozen copy of `answer`, or `null` when it is no answer: not a
 * record, a `sub` that is not a string, `claims` that are not a record, or an
 * array where a record is read (`cnf`, a `may_act` entry, `act`).
 */
export function snapshotValidated(answer: unknown): ValidatedToken | null {
	const reader = new Reader();
	if (!hasAnswerShape(answer, reader)) return null;
	let snapshot: ValidatedToken;
	try {
		snapshot = reader.copy(answer, ANSWER) as ValidatedToken;
	} catch (err) {
		if (err instanceof NotARecord) return null;
		throw err;
	}
	const authentication = verifiedAuthenticationOf(answer);
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

function hasAnswerShape(answer: unknown, reader: Reader): answer is ValidatedToken {
	if (!isRecord(answer)) return false;
	if (typeof reader.read(answer, "sub") !== "string") return false;
	return isRecord(reader.read(answer, "claims"));
}

function isRecord(value: unknown): value is object {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** One answer's reads: each member of each object read once, and each copy made once per `Reads`. */
class Reader {
	private readonly values = new Map<object, Map<string, unknown>>();
	private readonly keys = new Map<object, readonly string[]>();
	private readonly copies = new Map<object, Map<Reads, unknown>>();

	/** `source[key]`, read on the first call alone. */
	read(source: object, key: string): unknown {
		let values = this.values.get(source);
		if (values === undefined) {
			values = new Map();
			this.values.set(source, values);
		}
		if (values.has(key)) return values.get(key);
		const value: unknown = (source as Record<string, unknown>)[key];
		values.set(key, value);
		return value;
	}

	/** `value` as a plain, frozen copy holding what `reads` names. */
	copy(value: unknown, reads: Reads): unknown {
		if (typeof value !== "object" || value === null) return value;
		if (reads.record && Array.isArray(value)) throw new NotARecord();
		let byReads = this.copies.get(value);
		if (byReads === undefined) {
			byReads = new Map();
			this.copies.set(value, byReads);
		}
		if (byReads.has(reads)) return byReads.get(reads);
		if (Array.isArray(value)) {
			const out: unknown[] = [];
			byReads.set(reads, out);
			const length = this.read(value, "length") as number;
			for (let i = 0; i < length; i++) {
				out.push(this.copy(this.read(value, String(i)), reads.each ?? ANY));
			}
			return Object.freeze(out);
		}
		if (reads.presence && reads.names.every((name) => !(name in value))) {
			// Its reader finds none of the members it tests with `in`, so the record
			// matches nothing, whatever a read by name answers: so does the copy.
			byReads.set(reads, MATCHES_NOTHING);
			return MATCHES_NOTHING;
		}
		const out: Record<string, unknown> = {};
		byReads.set(reads, out);
		const names = new Set<string>(reads.ownKeys ? this.ownKeys(value) : []);
		for (const name of reads.names) {
			// Read whether or not `in` reports it: a stage reading the member by name
			// sees what this read sees.
			if (name in value || this.read(value, name) !== undefined) names.add(name);
		}
		for (const name of names) {
			define(
				out,
				name,
				this.copy(
					this.read(value, name),
					Object.hasOwn(reads.of, name) ? (reads.of[name] as Reads) : ANY,
				),
			);
		}
		return Object.freeze(out);
	}

	private ownKeys(source: object): readonly string[] {
		let keys = this.keys.get(source);
		if (keys === undefined) {
			keys = Object.keys(source);
			this.keys.set(source, keys);
		}
		return keys;
	}
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
