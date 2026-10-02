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
 * Secrets at rest, over core's key-ring envelope (`sealWithKeyRing` /
 * `openWithKeyRing`). Sealing happens only here, so no factor ever holds a key.
 *
 * - A factor's data is sealed under `o3co:mfa:factor` with its record (subject,
 *   factor id, kind, each length-prefixed) as authenticated data, so data copied
 *   to another subject, id or kind does not open. A ceremony's state (challenge,
 *   pending enrollment) is bound to its transaction id and kind under a purpose of
 *   its own, so neither opens as the other or as a factor's data.
 * - Every binding or digest part must be well-formed text: UTF-8 writes a lone
 *   surrogate as U+FFFD's bytes, which would make two bindings one.
 * - A factor's data and state are plain JSON-shaped values: plain objects,
 *   plain arrays, strings, finite numbers, booleans and `null`. What is sealed
 *   is their copy (`copyFactorValue`), each field read once, an own getter's
 *   included, frozen; the coordinator takes that copy where it reads a
 *   factor's answer and hands the same copy to everything that acts on it.
 *   Anything else — a class's instance, an Array subclass, a built-in, a
 *   cycle, a read that throws — is one `RangeError` that quotes nothing, never
 *   sealed in part.
 * - Opening never throws: `unreadable` for anything no key would cure, and
 *   `key_unavailable` (naming the key) when the sealing key has left the ring.
 *   Callers answer both with a `503`, never "no factor" or a wrong code.
 * - New seals use the ring's first key. Opening a factor's data sealed under
 *   another key logs `mfa_factor_sealed_with_retired_key` once per key id, and a
 *   stored digest compared under another key `mfa_digest_made_with_retired_key`,
 *   so an operator counts both before retiring the key.
 * - Keyed digests for codes compared but never recovered: HMAC-SHA-256 over the
 *   kind and parts (length-prefixed), under a key derived by HKDF-SHA-256 (info
 *   `o3co:mfa:digest`) so no key serves two algorithms; stored with the key id and
 *   compared in constant time. A stored value that is not such a digest is a
 *   `RangeError`: neither a missing key nor a wrong code.
 */

import { createHmac, hkdfSync } from "node:crypto";
import {
	checkSealingKeyRing,
	consoleLogger,
	constantTimeStringEqual,
	isSealingKeyId,
	type Logger,
	type MfaDigestMatch,
	type MfaDigests,
	type MfaFactorData,
	type MfaFactorState,
	type MfaKeyedDigest,
	openWithKeyRing,
	type SealingKey,
	type SealingKeyRing,
	sealWithKeyRing,
} from "@o3co/auth-provider-core";

/** The purpose a factor's data is sealed under. Fixed while any is at rest. */
export const MFA_FACTOR_SEALING_PURPOSE = "o3co:mfa:factor";
/** The purpose a pending challenge's state is sealed under. */
export const MFA_CHALLENGE_SEALING_PURPOSE = "o3co:mfa:challenge";
/** The purpose a pending enrollment's state is sealed under. */
export const MFA_ENROLLMENT_SEALING_PURPOSE = "o3co:mfa:enrollment";

/** The HKDF info a digest key is derived from a ring key with. */
const DIGEST_KEY_INFO = "o3co:mfa:digest";

/** The record a factor's data belongs to: what its sealing is bound to. */
export interface MfaFactorBinding {
	readonly subject: string;
	readonly id: string;
	readonly kind: string;
}

/** The ceremony a state belongs to: its transaction, the factor's kind, and whether it is a challenge's or a pending enrollment's. */
export interface MfaStateBinding {
	readonly transactionId: string;
	readonly kind: string;
	readonly use: "challenge" | "enrollment";
}

/**
 * What opening found: the value and the key that sealed it; `unreadable` —
 * not this envelope, or not for this binding; or `key_unavailable` — sealed
 * under a key no longer in the ring, named so it can be put back.
 */
export type OpenedMfaValue<T> =
	| { readonly state: "ok"; readonly value: T; readonly keyId: string }
	| { readonly state: "unreadable" }
	| { readonly state: "key_unavailable"; readonly keyId: string };

/** Sealing, opening and digesting under one key ring. */
export interface MfaSealing {
	/** `data`'s copy ({@link copyFactorValue}) as JSON, sealed to its record under the first key. A `RangeError` for data that is not a plain JSON object of plain JSON values, or a record with an empty part. */
	sealFactorData(binding: MfaFactorBinding, data: MfaFactorData): string;
	/** The data sealed to this record; never throws. */
	openFactorData(binding: MfaFactorBinding, sealed: unknown): OpenedMfaValue<MfaFactorData>;
	/** `state`'s copy ({@link copyFactorValue}) as JSON, sealed to its ceremony under the first key. */
	sealState(binding: MfaStateBinding, state: MfaFactorState): string;
	/** The state sealed to this ceremony; never throws. */
	openState(binding: MfaStateBinding, sealed: unknown): OpenedMfaValue<MfaFactorState>;
	/** Keyed digests bound to `kind`, as a factor of that kind is handed them. */
	digestsFor(kind: string): MfaDigests;
	/** Whether the ring holds the key `keyId` names: a digest made under another cannot be compared. */
	holdsKey(keyId: string): boolean;
}

export interface MfaSealingOptions {
	/** The ring, in order: the first key seals and digests, every key opens and matches. */
	readonly ring: SealingKeyRing;
	/** Where `mfa_factor_sealed_with_retired_key` goes. Absent, core's `consoleLogger`. */
	readonly logger?: Logger;
}

const u32 = (value: number): Buffer => {
	const out = Buffer.alloc(4);
	out.writeUInt32BE(value);
	return out;
};

/**
 * Whether `part` is well-formed text: UTF-8 writes a lone surrogate as
 * U+FFFD's bytes, so `"\uD800"`, `"\uDC00"` and `"\uFFFD"` would be one
 * binding, and one digest.
 */
const isWellFormedText = (part: unknown): part is string =>
	typeof part === "string" && part.isWellFormed();

/** Each part after its UTF-8 length, so no part can absorb its neighbour. Every part well-formed. */
const lengthPrefixed = (parts: readonly string[]): Buffer =>
	Buffer.concat(
		parts.flatMap((part) => {
			const bytes = Buffer.from(part, "utf8");
			return [u32(bytes.length), bytes];
		}),
	);

/** A binding's parts, length-prefixed — or `undefined` when one is not non-empty, well-formed text. */
const bindingRecord = (parts: readonly unknown[]): Buffer | undefined =>
	parts.every((part) => isWellFormedText(part) && part !== "")
		? lengthPrefixed(parts as readonly string[])
		: undefined;

const isJsonObject = (value: unknown): value is Readonly<Record<string, unknown>> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** What every refusal of a factor's data or state says: nothing of the value. */
const NOT_PLAIN_VALUE = "a factor's data or state must be a plain JSON object of plain JSON values";

/** What `copies` holds for an object while it is copied: met again inside itself, it is a cycle. */
const COPYING: unique symbol = Symbol("being copied");

const refuse = (): never => {
	throw new RangeError(NOT_PLAIN_VALUE);
};

/**
 * A factor's data or state as a plain JSON-shaped copy, each field read once,
 * frozen at every depth: what is sealed, and what the coordinator hands
 * everything that acts on the value, so nothing acts on what was not sealed.
 *
 * - `null`, a boolean, a string or a finite number other than `-0` (JSON writes
 *   it as `0`), as it is;
 * - a plain array (prototype `Array.prototype`): its `length` read once, its
 *   own keys exactly its indices — a hole, or a field of its own JSON would
 *   drop, is refused — and each index read once; `undefined` in it is
 *   refused, since JSON would write `null`;
 * - a plain object (prototype `Object.prototype` or none, read once): each
 *   own key read once — an own getter runs once — one read as `undefined`
 *   left out as JSON leaves it out, an own `__proto__` kept as the field it is.
 *
 * Every own key of either must be one JSON writes — a string, enumerable — so
 * a symbol's field or a hidden one, a hidden `toJSON` among them, is refused
 * rather than lost.
 *
 * Anything else is a `RangeError` with one fixed text: a class's instance, an
 * Array subclass, a built-in (a Date, a Map, a RegExp, a boxed number, a
 * Proxy over any of them), a function — a `toJSON` among them — a bigint,
 * NaN, an infinity, `-0`, a cycle, a read that throws, and nesting past the
 * stack, the copy's or JSON's. So a value is sealed whole or not at all, never in part. An object
 * two fields share is copied once.
 *
 * Not core's `copyByName` (beside `readPlainFields`), which snapshots a
 * record by the fields its type declares and so takes a record of any shape:
 * a factor's data and state declare no fields, so nothing names what to read
 * from a class's instance, and only a value JSON writes whole is taken.
 */
export function copyFactorValue(value: unknown): Readonly<Record<string, unknown>> {
	try {
		if (!isJsonObject(value)) return refuse();
		const copy = copyPlain(value, new Map()) as Readonly<Record<string, unknown>>;
		// Written once here, so a copy JSON cannot write — nesting a shared object
		// keeps shallow for the copy, deep for JSON — is refused where it is taken,
		// before anything acts on it.
		JSON.stringify(copy);
		return copy;
	} catch {
		// A value refused, a getter or a Proxy trap that throws, or nesting past
		// the stack: one answer, quoting nothing.
		throw new RangeError(NOT_PLAIN_VALUE);
	}
}

/** `value`'s copy ({@link copyFactorValue}) as JSON text; writing it is inside the same refusal. */
function factorValueText(value: unknown): string {
	const copy = copyFactorValue(value);
	try {
		return JSON.stringify(copy);
	} catch {
		throw new RangeError(NOT_PLAIN_VALUE);
	}
}

function copyPlain(value: unknown, copies: Map<object, unknown>): unknown {
	if (value === null || typeof value === "string" || typeof value === "boolean") return value;
	// -0 is refused: JSON writes it as 0, which would open as another value.
	if (typeof value === "number") {
		return Number.isFinite(value) && !Object.is(value, -0) ? value : refuse();
	}
	if (typeof value !== "object") return refuse();
	const known = copies.get(value);
	if (known === COPYING) return refuse();
	if (known !== undefined) return known;
	copies.set(value, COPYING);
	const prototype = Object.getPrototypeOf(value);
	const list = Array.isArray(value);
	if (list ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) {
		return refuse();
	}
	const copy = list ? copyList(value, copies) : copyFields(value, copies);
	copies.set(value, copy);
	return copy;
}

/**
 * `value`'s own keys, listed once, when each is a field JSON writes: a string
 * key, enumerable — else refused, since a field JSON would skip (a symbol's,
 * a hidden one) or call (a hidden `toJSON`) is content the copy would lose.
 * A list's `length` is not a field.
 */
function fieldsOf(value: object, list: boolean): string[] {
	const fields: string[] = [];
	for (const key of Reflect.ownKeys(value)) {
		if (list && key === "length") continue;
		if (typeof key !== "string" || !Object.prototype.propertyIsEnumerable.call(value, key)) {
			return refuse();
		}
		fields.push(key);
	}
	return fields;
}

function copyList(list: readonly unknown[], copies: Map<object, unknown>): readonly unknown[] {
	const length = list.length;
	const keys = fieldsOf(list, true);
	if (keys.length !== length || keys.some((key, index) => key !== String(index))) return refuse();
	const copy: unknown[] = [];
	for (let index = 0; index < length; index++) {
		const element = list[index];
		if (element === undefined) return refuse();
		copy.push(copyPlain(element, copies));
	}
	return Object.freeze(copy);
}

function copyFields(
	value: object,
	copies: Map<object, unknown>,
): Readonly<Record<string, unknown>> {
	const source = value as Readonly<Record<string, unknown>>;
	const copy: Record<string, unknown> = {};
	for (const key of fieldsOf(source, false)) {
		const field = source[key];
		if (field === undefined) continue;
		// Defined, not assigned: an own `__proto__` stays the field it is.
		Object.defineProperty(copy, key, {
			value: copyPlain(field, copies),
			enumerable: true,
			writable: true,
			configurable: true,
		});
	}
	return Object.freeze(copy);
}

/** What a digest's refusal of its parts says. */
const DIGEST_PARTS = "a digest is made over a list of well-formed strings";

/** The shape of a stored digest's digest: base64url of an HMAC-SHA-256, unpadded. */
const DIGEST_TEXT = /^[A-Za-z0-9_-]{43}$/;

/** Where a value is sealed: its purpose and its record, or `undefined` for a binding with a part that is not non-empty, well-formed text. */
interface Placement {
	readonly purpose: string;
	readonly record: Buffer | undefined;
}

const factorPlacement = (binding: MfaFactorBinding): Placement => ({
	purpose: MFA_FACTOR_SEALING_PURPOSE,
	record: bindingRecord([binding?.subject, binding?.id, binding?.kind]),
});

const statePlacement = (binding: MfaStateBinding): Placement => {
	const use = binding?.use;
	return {
		purpose:
			use === "challenge"
				? MFA_CHALLENGE_SEALING_PURPOSE
				: use === "enrollment"
					? MFA_ENROLLMENT_SEALING_PURPOSE
					: "",
		record: bindingRecord([binding?.transactionId, binding?.kind]),
	};
};

/** A sealing over `ring`. A `RangeError` for a ring the envelope refuses, or an empty one. */
export function createMfaSealing({ ring, logger = consoleLogger }: MfaSealingOptions): MfaSealing {
	checkSealingKeyRing(ring, "the MFA key ring");
	const first = ring[0];
	if (first === undefined) throw new RangeError("the MFA key ring has no key to seal with");
	const keys: SealingKeyRing = [...ring];
	const retiredSaid = new Set<string>();
	const retiredDigestSaid = new Set<string>();
	const digestKeys = new Map<string, Buffer>();

	const seal = (placement: Placement, value: unknown, what: string): string => {
		if (placement.record === undefined || placement.purpose === "") {
			throw new RangeError(
				`${what} is sealed to a binding whose every part is non-empty, well-formed text`,
			);
		}
		const text = factorValueText(value);
		return sealWithKeyRing(text, keys, {
			purpose: placement.purpose,
			record: placement.record,
		});
	};

	const open = (placement: Placement, sealed: unknown): OpenedMfaValue<Record<string, unknown>> => {
		if (typeof sealed !== "string" || placement.record === undefined || placement.purpose === "") {
			return { state: "unreadable" };
		}
		const opened = openWithKeyRing(sealed, keys, {
			purpose: placement.purpose,
			record: placement.record,
		});
		if (opened.state !== "ok") return opened;
		let value: unknown;
		try {
			value = JSON.parse(opened.value);
		} catch {
			return { state: "unreadable" };
		}
		return isJsonObject(value)
			? { state: "ok", value, keyId: opened.keyId }
			: { state: "unreadable" };
	};

	/** The HMAC key derived from a ring key, once per key. */
	const digestKey = (entry: SealingKey): Buffer => {
		let derived = digestKeys.get(entry.id);
		if (derived === undefined) {
			derived = Buffer.from(hkdfSync("sha256", entry.key, Buffer.alloc(0), DIGEST_KEY_INFO, 32));
			digestKeys.set(entry.id, derived);
		}
		return derived;
	};

	/** What a digest is made over: the kind and the parts — `length` read once, each part once — length-prefixed. A `RangeError` for parts that are not a list of well-formed strings. */
	const digestInput = (kind: string, parts: readonly string[]): Buffer => {
		const read: string[] = [];
		try {
			if (!Array.isArray(parts)) throw new RangeError(DIGEST_PARTS);
			const length = parts.length;
			for (let index = 0; index < length; index++) {
				const part: unknown = parts[index];
				if (!isWellFormedText(part)) throw new RangeError(DIGEST_PARTS);
				read.push(part);
			}
		} catch {
			// A part that is not text, or a read that throws: the same answer, quoting nothing.
			throw new RangeError(DIGEST_PARTS);
		}
		return lengthPrefixed([kind, ...read]);
	};

	const mac = (entry: SealingKey, input: Buffer): string =>
		createHmac("sha256", digestKey(entry)).update(input).digest("base64url");

	return Object.freeze({
		sealFactorData: (binding: MfaFactorBinding, data: MfaFactorData) =>
			seal(factorPlacement(binding), data, "a factor's data"),

		openFactorData(binding: MfaFactorBinding, sealed: unknown) {
			const opened = open(factorPlacement(binding), sealed);
			if (opened.state === "ok" && opened.keyId !== first.id && !retiredSaid.has(opened.keyId)) {
				retiredSaid.add(opened.keyId);
				logger.info({ keyId: opened.keyId }, "mfa_factor_sealed_with_retired_key");
			}
			return opened;
		},

		sealState: (binding: MfaStateBinding, state: MfaFactorState) =>
			seal(statePlacement(binding), state, "a ceremony's state"),

		openState: (binding: MfaStateBinding, sealed: unknown) => open(statePlacement(binding), sealed),

		holdsKey: (keyId: string) => keys.some((entry) => entry.id === keyId),

		digestsFor(kind: string): MfaDigests {
			if (!isWellFormedText(kind) || kind === "") {
				throw new RangeError("a digest is bound to a factor's kind, non-empty well-formed text");
			}
			return Object.freeze({
				digest: (parts: readonly string[]): MfaKeyedDigest => ({
					keyId: first.id,
					digest: mac(first, digestInput(kind, parts)),
				}),
				matchesDigest(parts: readonly string[], stored: MfaKeyedDigest): MfaDigestMatch {
					// Each field read once, by name. A record that is not a digest is neither a
					// missing key nor a wrong code: it is refused, quoting nothing.
					const { keyId, digest } =
						typeof stored === "object" && stored !== null
							? stored
							: ({} as Partial<MfaKeyedDigest>);
					if (!isSealingKeyId(keyId) || typeof digest !== "string" || !DIGEST_TEXT.test(digest)) {
						throw new RangeError("a stored digest must be { keyId, digest } as digest made it");
					}
					const input = digestInput(kind, parts);
					const entry = keys.find((candidate) => candidate.id === keyId);
					if (entry === undefined) return "key_unavailable";
					// A stored digest names the key it was made under: that key is still needed,
					// whatever this comparison finds.
					if (entry.id !== first.id && !retiredDigestSaid.has(entry.id)) {
						retiredDigestSaid.add(entry.id);
						logger.info({ keyId: entry.id }, "mfa_digest_made_with_retired_key");
					}
					return constantTimeStringEqual(mac(entry, input), digest) ? "match" : "mismatch";
				},
			});
		},
	});
}
