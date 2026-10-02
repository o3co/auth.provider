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
 * - What is sealed is a copy: each field of the value read by name, once,
 *   however it is held (a getter, a class's instance, an Array subclass), into
 *   plain JSON data that is then checked and serialised. A value JSON does not
 *   hold as it is (a Date, a Map, a function, BigInt, NaN, a cycle, a hole) is
 *   refused, and so is a read that throws, quoting nothing.
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
	/** `data` as JSON, sealed to its record under the first key. A `RangeError` for data that is not a JSON object, or a record with an empty part. */
	sealFactorData(binding: MfaFactorBinding, data: MfaFactorData): string;
	/** The data sealed to this record; never throws. */
	openFactorData(binding: MfaFactorBinding, sealed: unknown): OpenedMfaValue<MfaFactorData>;
	/** `state` as JSON, sealed to its ceremony under the first key. */
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

/** What {@link copyByName} answers for a value that is not JSON data. */
const NOT_JSON: unique symbol = Symbol("not JSON");
/** What `copies` holds for an object while it is copied: met again inside itself, it is a cycle. */
const COPYING: unique symbol = Symbol("being copied");

/**
 * Whether JSON writes `value` as its own fields: a plain object, one without a
 * prototype, a class's instance — not a Date, a Map, a RegExp or another
 * built-in, which JSON writes as something else or as nothing.
 */
const writtenAsFields = (value: object): boolean =>
	Object.prototype.toString.call(value) === "[object Object]";

/**
 * `value` copied by name as JSON data, or {@link NOT_JSON}. Every read is an
 * ordinary one, so a getter runs, and each runs once:
 *
 * - `null`, a boolean, a string or a finite number, as it is;
 * - a list (`Array.isArray`, whatever its prototype): its `length` and each
 *   index read once, in order, into a plain array; a hole or an `undefined`
 *   is not JSON data, since JSON would write it as `null`;
 * - an object JSON writes as its fields ({@link writtenAsFields}): each own
 *   enumerable string key read once, one read as `undefined` left out as JSON
 *   leaves it out, into an object without a prototype. What its prototype
 *   holds is not a field, as JSON says, and a `toJSON` is not asked.
 *
 * Anything else is not JSON data: a bigint, NaN, an infinity, a symbol, a
 * function, `undefined`, a Date, a Map, and a cycle. `copies` keeps one copy
 * of an object two fields share, so it is read once. A read that throws is
 * let through as it was thrown.
 */
function copyByName(value: unknown, copies: Map<object, unknown>): unknown {
	if (value === null || typeof value === "string" || typeof value === "boolean") return value;
	if (typeof value === "number") return Number.isFinite(value) ? value : NOT_JSON;
	if (typeof value !== "object") return NOT_JSON;
	const known = copies.get(value);
	if (known === COPYING) return NOT_JSON;
	if (known !== undefined) return known;
	copies.set(value, COPYING);
	const copy = Array.isArray(value) ? copyList(value, copies) : copyFields(value, copies);
	copies.set(value, copy);
	return copy;
}

function copyList(list: readonly unknown[], copies: Map<object, unknown>): unknown {
	const length = list.length;
	const copy: unknown[] = [];
	for (let index = 0; index < length; index++) {
		if (!Object.hasOwn(list, index)) return NOT_JSON;
		const element = list[index];
		if (element === undefined) return NOT_JSON;
		const copied = copyByName(element, copies);
		if (copied === NOT_JSON) return NOT_JSON;
		copy.push(copied);
	}
	return copy;
}

function copyFields(value: object, copies: Map<object, unknown>): unknown {
	if (!writtenAsFields(value)) return NOT_JSON;
	const source = value as Readonly<Record<string, unknown>>;
	const copy: Record<string, unknown> = Object.create(null);
	for (const key of Object.keys(source)) {
		const field = source[key];
		if (field === undefined) continue;
		const copied = copyByName(field, copies);
		if (copied === NOT_JSON) return NOT_JSON;
		copy[key] = copied;
	}
	return copy;
}

/**
 * `value`'s copy ({@link copyByName}) as JSON text, when `value` is an object
 * whose copy is JSON data — so parsing the text gives back an equal object —
 * and `undefined` otherwise, a read that throws included. Never throws.
 */
function jsonObjectText(value: unknown): string | undefined {
	try {
		if (!isJsonObject(value)) return undefined;
		const copy = copyByName(value, new Map());
		return copy === NOT_JSON ? undefined : JSON.stringify(copy);
	} catch {
		// A getter that throws, or a Proxy whose trap does: the value cannot be read.
		return undefined;
	}
}

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
		const text = jsonObjectText(value);
		if (text === undefined) {
			throw new RangeError(
				`${what} must be a JSON object of JSON values, which JSON gives back as it is`,
			);
		}
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

	/** What a digest is made over: the kind and the parts, each read once, length-prefixed. A `RangeError` for parts that are not a list of well-formed strings. */
	const digestInput = (kind: string, parts: readonly string[]): Buffer => {
		const read = Array.isArray(parts) ? copyByName(parts, new Map()) : NOT_JSON;
		if (!Array.isArray(read) || !read.every(isWellFormedText)) {
			throw new RangeError("a digest is made over a list of well-formed strings");
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
