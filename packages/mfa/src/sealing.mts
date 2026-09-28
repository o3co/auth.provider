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
 * Secrets at rest (the MFA ADR's D11), over core's key-ring envelope
 * (`sealWithKeyRing` / `openWithKeyRing`). One place seals, so no factor ever
 * holds a key (D7).
 *
 * - **A factor's data** is JSON sealed under the purpose `o3co:mfa:factor`
 *   with its record — subject ‖ factor id ‖ kind, each length-prefixed — as
 *   the authenticated data: data copied into another subject's record, under
 *   another id, or relabelled as another kind does not open.
 * - **A ceremony's state** — a challenge, a pending enrollment — is sealed
 *   with the transaction id (and the factor's kind) as the authenticated
 *   data, under a purpose of its own for each, so neither opens as the
 *   other, nor as a factor's data.
 * - **Every part of a binding or a digest is well-formed text**: UTF-8 would
 *   write a lone surrogate as U+FFFD's bytes, making two bindings one.
 *   Sealing and digesting refuse such a part; opening answers `unreadable`.
 * - **What is sealed is what opening gives back**: a JSON object of JSON
 *   values — plain objects and real arrays, nothing JSON would change, drop
 *   or refuse (a Date, a Map, a `toJSON`, a BigInt, NaN, a cycle), and no
 *   accessor at any depth — or a `RangeError` that quotes nothing. The value
 *   is read once, into a copy, and the copy is what is serialised: nothing a
 *   getter answers can differ between the check and the text.
 * - **Opening never throws** on what it is handed: `unreadable` for anything
 *   that is not its envelope or does not open to a JSON object under this
 *   binding — which no key would cure — and `key_unavailable`, naming the
 *   key, when the key that sealed it has left the ring — which putting the
 *   key back cures. Both are the coordinator's `503` and one
 *   `mfa_factor_unreadable` line, never "no factor" or a wrong code.
 * - **Rotation**: what is sealed is sealed under the ring's first key.
 *   Opening a factor's data sealed under another key logs
 *   `mfa_factor_sealed_with_retired_key` (info, the key id) once per key id,
 *   so an operator knows that key is still needed.
 * - **Keyed digests** for codes that are compared and never recovered: an
 *   HMAC-SHA-256 over the factor's kind and the parts, each length-prefixed,
 *   base64url, kept with the id of the key it was made under and compared
 *   in constant time under that key — or `key_unavailable` when it has left
 *   the ring. A stored value that is not such a digest is refused with a
 *   `RangeError`: it is neither a missing key nor a wrong code. The HMAC key is not the sealing key itself but one derived
 *   from it (HKDF-SHA-256, info `o3co:mfa:digest`): the same key is not used
 *   by two algorithms.
 *
 * Building one checks the ring as core's envelope does, and refuses an empty
 * one: every seal needs a first key.
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

/** The purpose a factor's data is sealed under (D11). Fixed while any is at rest. */
export const MFA_FACTOR_SEALING_PURPOSE = "o3co:mfa:factor";
/** The purpose a pending challenge's state is sealed under. */
export const MFA_CHALLENGE_SEALING_PURPOSE = "o3co:mfa:challenge";
/** The purpose a pending enrollment's state is sealed under. */
export const MFA_ENROLLMENT_SEALING_PURPOSE = "o3co:mfa:enrollment";

/** The HKDF info a digest key is derived from a ring key with. */
const DIGEST_KEY_INFO = "o3co:mfa:digest";

/** The record a factor's data belongs to (D7): what its sealing is bound to. */
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

/** What {@link jsonCopy} answers for a value JSON would not give back as it is. */
const NOT_JSON: unique symbol = Symbol("not JSON");

/** Whether any own property of `value` — enumerable or not, keyed by a string or a symbol — is an accessor. */
const hasAccessor = (value: object): boolean =>
	Reflect.ownKeys(value).some((key) => {
		const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
		return descriptor !== undefined && !("value" in descriptor);
	});

/**
 * A copy of `value` made of what its own data properties hold, each read
 * once, through its descriptor — or {@link NOT_JSON} when JSON would not give
 * it back as it is. JSON's: `null`, a boolean, a finite number, a string, a
 * real array (its prototype `Array.prototype`) of such values with no hole
 * and no `undefined`, or a plain object (its prototype `Object.prototype` or
 * none) whose enumerable values are such values or `undefined`, which JSON
 * leaves out and the copy does too. Refused: an accessor anywhere — a getter
 * or a setter, on an object or at an index, at any depth — since a getter
 * could answer this check one thing and the serialisation another; a Date, a
 * Map, a class instance, an Array subclass, a function (a `toJSON` among
 * them), a BigInt, NaN or Infinity, a cycle. What is serialised is the copy:
 * the value that was checked, and nothing read again.
 */
function jsonCopy(value: unknown, ancestors: Set<object>): unknown {
	if (value === null || typeof value === "string" || typeof value === "boolean") return value;
	if (typeof value === "number") return Number.isFinite(value) ? value : NOT_JSON;
	if (typeof value !== "object" || ancestors.has(value) || hasAccessor(value)) return NOT_JSON;
	const prototype = Object.getPrototypeOf(value);
	ancestors.add(value);
	try {
		if (Array.isArray(value)) {
			if (prototype !== Array.prototype) return NOT_JSON;
			// An array's length is an own data property it cannot redefine: read once.
			const length = Reflect.getOwnPropertyDescriptor(value, "length")?.value as number;
			const copy: unknown[] = [];
			for (let index = 0; index < length; index++) {
				// A hole has no descriptor; `undefined` JSON would write as null.
				const descriptor = Reflect.getOwnPropertyDescriptor(value, String(index));
				if (descriptor === undefined || descriptor.value === undefined) return NOT_JSON;
				const entry = jsonCopy(descriptor.value, ancestors);
				if (entry === NOT_JSON) return NOT_JSON;
				copy.push(entry);
			}
			return copy;
		}
		if (prototype !== Object.prototype && prototype !== null) return NOT_JSON;
		const copy: Record<string, unknown> = Object.create(null);
		for (const key of Object.keys(value)) {
			const entry: unknown = Reflect.getOwnPropertyDescriptor(value, key)?.value;
			if (entry === undefined) continue;
			const copied = jsonCopy(entry, ancestors);
			if (copied === NOT_JSON) return NOT_JSON;
			copy[key] = copied;
		}
		return copy;
	} finally {
		ancestors.delete(value);
	}
}

/**
 * `value` as JSON text, when it is a JSON object JSON gives back as it is —
 * the text of the copy {@link jsonCopy} checked, so parsing it gives back an
 * equal object — and `undefined` otherwise. Never throws.
 */
function jsonObjectText(value: unknown): string | undefined {
	if (!isJsonObject(value)) return undefined;
	try {
		const copy = jsonCopy(value, new Set());
		return copy === NOT_JSON ? undefined : JSON.stringify(copy);
	} catch {
		// A Proxy whose traps throw, or anything else that cannot be read.
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

const statePlacement = (binding: MfaStateBinding): Placement => ({
	purpose:
		binding?.use === "challenge"
			? MFA_CHALLENGE_SEALING_PURPOSE
			: binding?.use === "enrollment"
				? MFA_ENROLLMENT_SEALING_PURPOSE
				: "",
	record: bindingRecord([binding?.transactionId, binding?.kind]),
});

/** A sealing over `ring`. A `RangeError` for a ring the envelope refuses, or an empty one. */
export function createMfaSealing({ ring, logger = consoleLogger }: MfaSealingOptions): MfaSealing {
	checkSealingKeyRing(ring, "the MFA key ring");
	const first = ring[0];
	if (first === undefined) throw new RangeError("the MFA key ring has no key to seal with");
	const keys: SealingKeyRing = [...ring];
	const retiredSaid = new Set<string>();
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

	/** What a digest is made over: the kind and the parts, length-prefixed. A `RangeError` for parts that are not well-formed strings. */
	const digestInput = (kind: string, parts: readonly string[]): Buffer => {
		if (!Array.isArray(parts) || !parts.every(isWellFormedText)) {
			throw new RangeError("a digest is made over a list of well-formed strings");
		}
		return lengthPrefixed([kind, ...parts]);
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
					// A record that is not a digest is neither a missing key nor a
					// wrong code (D11): it is refused, quoting nothing.
					if (
						typeof stored !== "object" ||
						stored === null ||
						!isSealingKeyId(stored.keyId) ||
						typeof stored.digest !== "string" ||
						!DIGEST_TEXT.test(stored.digest)
					) {
						throw new RangeError("a stored digest must be { keyId, digest } as digest made it");
					}
					const input = digestInput(kind, parts);
					const entry = keys.find((candidate) => candidate.id === stored.keyId);
					if (entry === undefined) return "key_unavailable";
					return constantTimeStringEqual(mac(entry, input), stored.digest) ? "match" : "mismatch";
				},
			});
		},
	});
}
