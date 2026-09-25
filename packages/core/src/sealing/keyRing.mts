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
 * The key ring a value is sealed under at rest: what one key is, what a ring
 * of them must satisfy, and how a configured key becomes key material. The
 * envelope that uses the ring is `envelope.mts`.
 */

/** AES-256: every key in a ring is exactly this many bytes. */
export const SEALING_KEY_BYTES = 32;

/**
 * One key in a sealing key ring. The ring's first entry seals; every entry
 * may open.
 *
 * A ring, and not one key, because a mistake with the key revokes every value
 * sealed under it at once: an operator must be able to introduce a key
 * without re-sealing values at rest, and to put back a key that was dropped by
 * accident.
 */
export interface SealingKey {
	/** Named inside the envelope. One to 64 characters of `A-Za-z0-9_-`: the separator may not appear in it. */
	readonly id: string;
	/** {@link SEALING_KEY_BYTES} bytes. */
	readonly key: Buffer;
}

/** The keys a value is sealed and opened under, in order: the first seals. */
export type SealingKeyRing = readonly SealingKey[];

const KEY_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

/** Whether `id` is one a ring may hold, and so one an envelope may name. */
export const isSealingKeyId = (id: string): boolean => KEY_ID_PATTERN.test(id);

/**
 * Refuses, as a `RangeError`, a ring no envelope could be sealed or opened
 * under: a key ID outside the rule, a duplicate ID, or key material that is
 * not {@link SEALING_KEY_BYTES} bytes. A ring is a setting, and one that is
 * given but unusable is refused rather than worked around. An empty ring
 * passes; whether one may be empty is the caller's to say (it can open
 * nothing and seal nothing).
 */
export function checkSealingKeyRing(ring: SealingKeyRing): void {
	const seen = new Set<string>();
	for (const entry of ring) {
		if (!isSealingKeyId(entry.id)) {
			throw new RangeError(`encryption key id must match ${KEY_ID_PATTERN.source}`);
		}
		if (seen.has(entry.id)) throw new RangeError("duplicate encryption key id");
		seen.add(entry.id);
		if (entry.key.length !== SEALING_KEY_BYTES) {
			throw new RangeError(`encryption key must be ${SEALING_KEY_BYTES} bytes`);
		}
	}
}

/**
 * A configured key as key material: canonical base64 of exactly
 * {@link SEALING_KEY_BYTES} bytes, or `undefined`. The caller refuses the
 * `undefined`, naming the configuration key it read.
 *
 * `Buffer.from(…, "base64")` ignores embedded whitespace and drops what it
 * cannot decode, so a value is read only if re-encoding gives it back
 * exactly: a key pasted out of a file with its newline, or wrapped by a
 * secret manager, is not the value an operator checked.
 */
export function decodeSealingKey(encoded: string): Buffer | undefined {
	if (/\s/.test(encoded)) return undefined;
	const bytes = Buffer.from(encoded, "base64");
	if (bytes.toString("base64") !== encoded) return undefined;
	return bytes.length === SEALING_KEY_BYTES ? bytes : undefined;
}
