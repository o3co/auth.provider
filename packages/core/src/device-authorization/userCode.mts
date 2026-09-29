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
 * Generating and normalising the two codes RFC 8628 defines.
 *
 * - **`device_code`** is a bearer credential nobody types: 256 bits,
 *   base64url, per §5.2's "very high entropy code".
 * - **`user_code`** is typed by a human: 8 characters of base 20 (~34.5
 *   bits), which §5.1 accepts only together with rate-limiting to about 5
 *   attempts. The code and the limit are one mitigation; never ship the
 *   code without the limit.
 *
 * The alphabet is RFC 8628 §6.1's consonants: no vowels (no code spells a
 * word) and no digits (no `0`/`O`, `1`/`I` style confusion). The hyphen is
 * presentation only; see `normaliseUserCode` for what input is accepted.
 */

import { randomBytes, randomInt } from "node:crypto";

/** RFC 8628 §6.1's base-20 character set. */
export const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ";

/** Characters per code. 8 × log2(20) ≈ 34.5 bits — the §5.1 worked example. */
export const USER_CODE_LENGTH = 8;

/** Where the display hyphen goes. Presentation only; never stored or compared. */
const USER_CODE_GROUP = 4;

/**
 * A fresh `user_code`, in display form (`BCDF-GHJK`).
 *
 * `randomInt` rather than `randomBytes() % 20`: the modulo of 256 by 20 is
 * biased toward the first 16 characters, which would quietly cost about a bit
 * of the 34.5 this is counting on. `randomInt` rejects and re-draws instead.
 */
export const generateUserCode = (): string => {
	let raw = "";
	for (let i = 0; i < USER_CODE_LENGTH; i++) {
		raw += USER_CODE_ALPHABET[randomInt(USER_CODE_ALPHABET.length)];
	}
	return formatUserCode(raw);
};

/** Insert the display hyphen into a normalised code. */
export const formatUserCode = (normalised: string): string => {
	const groups: string[] = [];
	for (let i = 0; i < normalised.length; i += USER_CODE_GROUP) {
		groups.push(normalised.slice(i, i + USER_CODE_GROUP));
	}
	return groups.join("-");
};

/**
 * Reduce what a human typed to the canonical form used for storage and
 * comparison, or `null` when it cannot be one of our codes.
 *
 * Case is folded and whitespace and hyphens dropped. Any other character
 * outside the alphabet is **rejected, not stripped**: stripping a mistyped
 * `0` could match a different code.
 */
export const normaliseUserCode = (input: string): string | null => {
	const compact = input.replace(/[\s-]/g, "").toUpperCase();
	if (compact.length !== USER_CODE_LENGTH) return null;
	for (const character of compact) {
		if (!USER_CODE_ALPHABET.includes(character)) return null;
	}
	return compact;
};

/**
 * A fresh `device_code`. 256 bits, base64url — §5.2 wants "a very high
 * entropy code", and nothing types this one.
 */
export const generateDeviceCode = (): string => randomBytes(32).toString("base64url");
