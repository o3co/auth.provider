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
 * Generating and normalising the two codes RFC 8628 defines (#298).
 *
 * They have opposite jobs and therefore opposite designs:
 *
 * - **`device_code`** is never shown to anyone. It is a bearer credential the
 *   device redeems, so RFC 8628 §5.2 asks for "a very high entropy code" and
 *   nothing about it needs to be typeable. 256 bits, base64url.
 *
 * - **`user_code`** is read off one screen and typed into another. Entropy
 *   fights usability directly here, and §5.1 resolves the fight with
 *   rate-limiting rather than length: "an 8-character base 20 user code (with
 *   roughly 34.5 bits of entropy)" is sufficient *when* "the rate-limiting
 *   interval and validity period would need to only allow 5 attempts". Those
 *   are two halves of one mitigation; shipping the code without the limit
 *   would be shipping 34.5 bits against an unlimited attacker.
 *
 * ### The character set
 *
 * `BCDFGHJKLMNPQRSTVWXZ` — the consonants, from RFC 8628 §6.1. Two properties
 * matter, and neither is arbitrary:
 *
 * - **No vowels**, so no arrangement of the 20 characters can spell a word.
 *   A code that reads as an obscenity in some language gets screenshotted
 *   rather than typed.
 * - **No characters that are confusable in a typical font.** The set omits
 *   every digit, so `0`/`O`, `1`/`I`/`l`, `5`/`S`, `8`/`B` and `2`/`Z` cannot
 *   arise. §6.1: "It is RECOMMENDED to avoid character sets that contain two
 *   or more characters that can easily be confused".
 *
 * The hyphen in `BCDF-GHJK` is presentation only. Normalisation drops it and
 * whitespace, and folds case — so `bcdf ghjk`, `BCDFGHJK` and `bcdf-ghjk` are
 * all the same code. Any *other* character outside the set is **rejected, not
 * stripped**: a user who mistypes a `0` for an `O` is told the code is wrong
 * rather than having a character silently removed and being matched against a
 * different code.
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
 * Reduce anything a human typed to the canonical form used for storage and
 * comparison, or `null` when it cannot be one of our codes.
 *
 * Lower case is folded up and formatting characters are dropped, because a
 * user copying `bcdf-ghjk` off a television has entered the right code.
 * Characters *outside* the alphabet are **rejected rather than stripped**: a
 * `0` typed for an `O` is a mistake, and silently removing it would turn an
 * 8-character mistake into a 7-character lookup that fails for a reason the
 * user cannot see — or worse, matches a different code.
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
