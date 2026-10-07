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
 * RFC 4648 base32 without padding: the spelling of a TOTP secret the user is
 * shown and the `otpauth://` URI carries (the MFA ADR's F6), and the one the
 * factor keeps in its data. Decoding takes only what encoding produces —
 * upper case, no padding, a length some number of bytes encodes to, and no
 * stray bits in the last character — so a secret is never read as another
 * one it happens to resemble.
 */
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/** The lengths, modulo 8, that some whole number of bytes encodes to without padding. */
const ENCODED_LENGTHS = new Set([0, 2, 4, 5, 7]);
/** `bytes` in RFC 4648 base32, upper case, without padding. */
export function encodeBase32(bytes) {
    let out = "";
    let buffer = 0;
    let bits = 0;
    for (const byte of bytes) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out += ALPHABET[(buffer >>> bits) & 0x1f];
        }
        buffer &= (1 << bits) - 1;
    }
    if (bits > 0)
        out += ALPHABET[(buffer << (5 - bits)) & 0x1f];
    return out;
}
/** The bytes `text` encodes, or `undefined` when it is not what {@link encodeBase32} would write. */
export function decodeBase32(text) {
    if (typeof text !== "string" || !/^[A-Z2-7]*$/.test(text))
        return undefined;
    if (!ENCODED_LENGTHS.has(text.length % 8))
        return undefined;
    const bytes = [];
    let buffer = 0;
    let bits = 0;
    for (const character of text) {
        buffer = (buffer << 5) | ALPHABET.indexOf(character);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            bytes.push((buffer >>> bits) & 0xff);
        }
        buffer &= (1 << bits) - 1;
    }
    // The last character's unused bits are zero in anything encoding wrote.
    return buffer === 0 ? Buffer.from(bytes) : undefined;
}
