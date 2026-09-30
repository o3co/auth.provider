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
 * An email address as the provider digests and compares it — the email
 * factor's enrolled address against the account's current one — so every
 * reader spells one mailbox alike: surrounding whitespace dropped, Unicode
 * NFC, the domain in its ASCII form (IDNA), all in lower case. One mailbox
 * alone: an addr-spec (RFC 5322, widened to UTF-8 by RFC 6531), never a list,
 * an angle address, a comment or a domain literal — and never a local part a
 * relay could route onward or a mail user agent decode into another address:
 * no `%` or `!` in a dot-atom, no `@`, `%` or `!` in a quoted local part, no
 * encoded word (`=?…?=`, RFC 2047), and no `<` or `>` in a quoted local part,
 * which an SMTP envelope refuses. The domain is held to
 * letter-digit-hyphen labels, or labels with letters beyond ASCII, before it
 * is converted, so no URL parser's reading — a path, a query, a fragment, a
 * percent-escape, a character it maps to ASCII — can cut one domain down to
 * another.
 */

import { domainToASCII } from "node:url";

/** A dot-atom's atom: RFC 5322's atext, and letters, marks and digits beyond ASCII. */
const ATOM = /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~\p{L}\p{M}\p{N}]+$/u;

/** A quoted local part: printable ASCII but a quote or a backslash, or those letters, or a backslash before printable ASCII. */
const QUOTED = /^"(?:[\x21\x23-\x5B\x5D-\x7E\p{L}\p{M}\p{N}]|\\[\x21-\x7E])+"$/u;

/** A label as written: letters, digits and hyphens — letters beyond ASCII too — neither starting nor ending with a hyphen. */
const LABEL =
	/^[A-Za-z0-9\p{L}\p{M}\p{N}](?:[A-Za-z0-9\p{L}\p{M}\p{N}-]*[A-Za-z0-9\p{L}\p{M}\p{N}])?$/u;

/** A label in its ASCII form: letters, digits and hyphens, neither starting nor ending with a hyphen. */
const ASCII_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

/** The routing operators (RFC 5321 §2.3.11's source routes, `%` and `!` hacks): refused in a dot-atom. */
const DOT_ATOM_REFUSED = /[%!]/;

/** Refused inside a quoted local part: the routing operators, `@`, and the angle brackets an envelope refuses. */
const QUOTED_REFUSED = /[@%!<>]/;

/** An encoded word (RFC 2047), which a mail user agent decodes into other text. */
const ENCODED_WORD = /=\?.*\?=/;

/** The longest local part, label and domain RFC 5321 lets a mail carry, in octets. */
const MAX_LOCAL_OCTETS = 64;
const MAX_LABEL_OCTETS = 63;
const MAX_DOMAIN_OCTETS = 253;

/**
 * `local` as an addr-spec's local part reads it — a dot-atom or a quoted
 * string, without what a relay could route on or decode — in lower case, or
 * `undefined`. It is held to the grammar and the
 * octet limit as it is answered: lower-cased, then in NFC, since lower-casing
 * can lengthen a character or leave one a precomposed form exists for — so
 * reading the answer again changes nothing.
 */
function localPartOf(local: string): string | undefined {
	const lowered = local.toLowerCase().normalize("NFC");
	if (Buffer.byteLength(lowered, "utf8") > MAX_LOCAL_OCTETS) return undefined;
	if (ENCODED_WORD.test(lowered)) return undefined;
	if (QUOTED.test(lowered)) return QUOTED_REFUSED.test(lowered.slice(1, -1)) ? undefined : lowered;
	const readable =
		!DOT_ATOM_REFUSED.test(lowered) && lowered.split(".").every((atom) => ATOM.test(atom));
	return readable ? lowered : undefined;
}

/**
 * `domain` in its ASCII form, or `undefined` unless each label is held to
 * {@link LABEL} before conversion and, after it, an ASCII label is itself in
 * lower case and a label beyond ASCII is an A-label (`xn--`): so a label
 * conversion maps to plain ASCII — a fullwidth letter — is refused.
 */
function domainOf(domain: string): string | undefined {
	const labels = domain.split(".");
	if (!labels.every((label) => LABEL.test(label))) return undefined;
	const ascii = domainToASCII(domain);
	const converted = ascii.split(".");
	if (ascii === "" || converted.length !== labels.length) return undefined;
	const held = converted.every((label, index) => {
		const written = labels[index] as string;
		const same = /^[A-Za-z0-9-]+$/.test(written)
			? label === written.toLowerCase()
			: label.startsWith("xn--");
		return same && label.length <= MAX_LABEL_OCTETS && ASCII_LABEL.test(label);
	});
	return held && ascii.length <= MAX_DOMAIN_OCTETS ? ascii : undefined;
}

/**
 * `address` as {@link normaliseMailAddress} spells it, or `undefined` for a
 * value that is no address: not a string, not well-formed, carrying a
 * control character, a format character or whitespace, or not one addr-spec
 * — a dot-atom or a quoted local part of at most 64 octets once lower-cased,
 * holding nothing a relay could route on or decode ({@link localPartOf}),
 * then `@`, then a domain of labels as {@link domainOf} reads them.
 */
export function normaliseMailAddress(address: unknown): string | undefined {
	if (typeof address !== "string" || !address.isWellFormed()) return undefined;
	// A format character anywhere, even where trimming would drop it (a byte-order mark).
	if (/\p{Cf}/u.test(address)) return undefined;
	const trimmed = address.trim().normalize("NFC");
	if (/[\p{Cc}\s]/u.test(trimmed)) return undefined;
	const at = trimmed.lastIndexOf("@");
	if (at <= 0 || at === trimmed.length - 1) return undefined;
	const local = localPartOf(trimmed.slice(0, at));
	const domain = domainOf(trimmed.slice(at + 1));
	return local === undefined || domain === undefined ? undefined : `${local}@${domain}`;
}
