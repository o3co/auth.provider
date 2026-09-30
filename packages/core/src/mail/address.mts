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
 * NFC, the domain in its ASCII form (IDNA), all in lower case.
 */

import { domainToASCII } from "node:url";

/**
 * `address` as {@link normaliseMailAddress} spells it, or `undefined` for a
 * value that is no address: not a string, not well-formed, carrying a control
 * character or whitespace, or without a non-empty local part and a domain of
 * non-empty labels around its last `@`.
 */
export function normaliseMailAddress(address: unknown): string | undefined {
	if (typeof address !== "string" || !address.isWellFormed()) return undefined;
	const trimmed = address.trim().normalize("NFC");
	if (/[\p{Cc}\s]/u.test(trimmed)) return undefined;
	const at = trimmed.lastIndexOf("@");
	if (at <= 0 || at === trimmed.length - 1) return undefined;
	const domain = domainToASCII(trimmed.slice(at + 1));
	if (domain === "" || domain.split(".").some((label) => label === "")) return undefined;
	return `${trimmed.slice(0, at).toLowerCase()}@${domain.toLowerCase()}`;
}
