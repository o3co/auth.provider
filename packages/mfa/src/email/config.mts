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
 * The email factor's section, `mfa-email-factor` (the MFA ADR's D19, F5,
 * O7): its switch, whether a verification adds `mfa`, a code's life, the
 * sends one transaction allows and the pause between them, the budget of
 * sends per subject, and the message's subject and text. Strict: a key the
 * section does not know is refused. Every leaf reads the string an
 * environment variable carries. The subject is one line of text, since a
 * header carries it; the text carries `{code}`, and may carry `{minutes}`.
 * The ranges the ADR does not state are this schema's: a code lives 60 to
 * 1800 seconds, as a transaction does; 1 to 10 sends, 0 to 600 seconds
 * apart; a budget's window at most a year, as every rate-limit budget's.
 */

import { coerceBooleanFromEnv } from "@o3co/auth-provider-core";
import { z } from "zod";
import { environmentWholeNumber, hasControlCharacter, sectionError } from "../config.mjs";

/** The longest window a rate-limit budget may take: a year, in seconds. */
const YEAR_SECONDS = 31_536_000;

const SUBJECT_RULE =
	"must be well-formed text on one line, not blank, at most 200 characters, with no control character — a mail header carries it";
const BODY_RULE =
	"must be well-formed text, at most 2000 characters, with no control character but line breaks and tabs, carrying {code}";

/** The characters a message's text may carry beside printable ones. */
const TEXT_LAYOUT: ReadonlySet<string> = new Set(["\n", "\t"]);

const subjectSchema = z
	.string({ error: SUBJECT_RULE })
	.refine(
		(subject) =>
			subject.isWellFormed() &&
			subject.trim() !== "" &&
			subject.length <= 200 &&
			!hasControlCharacter(subject),
		{ error: SUBJECT_RULE },
	);

const bodySchema = z
	.string({ error: BODY_RULE })
	.refine(
		(body) =>
			body.isWellFormed() &&
			body.length <= 2000 &&
			body.includes("{code}") &&
			!hasControlCharacter(body, TEXT_LAYOUT),
		{ error: BODY_RULE },
	);

/** `mfa-email-factor.sendLimit`: the sends one subject is allowed per window. */
const sendLimitSchema = z.strictObject(
	{
		limit: environmentWholeNumber(1, Number.MAX_SAFE_INTEGER, ""),
		windowSeconds: environmentWholeNumber(1, YEAR_SECONDS, " seconds"),
	},
	{ error: sectionError },
);

/** The email factor's section, `mfa-email-factor`, as its module parses it before any factory runs. */
export const mfaEmailFactorConfigSchema = z.strictObject(
	{
		enabled: coerceBooleanFromEnv,
		addsMfa: coerceBooleanFromEnv,
		codeTtlSeconds: environmentWholeNumber(60, 1800, " seconds"),
		maxSends: environmentWholeNumber(1, 10, ""),
		resendAfterSeconds: environmentWholeNumber(0, 600, " seconds"),
		sendLimit: sendLimitSchema,
		subject: subjectSchema,
		body: bodySchema,
	},
	{ error: sectionError },
);

/** `mfa-email-factor` as its schema reads it. */
export type MfaEmailFactorSettings = z.infer<typeof mfaEmailFactorConfigSchema>;
