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
 * The standard mail text: for each purpose a subject line and a plain-text
 * body, in English, carrying the code and the minutes it has left. Nothing
 * else of the send is rendered: not the account, not the recipient, nothing
 * clickable. A send it cannot render is a `RangeError` that quotes nothing
 * of the send.
 */

import {
	hasControlCharacter,
	MAIL_PURPOSES,
	type MailPurpose,
	type MailSend,
} from "@o3co/auth-provider-core";

/** A mail as the standard text renders it. */
export interface RenderedMail {
	/** One line, with no control character. */
	readonly subject: string;
	readonly text: string;
}

const IF_NOT_SIGNING_IN =
	"If you did not try to sign in, someone may know your password: change it.";

/** Each purpose's subject line, the body's first line around the code, and its last line. */
const TEMPLATES: Readonly<
	Record<
		MailPurpose,
		{
			readonly subject: string;
			readonly opening: (code: string) => string;
			readonly closing: string;
		}
	>
> = {
	login_code: {
		subject: "Your sign-in code",
		opening: (code) => `Your sign-in code is ${code}.`,
		closing: IF_NOT_SIGNING_IN,
	},
	account_email_proof: {
		subject: "Confirm your email address",
		opening: (code) => `Your code to confirm this email address is ${code}.`,
		closing: IF_NOT_SIGNING_IN,
	},
	email_factor_enrollment: {
		subject: "Confirm sign-in codes by email",
		opening: (code) => `Your code to receive sign-in codes at this address is ${code}.`,
		closing: "If you did not ask for this, someone may know your password: change it.",
	},
};

/** The whole minutes `expiresAtMs` is from `nowMs`, rounded up, one at least. */
const minutesLeft = (expiresAtMs: number, nowMs: number): number =>
	Math.max(1, Math.ceil((expiresAtMs - nowMs) / 60_000));

/**
 * The subject line and body of `mail` at `nowMs`, the time the minutes left
 * are counted from.
 */
export function renderStandardMail(mail: MailSend, nowMs: number): RenderedMail {
	const { purpose, code, expiresAtMs } = mail;
	if (!(MAIL_PURPOSES as readonly unknown[]).includes(purpose)) {
		throw new RangeError(
			`renderStandardMail: the purpose is not one of ${MAIL_PURPOSES.join(", ")}`,
		);
	}
	if (
		typeof code !== "string" ||
		code === "" ||
		!code.isWellFormed() ||
		hasControlCharacter(code)
	) {
		throw new RangeError(
			"renderStandardMail: the code must be well-formed text, not empty, with no control character",
		);
	}
	if (typeof expiresAtMs !== "number" || !Number.isFinite(expiresAtMs)) {
		throw new RangeError("renderStandardMail: the expiry must be an instant in epoch milliseconds");
	}
	const minutes = minutesLeft(expiresAtMs, nowMs);
	const template = TEMPLATES[purpose];
	return {
		subject: template.subject,
		text: `${template.opening(code)}\nIt expires in ${minutes} ${minutes === 1 ? "minute" : "minutes"}.\n\n${template.closing}\n`,
	};
}
