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
 * The standard mail text: a subject line and a body for each purpose,
 * carrying the code and the minutes it has left and nothing else of the
 * send; a send it cannot render is refused, quoting nothing of it.
 */

import { MAIL_PURPOSES, type MailSend } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { renderStandardMail } from "#/mail/render.mjs";

const NOW = Date.UTC(2026, 8, 30, 12, 0, 0);
const MINUTE = 60_000;

const send = (overrides: Partial<MailSend> = {}): MailSend => ({
	purpose: "login_code",
	subject: "u-alice",
	to: "alice@example.com",
	code: "482913",
	expiresAtMs: NOW + 10 * MINUTE,
	...overrides,
});

describe("renderStandardMail", () => {
	it("renders the login code as a sign-in code, with the minutes it has left and what to do if the reader did not sign in", () => {
		expect(renderStandardMail(send(), NOW)).toEqual({
			subject: "Your sign-in code",
			text: "Your sign-in code is 482913.\nIt expires in 10 minutes.\n\nIf you did not try to sign in, someone may know your password: change it.\n",
		});
	});

	it("renders the account-email proof and the email factor's enrollment code as confirmations of the address", () => {
		expect(renderStandardMail(send({ purpose: "account_email_proof" }), NOW)).toEqual({
			subject: "Confirm your email address",
			text: "Your code to confirm this email address is 482913.\nIt expires in 10 minutes.\n\nIf you did not try to sign in, someone may know your password: change it.\n",
		});
		expect(renderStandardMail(send({ purpose: "email_factor_enrollment" }), NOW)).toEqual({
			subject: "Confirm sign-in codes by email",
			text: "Your code to receive sign-in codes at this address is 482913.\nIt expires in 10 minutes.\n\nIf you did not ask for this, someone may know your password: change it.\n",
		});
	});

	it("gives every purpose a subject line of its own, on one line, and a body carrying the code", () => {
		const subjects = new Set<string>();
		for (const purpose of MAIL_PURPOSES) {
			const rendered = renderStandardMail(send({ purpose }), NOW);
			subjects.add(rendered.subject);
			expect(rendered.subject).not.toMatch(/[\r\n]/);
			expect(rendered.text).toContain("482913");
		}
		expect(subjects.size).toBe(MAIL_PURPOSES.length);
	});

	it("counts the minutes left up to a whole minute, one at least, and says one minute in the singular", () => {
		const minutes = (expiresAtMs: number) =>
			renderStandardMail(send({ expiresAtMs }), NOW).text.split("\n")[1];
		expect(minutes(NOW + 90_000)).toBe("It expires in 2 minutes.");
		expect(minutes(NOW + 30_000)).toBe("It expires in 1 minute.");
		expect(minutes(NOW + MINUTE)).toBe("It expires in 1 minute.");
		expect(minutes(NOW - MINUTE)).toBe("It expires in 1 minute.");
	});

	it("renders nothing of the account or the recipient", () => {
		for (const purpose of MAIL_PURPOSES) {
			const { subject, text } = renderStandardMail(send({ purpose }), NOW);
			for (const part of ["u-alice", "alice@example.com", "alice"]) {
				expect(`${subject}\n${text}`, `${purpose} ${part}`).not.toContain(part);
			}
		}
	});

	it("refuses a purpose outside the list, a code that is empty, no string or carries a control character, and an expiry that is no instant, quoting none of them", () => {
		const bad: Partial<Record<keyof MailSend, unknown>>[] = [
			{ purpose: "security_notice" },
			{ purpose: undefined },
			{ code: "" },
			{ code: 482913 },
			{ code: "4829\r\nBcc: mallory@example.com" },
			{ code: "4829\u0000" },
			{ code: "4829\u0085" },
			{ code: "\uD800" },
			{ expiresAtMs: Number.NaN },
			{ expiresAtMs: "soon" },
		];
		for (const overrides of bad) {
			let refused: unknown;
			try {
				renderStandardMail(send(overrides as Partial<MailSend>), NOW);
			} catch (error) {
				refused = error;
			}
			expect(refused, JSON.stringify(overrides)).toBeInstanceOf(RangeError);
			const message = (refused as Error).message;
			for (const part of ["4829", "mallory", "security_notice", "soon", "alice"]) {
				expect(message, JSON.stringify(overrides)).not.toContain(part);
			}
		}
	});
});
