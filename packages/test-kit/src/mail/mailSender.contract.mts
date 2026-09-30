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
 * The conformance suite of a `MailSender`, the `mailSender` slot's value.
 *
 * `mailSenderContract(input)` holds a sender to what the provider relies on:
 * a `kind` that names it; a send the relay accepted answered `delivered`,
 * the relay, copied before the send and compared whole after it, then
 * holding one mail more — its envelope addressed to the recipient alone,
 * carrying the code — and nothing else new, for every purpose; a relay
 * refusing at a limit answered `refused_at_limit` (the provider's `429`);
 * each answer read as the provider reads it, through core's
 * `mailSendOutcome`; under each other way a relay refuses
 * (`MAIL_RELAY_REFUSALS`), a transient failure among them, a rejection, never
 * an answer (its `503`); and the mail it is handed left as it was. Every text
 * field of the mail but its purpose, a closed list, carries one mark, and so
 * does the relay's reply, which the suite writes. No rejection's loggable
 * projection (`loggableError`, its message and its causes') carries the
 * mark — in text, or in base64 at any of the three offsets a field may start
 * at — a field in base64 or the expiry, searched in lower case over letters
 * and digits alone.
 *
 * What it cannot see, and a sender's own tests must: what the sender logs
 * itself (a transport's debug transcript, say), an error's properties
 * outside the projection, and an encoding of the mail other than base64.
 */

import assert from "node:assert/strict";
import {
	loggableError,
	MAIL_PURPOSES,
	type MailPurpose,
	type MailSend,
	type MailSender,
	mailSendOutcome,
} from "@o3co/auth-provider-core";
import type { ContractCase } from "@o3co/auth-provider-core/testing";

/** The ways a relay refuses a mail, each a case of the suite. `limit` is the one a sender answers rather than rejects. */
export const MAIL_RELAY_REFUSALS = Object.freeze([
	"recipient_refused",
	"message_refused",
	"unreachable",
	"auth_failed",
	"temporary_failure",
	"limit",
] as const);

/** A way a relay refuses a mail: see {@link MAIL_RELAY_REFUSALS}. */
export type MailRelayRefusal = (typeof MAIL_RELAY_REFUSALS)[number];

/** A mail as the relay holds it: the recipients its envelope named, in order, and the whole message as text. */
export interface RelayedMail {
	readonly to: readonly string[];
	readonly content: string;
}

export interface MailSenderContractInput {
	/** A fresh sender over a relay that accepts, and what that relay holds, oldest first. */
	readonly build: () => {
		readonly sender: MailSender;
		readonly relayed: () => Promise<readonly RelayedMail[]>;
	};
	/**
	 * A fresh sender over a relay that refuses as `refusal` names, answering
	 * `reply` as its own text: the status line after `RCPT TO` or `DATA`, the
	 * answer to `AUTH`, or the connection's failure for an unreachable one.
	 */
	readonly refusing: (refusal: MailRelayRefusal, reply: string) => MailSender;
}

/**
 * Text no relay, library or transport writes by chance, at the start of
 * every text field of the mail and in the relay's reply: found in a
 * projection only when copied from one of them.
 */
const MARK = "zq7kx3";

/** An expiry with digits no error carries by chance, in its ISO form too. */
const EXPIRES_AT_MS = Date.UTC(2099, 11, 31, 23, 59, 58, 713);

/** A mail each of whose text fields starts with the mark. */
const mailOf = (serial: number, purpose: MailPurpose = "login_code"): MailSend =>
	Object.freeze({
		purpose,
		subject: `${MARK}s${serial}`,
		to: `${MARK}r${serial}@example.com`,
		code: `${MARK}c${serial}`,
		expiresAtMs: EXPIRES_AT_MS,
	});

/** What the relay answers under each refusal, as the suite writes it: marked, and echoing the recipient where a relay would. */
const replyTo = (refusal: MailRelayRefusal, mail: MailSend): string => {
	switch (refusal) {
		case "recipient_refused":
			return `550 5.1.1 <${mail.to}>: ${MARK} recipient address rejected`;
		case "message_refused":
			return `554 5.7.1 ${MARK} message content rejected`;
		case "unreachable":
			return `connect ECONNREFUSED ${MARK}.relay.example:587`;
		case "auth_failed":
			return `535 5.7.8 ${MARK} authentication credentials invalid`;
		case "temporary_failure":
			return `421 4.3.2 <${mail.to}>: ${MARK} service not available, try again later`;
		case "limit":
			return `451 4.7.1 <${mail.to}>: ${MARK} rate limited, try again later`;
	}
};

/** What each refusal is called in its case's name. */
const REFUSAL_TEXT: Readonly<Record<Exclude<MailRelayRefusal, "limit">, string>> = {
	recipient_refused: "refuses the recipient",
	message_refused: "refuses the message",
	unreachable: "cannot be reached",
	auth_failed: "refuses the sender's credentials",
	temporary_failure: "fails for now",
};

/** Text as the suite searches it: lower case, letters and digits alone. */
const normalised = (text: string): string => text.toLowerCase().replace(/[^a-z0-9]/g, "");

/**
 * The base64 characters `text`'s bytes alone decide, when they start
 * `offset` bytes into what is encoded: a field that opens with the mark
 * carries these wherever its encoding starts.
 */
const base64At = (text: string, offset: number): string => {
	const bytes = Buffer.from(text);
	const encoded = Buffer.concat([Buffer.alloc(offset), bytes]).toString("base64");
	return encoded.slice(Math.ceil((8 * offset) / 6), Math.floor((8 * (offset + bytes.length)) / 6));
};

/**
 * What a projection must never carry of `mail`, normalised: the mark — in
 * text, and in base64 at each of the three offsets a field may start at —
 * each text field in base64, and the expiry as a number and as a date.
 */
const neverLogged = (mail: MailSend): string[] =>
	[
		MARK,
		...[0, 1, 2].map((offset) => base64At(MARK, offset)),
		...[mail.to, mail.code, mail.subject].flatMap((field) => [
			Buffer.from(field).toString("base64"),
			Buffer.from(field).toString("base64url"),
		]),
		String(mail.expiresAtMs),
		new Date(mail.expiresAtMs).toISOString(),
	].map(normalised);

/** The rejection of `sending`, or a failure saying what it resolved with. */
async function rejectionOf(sending: Promise<unknown>): Promise<unknown> {
	let answer: unknown;
	try {
		answer = await sending;
	} catch (error) {
		return error;
	}
	assert.fail(
		`send over a refusing relay answered ${JSON.stringify(answer)}: an outage must reject, never answer`,
	);
}

/** The answer of `sending`, or a failure saying it rejected. */
async function answerOf(sending: Promise<unknown>, what: string): Promise<unknown> {
	try {
		return await sending;
	} catch (error) {
		assert.fail(`${what} rejected (${String(error)}): the provider would answer an outage`);
	}
}

/** What the relay holds, copied: records and envelopes a relay goes on changing stay as they were read. */
const copied = (held: readonly RelayedMail[]): RelayedMail[] =>
	[...held].map((mail) => ({
		to: Array.isArray(mail.to) ? [...mail.to] : mail.to,
		content: mail.content,
	}));

/** The cases of the `MailSender` contract over the senders `input` builds. */
export function mailSenderContract(input: MailSenderContractInput): readonly ContractCase[] {
	/**
	 * Sends `mail` over a relay that accepts: answered delivered, and the
	 * relay, compared whole, holding what it held and one mail more, its
	 * envelope to the recipient alone, carrying the code.
	 */
	const deliver = async (
		sender: MailSender,
		relayed: () => Promise<readonly RelayedMail[]>,
		mail: MailSend,
	) => {
		const before = copied(await relayed());
		const answer = await answerOf(sender.send(mail), "a send the relay accepted");
		assert.equal(
			mailSendOutcome(answer),
			"delivered",
			`a send the relay accepted answered ${JSON.stringify(answer)}, which the provider reads as ${mailSendOutcome(answer)}`,
		);
		const after = copied(await relayed());
		assert.equal(
			after.length,
			before.length + 1,
			`the relay holds ${after.length - before.length} new mails, not one`,
		);
		assert.deepEqual(after.slice(0, before.length), before, "the send changed what the relay held");
		const added = after[before.length];
		assert.deepEqual(
			added?.to,
			[mail.to],
			`the relay's new mail is addressed to ${JSON.stringify(added?.to)}, not to the recipient alone`,
		);
		assert.ok(
			added?.content.includes(mail.code) === true,
			"the relay's new mail does not carry the code",
		);
	};

	return [
		{
			name: "kind is a non-empty string",
			run: async () => {
				const { kind } = input.build().sender;
				assert.ok(
					typeof kind === "string" && kind.length > 0,
					`kind ${String(kind)} names nothing`,
				);
			},
		},
		{
			name: "a send the relay accepts answers delivered, and the relay then holds one more mail, to the recipient alone, carrying the code, and nothing else new",
			run: async () => {
				const { sender, relayed } = input.build();
				await deliver(sender, relayed, mailOf(1));
			},
		},
		{
			name: "a send of every purpose answers delivered, each relayed alone with its code",
			run: async () => {
				const { sender, relayed } = input.build();
				for (const [index, purpose] of MAIL_PURPOSES.entries()) {
					await deliver(sender, relayed, mailOf(2 + index, purpose));
				}
			},
		},
		{
			name: "a relay refusing at a limit is answered refused_at_limit, and nothing of the mail or of the relay's reply",
			run: async () => {
				const mail = mailOf(8);
				const sender = input.refusing("limit", replyTo("limit", mail));
				const answer = await answerOf(sender.send(mail), "a send refused at a limit");
				assert.equal(
					mailSendOutcome(answer),
					"refused_at_limit",
					`a send refused at a limit answered ${JSON.stringify(answer)}, which the provider reads as ${mailSendOutcome(answer)}`,
				);
			},
		},
		...(
			[
				"recipient_refused",
				"message_refused",
				"unreachable",
				"auth_failed",
				"temporary_failure",
			] as const
		).map(
			(refusal, index): ContractCase => ({
				name: `a relay that ${REFUSAL_TEXT[refusal]}: send rejects, and the rejection's projection carries nothing of the mail or of the relay's reply`,
				run: async () => {
					const mail = mailOf(10 + index);
					const error = await rejectionOf(
						input.refusing(refusal, replyTo(refusal, mail)).send(mail),
					);
					// What a log line carries of it: its message, and its causes'.
					const written = normalised(JSON.stringify(loggableError(error)));
					for (const text of neverLogged(mail)) {
						assert.ok(
							!written.includes(text),
							"the rejection carries part of the mail or of the relay's reply, which the log line it reaches would then hold",
						);
					}
				},
			}),
		),
		{
			name: "send leaves the mail it is handed as it was",
			run: async () => {
				const { sender } = input.build();
				const mail = mailOf(20);
				// Frozen: a sender that writes to it throws here, in strict mode.
				await answerOf(sender.send(mail), "a send the relay accepted");
				assert.deepEqual(mail, mailOf(20), "send changed the mail it was handed");
			},
		},
	];
}
