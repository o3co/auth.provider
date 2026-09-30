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
 * The contract suite of the `MailSender` port, the `mailSender` slot's value.
 *
 * `mailSenderContract(input)` holds a sender to what the MFA coordinator
 * relies on: a `kind` that names it; `send` resolving only once the relay
 * accepted the message, which the relay then holds as sent; the message
 * handed to `send` left as it was; and, under each way a relay refuses
 * (`MAIL_REFUSALS`: the recipient refused, the message refused, the relay
 * unreachable, the credentials refused), a rejection — never "sent" — whose
 * `loggableError` projection, its message and its causes', carries no part
 * of the message and none of the relay's reply, which the suite writes.
 * Every part of the message, the code line among them, starts with one mark,
 * and the projection must not carry the mark anywhere.
 *
 * What it cannot see, and a sender's own tests must: what the sender logs
 * itself (a transport's debug transcript); an error's properties outside
 * the projection; a quote cut to fewer characters than the mark. The double
 * is `createRecordingMailSender`. Published on
 * `@o3co/auth-provider-core/testing`; moves to the test-kit package with the
 * other contract suites.
 */

import assert from "node:assert/strict";
import { loggableError } from "../../logging/loggableError.mjs";
import type { MailMessage, MailSender } from "../../mail/types.mjs";
import type { ContractCase } from "../../session-admission/testing/requirement.contract.mjs";

/** The ways a relay refuses a message, each a case of the suite. */
export const MAIL_REFUSALS = Object.freeze([
	"recipient_refused",
	"message_refused",
	"unreachable",
	"auth_failed",
] as const);

/** A way a relay refuses a message: see {@link MAIL_REFUSALS}. */
export type MailRefusal = (typeof MAIL_REFUSALS)[number];

export interface MailSenderContractInput {
	/** A fresh sender over a relay that accepts, and what that relay has received, oldest first. */
	readonly build: () => {
		readonly sender: MailSender;
		readonly received: () => Promise<readonly MailMessage[]>;
	};
	/**
	 * A sender over a relay that refuses as `refusal` names, answering `reply`
	 * as its own text wherever the refusal carries one (a status line after
	 * `RCPT TO`, say); an unreachable relay answers nothing.
	 */
	readonly refusing: (refusal: MailRefusal, reply: string) => MailSender;
}

/**
 * Text no relay, library or transport writes by chance, at the start of
 * every part of the message and in the relay's reply: found in a projection
 * only when copied from one of them.
 */
const MARK = "zq7kx3";

/** A message each of whose parts starts with the mark: the recipient, the subject and each line of the text, the code's among them. */
const message = (serial: number): MailMessage =>
	Object.freeze({
		to: `${MARK}r${serial}@example.com`,
		subject: `${MARK}s${serial} Your sign-in code`,
		text: `${MARK}t${serial} Your sign-in code follows.\n${MARK}c${serial} Your code is 1234 5678.`,
	});

/** What the relay answers, as the suite writes it: a status line echoing the recipient, under the mark. */
const replyTo = (sent: MailMessage): string =>
	`550 5.1.1 <${sent.to}>: ${MARK} recipient address rejected`;

/** What each refusal is called in its case's name. */
const REFUSAL_TEXT: Readonly<Record<MailRefusal, string>> = {
	recipient_refused: "refuses the recipient",
	message_refused: "refuses the message",
	unreachable: "cannot be reached",
	auth_failed: "refuses the sender's credentials",
};

/** Text as a relay may hand it back: line breaks as `\n`, no trailing whitespace. */
const normalised = (text: string): string => text.replace(/\r\n/g, "\n").trimEnd();

/** The rejection of `sending`, or a failure saying it resolved. */
async function rejectionOf(sending: Promise<void>): Promise<unknown> {
	try {
		await sending;
	} catch (error) {
		return error;
	}
	assert.fail(
		"send over a refusing relay resolved: a delivery that did not happen was answered as sent",
	);
}

/** The cases of the `MailSender` contract over the senders `input` builds. */
export function mailSenderContract(input: MailSenderContractInput): readonly ContractCase[] {
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
			name: "send resolves once the relay accepted the message, and the relay holds that recipient, subject and text",
			run: async () => {
				const { sender, received } = input.build();
				const sent = message(1);
				await sender.send(sent);
				const found = (await received()).find(
					(m) => m.to === sent.to && m.subject === sent.subject,
				);
				assert.ok(found, `the relay holds no message to ${sent.to} after send resolved`);
				assert.equal(
					normalised(found.text),
					normalised(sent.text),
					"the relay holds another text than the one sent",
				);
			},
		},
		...MAIL_REFUSALS.map(
			(refusal, index): ContractCase => ({
				name: `a relay that ${REFUSAL_TEXT[refusal]}: send rejects, never resolves, and the rejection's projection carries nothing of the message or of the relay's reply`,
				run: async () => {
					const sent = message(10 + index);
					const error = await rejectionOf(input.refusing(refusal, replyTo(sent)).send(sent));
					// What the coordinator's log line carries of it: its message, and its causes'.
					const written = JSON.stringify(loggableError(error));
					assert.ok(
						!written.includes(MARK),
						"the rejection carries part of the message or of the relay's reply, which the log line it reaches would then hold",
					);
				},
			}),
		),
		{
			name: "send leaves the message it is handed as it was",
			run: async () => {
				const { sender } = input.build();
				const sent = message(4);
				// Frozen: a sender that writes to it throws here, in strict mode.
				await sender.send(sent);
				assert.deepEqual(sent, message(4), "send changed the message it was handed");
			},
		},
	];
}
