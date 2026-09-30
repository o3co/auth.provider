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
 * accepted the message, which the relay then holds as sent; a relay that
 * refuses answered by a rejection, never as sent; a rejection whose
 * `loggableError` projection — its message and its causes' — names no
 * recipient and quotes no subject or text, since the coordinator logs it;
 * and the message handed to `send` left as it was. The double is
 * `createRecordingMailSender`. Published on
 * `@o3co/auth-provider-core/testing`; moves to the test-kit package with the
 * other contract suites.
 */

import assert from "node:assert/strict";
import { loggableError } from "../../logging/loggableError.mjs";
import type { MailMessage, MailSender } from "../../mail/types.mjs";
import type { ContractCase } from "../../session-admission/testing/requirement.contract.mjs";

export interface MailSenderContractInput {
	/** A fresh sender over a relay that accepts, and what that relay has received, oldest first. */
	readonly build: () => {
		readonly sender: MailSender;
		readonly received: () => Promise<readonly MailMessage[]>;
	};
	/** A sender over a relay that refuses the message or cannot be reached. */
	readonly failing: () => MailSender;
}

/** Text no relay, library or transport writes by chance: found in an error only when copied from the message. */
const MARK = "c0ntract-7f3a";

/** A message whose recipient, subject and text are each found by its own mark. */
const message = (serial: number): MailMessage =>
	Object.freeze({
		to: `recipient-${MARK}-${serial}@example.com`,
		subject: `Subject ${MARK}-s${serial}`,
		text: `Text ${MARK}-t${serial}\nYour code is 1234 5678.`,
	});

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
		{
			name: "send over a relay that refuses rejects, and never resolves",
			run: async () => {
				await rejectionOf(input.failing().send(message(2)));
			},
		},
		{
			name: "a rejection names no recipient and quotes nothing of the message",
			run: async () => {
				const sent = message(3);
				const error = await rejectionOf(input.failing().send(sent));
				// What the coordinator's log line carries of it: its message, and its causes'.
				const written = JSON.stringify(loggableError(error));
				for (const [part, value] of [
					["recipient", sent.to],
					["subject", sent.subject],
					["text", sent.text.split("\n")[0] as string],
				] as const) {
					assert.ok(
						!written.includes(value),
						`the rejection carries the message's ${part}, which the log line it reaches would then hold`,
					);
				}
			},
		},
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
