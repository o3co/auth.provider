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
 * The `MailSender` port's contract suite, run against the recording double;
 * each way a sender can break the contract fails the case that names it,
 * under each way a relay can refuse.
 */

import { describe, expect, it } from "vitest";
import type { MailMessage, MailSender } from "#/mail/types.mjs";
import {
	createRecordingMailSender,
	MAIL_REFUSALS,
	type MailRefusal,
	type MailSenderContractInput,
	mailSenderContract,
} from "#/testing/index.mjs";

const REFUSED: Readonly<Record<MailRefusal, string>> = {
	recipient_refused:
		"a relay that refuses the recipient: send rejects, never resolves, and the rejection's projection carries nothing of the message or of the relay's reply",
	message_refused:
		"a relay that refuses the message: send rejects, never resolves, and the rejection's projection carries nothing of the message or of the relay's reply",
	unreachable:
		"a relay that cannot be reached: send rejects, never resolves, and the rejection's projection carries nothing of the message or of the relay's reply",
	auth_failed:
		"a relay that refuses the sender's credentials: send rejects, never resolves, and the rejection's projection carries nothing of the message or of the relay's reply",
};

const RULES = {
	kind: "kind is a non-empty string",
	delivered:
		"send resolves once the relay accepted the message, and the relay holds that recipient, subject and text",
	untouched: "send leaves the message it is handed as it was",
} as const;

const ALL_REFUSALS = Object.values(REFUSED);

/** The recording double: what it accepted is what its relay received; a refusal names only its kind. */
const recording: MailSenderContractInput = {
	build: () => {
		const sender = createRecordingMailSender();
		return { sender, received: async () => sender.sent };
	},
	refusing: (refusal) => {
		const sender = createRecordingMailSender();
		sender.failWith(new Error(`relay ${refusal}`));
		return sender;
	},
};

/** The names of the cases the senders `input` builds fail. */
const failing = async (input: MailSenderContractInput): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of mailSenderContract(input)) {
		try {
			await run();
		} catch {
			failed.push(name);
		}
	}
	return failed;
};

/** A sender over a refusing relay that rejects with the error `leak` makes of the message and the relay's reply. */
const leaking =
	(leak: (message: MailMessage, reply: string, refusal: MailRefusal) => unknown) =>
	(refusal: MailRefusal, reply: string): MailSender => ({
		kind: "leaking",
		send: async (message) => {
			throw leak(message, reply, refusal);
		},
	});

/** A sender that accepts every message into `into` after `mutate` runs on it. */
const accepting = (
	into: MailMessage[],
	extra: Partial<MailSender> = {},
	mutate: (message: MailMessage) => void = () => {},
): MailSender => ({
	kind: "accepting",
	send: async (message) => {
		mutate(message);
		into.push({ ...message });
	},
	...extra,
});

describe("mailSenderContract", () => {
	it("names every rule it holds a sender to, one case per way a relay refuses", () => {
		expect(mailSenderContract(recording).map((c) => c.name)).toEqual([
			RULES.kind,
			RULES.delivered,
			...MAIL_REFUSALS.map((refusal) => REFUSED[refusal]),
			RULES.untouched,
		]);
	});

	it("passes the recording double", async () => {
		expect(await failing(recording)).toEqual([]);
	});

	it("fails a sender with no kind", async () => {
		expect(
			await failing({
				...recording,
				build: () => {
					const into: MailMessage[] = [];
					return { sender: accepting(into, { kind: "" }), received: async () => into };
				},
			}),
		).toEqual([RULES.kind]);
	});

	it("fails a sender that resolves without the relay holding the message", async () => {
		expect(
			await failing({
				...recording,
				build: () => ({
					sender: { kind: "lost", send: async () => {} },
					received: async () => [],
				}),
			}),
		).toEqual([RULES.delivered]);
	});

	it("fails a sender that answers a refusing relay as sent, under every refusal", async () => {
		expect(
			await failing({
				...recording,
				refusing: () => ({ kind: "optimistic", send: async () => {} }),
			}),
		).toEqual(ALL_REFUSALS);
	});

	it("fails a sender whose rejection carries any part of the message: the recipient, its local part, the recipient encoded, the subject, the code line", async () => {
		for (const leak of [
			(m: MailMessage) => new Error(`550 5.1.1 <${m.to}>: Recipient address rejected`),
			(m: MailMessage) => new Error(`550 mailbox ${m.to.split("@")[0]} unavailable`),
			(m: MailMessage) => new Error(`550 rcpt=${encodeURIComponent(m.to)}`),
			(m: MailMessage) => new Error(`relay refused "${m.subject}"`),
			(m: MailMessage) => new Error(`552 message refused near: ${m.text.split("\n").at(-1)}`),
		]) {
			expect(await failing({ ...recording, refusing: leaking(leak) })).toEqual(ALL_REFUSALS);
		}
	});

	it("fails a sender whose rejection quotes the relay's reply", async () => {
		expect(
			await failing({
				...recording,
				refusing: leaking((_m, reply) => new Error(`delivery failed: ${reply}`)),
			}),
		).toEqual(ALL_REFUSALS);
	});

	it("fails a sender whose rejection carries the recipient in a cause, or past most of the projection's length", async () => {
		for (const leak of [
			(m: MailMessage) => new Error("delivery failed", { cause: new Error(`550 ${m.to}`) }),
			(m: MailMessage) => new Error(`${"x".repeat(240)} ${m.to}`),
		]) {
			expect(await failing({ ...recording, refusing: leaking(leak) })).toEqual(ALL_REFUSALS);
		}
	});

	it("fails a sender that stays quiet on one refusal and leaks on another, on that one alone", async () => {
		expect(
			await failing({
				...recording,
				refusing: leaking((m, _reply, refusal) =>
					refusal === "recipient_refused"
						? new Error(`Can't send mail - all recipients were rejected: 550 <${m.to}>`)
						: new Error("connect ECONNREFUSED 192.0.2.5:587"),
				),
			}),
		).toEqual([REFUSED.recipient_refused]);
	});

	it("fails a sender that changes the message it is handed", async () => {
		expect(
			await failing({
				...recording,
				build: () => {
					const into: MailMessage[] = [];
					const sender = accepting(into, {}, (message) => {
						(message as { subject: string }).subject = "[relayed] subject";
					});
					return { sender, received: async () => into };
				},
			}),
		).toContain(RULES.untouched);
	});
});
