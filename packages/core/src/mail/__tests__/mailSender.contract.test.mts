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
 * each way a sender can break the contract fails the case that names it.
 */

import { describe, expect, it } from "vitest";
import type { MailMessage, MailSender } from "#/mail/types.mjs";
import {
	createRecordingMailSender,
	type MailSenderContractInput,
	mailSenderContract,
} from "#/testing/index.mjs";

const RULES = {
	kind: "kind is a non-empty string",
	delivered:
		"send resolves once the relay accepted the message, and the relay holds that recipient, subject and text",
	refused: "send over a relay that refuses rejects, and never resolves",
	quiet: "a rejection names no recipient and quotes nothing of the message",
	untouched: "send leaves the message it is handed as it was",
} as const;

/** The recording double: what it accepted is what its relay received. */
const recording: MailSenderContractInput = {
	build: () => {
		const sender = createRecordingMailSender();
		return { sender, received: async () => sender.sent };
	},
	failing: () => {
		const sender = createRecordingMailSender();
		sender.failWith(new Error("relay unreachable"));
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

	it("fails a sender that answers a refusing relay as sent", async () => {
		expect(
			await failing({
				...recording,
				failing: () => ({ kind: "optimistic", send: async () => {} }),
			}),
		).toEqual([RULES.refused, RULES.quiet]);
	});

	it("fails a sender whose rejection quotes the recipient, the subject or the text", async () => {
		for (const quote of [
			(m: MailMessage) => `could not deliver to ${m.to}`,
			(m: MailMessage) => `relay refused "${m.subject}"`,
			(m: MailMessage) => `rejected body: ${m.text}`,
		]) {
			expect(
				await failing({
					...recording,
					failing: () => ({
						kind: "talkative",
						send: async (message) => {
							throw new Error(quote(message));
						},
					}),
				}),
			).toEqual([RULES.quiet]);
		}
	});

	it("fails a sender whose rejection carries the recipient in a cause", async () => {
		expect(
			await failing({
				...recording,
				failing: () => ({
					kind: "wrapped",
					send: async (message) => {
						throw new Error("delivery failed", { cause: new Error(`550 ${message.to}`) });
					},
				}),
			}),
		).toEqual([RULES.quiet]);
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
