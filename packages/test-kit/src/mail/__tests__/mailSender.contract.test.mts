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
 * The conformance suite of a `MailSender`, over core's recording sender
 * standing in for one whose relay accepts, refuses at a limit or fails; each
 * way a sender can break the contract fails the case that names it.
 */

import type { MailSend, MailSender } from "@o3co/auth-provider-core";
import { createRecordingMailSender } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import {
	MAIL_RELAY_REFUSALS,
	type MailRelayRefusal,
	type MailSenderContractInput,
	mailSenderContract,
} from "#/index.mjs";

const RULES = {
	kind: "kind is a non-empty string",
	delivered:
		"a send the relay accepts answers delivered, and the relay then holds one more mail, to the recipient, carrying the code, and nothing else new",
	purposes: "a send of every purpose answers delivered, each relayed alone with its code",
	limit:
		"a relay refusing at a limit is answered refused_at_limit, and nothing of the mail or of the relay's reply",
	recipient_refused:
		"a relay that refuses the recipient: send rejects, and the rejection's projection carries nothing of the mail or of the relay's reply",
	message_refused:
		"a relay that refuses the message: send rejects, and the rejection's projection carries nothing of the mail or of the relay's reply",
	unreachable:
		"a relay that cannot be reached: send rejects, and the rejection's projection carries nothing of the mail or of the relay's reply",
	auth_failed:
		"a relay that refuses the sender's credentials: send rejects, and the rejection's projection carries nothing of the mail or of the relay's reply",
	temporary_failure:
		"a relay that fails for now: send rejects, and the rejection's projection carries nothing of the mail or of the relay's reply",
	unchanged: "send leaves the mail it is handed as it was",
} as const;

/** A relay the recording sender stands in for: what it holds is what the sender delivered. */
const relayOf = (sender: ReturnType<typeof createRecordingMailSender>) => async () =>
	sender.sent.map((mail) => ({ to: mail.to, content: `${mail.purpose} ${mail.code}` }));

/** The cases of the refusals a sender answers by rejecting. */
const OUTAGES = [
	RULES.recipient_refused,
	RULES.message_refused,
	RULES.unreachable,
	RULES.auth_failed,
	RULES.temporary_failure,
];

/** The recording sender as a conforming sender over each relay the suite asks for. */
const conforming: MailSenderContractInput = {
	build: () => {
		const sender = createRecordingMailSender();
		return { sender, relayed: relayOf(sender) };
	},
	refusing: (refusal) => {
		const sender = createRecordingMailSender();
		if (refusal === "limit") sender.refuseAtLimit();
		else sender.failWith(new Error(`the relay refused: ${refusal}`));
		return sender;
	},
};

/** `input` with each sender it builds changed by `change`. */
const changed = (
	change: (sender: MailSender, refusal: MailRelayRefusal | undefined, reply: string) => MailSender,
	input: MailSenderContractInput = conforming,
): MailSenderContractInput => ({
	build: () => {
		const built = input.build();
		return { sender: change(built.sender, undefined, ""), relayed: built.relayed };
	},
	refusing: (refusal, reply) => change(input.refusing(refusal, reply), refusal, reply),
});

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

/** A sender that sends through `sender` and, on a refusal, rejects with `error` of the mail and the reply. */
const rejectingWith =
	(error: (mail: MailSend, reply: string) => unknown, only?: MailRelayRefusal) =>
	(sender: MailSender, refusal: MailRelayRefusal | undefined, reply: string): MailSender =>
		refusal === undefined || refusal === "limit" || (only !== undefined && refusal !== only)
			? sender
			: {
					kind: sender.kind,
					send: async (mail) => {
						throw error(mail, reply);
					},
				};

describe("mailSenderContract", () => {
	it("names every rule it holds a sender to, one refusal case per way a relay refuses", () => {
		expect(MAIL_RELAY_REFUSALS).toEqual([
			"recipient_refused",
			"message_refused",
			"unreachable",
			"auth_failed",
			"temporary_failure",
			"limit",
		]);
		expect(mailSenderContract(conforming).map((c) => c.name)).toEqual(Object.values(RULES));
	});

	it("passes a sender that delivers, answers a limit, and rejects with nothing of the mail", async () => {
		expect(await failing(conforming)).toEqual([]);
	});

	it("hands every refusing relay a reply the suite writes, the recipient's refusal naming the recipient", async () => {
		const replies = new Map<MailRelayRefusal, string>();
		await failing({
			...conforming,
			refusing: (refusal, reply) => {
				replies.set(refusal, reply);
				return conforming.refusing(refusal, reply);
			},
		});
		expect([...replies.keys()].sort()).toEqual([...MAIL_RELAY_REFUSALS].sort());
		for (const reply of replies.values()) expect(reply).not.toBe("");
		expect(replies.get("recipient_refused")).toMatch(/^550 .*@example\.com/);
	});

	it("fails a kind that names nothing", async () => {
		expect(await failing(changed((sender) => ({ ...sender, kind: "" })))).toEqual([RULES.kind]);
	});

	it("fails a sender that resolves with anything but delivered for a mail the relay accepted", async () => {
		const answering = (answer: unknown) =>
			changed((sender, refusal) =>
				refusal === undefined
					? {
							kind: sender.kind,
							send: async (mail) => {
								await sender.send(mail);
								return answer as never;
							},
						}
					: sender,
			);
		for (const answer of [undefined, true, { outcome: "sent" }, { ok: true }]) {
			expect(await failing(answering(answer)), JSON.stringify(answer)).toEqual([
				RULES.delivered,
				RULES.purposes,
			]);
		}
	});

	it("fails a sender that answers delivered with the relay holding nothing, or no code, or the mail to another recipient", async () => {
		const relaying = (relayed: (mail: MailSend) => { to: string; content: string }[]) => {
			let held: { to: string; content: string }[] = [];
			return {
				build: () => ({
					sender: {
						kind: "test",
						send: async (mail: MailSend) => {
							held = [...held, ...relayed(mail)];
							return { outcome: "delivered" } as const;
						},
					},
					relayed: async () => held,
				}),
				refusing: conforming.refusing,
			} satisfies MailSenderContractInput;
		};
		expect(await failing(relaying(() => []))).toEqual([RULES.delivered, RULES.purposes]);
		expect(await failing(relaying((mail) => [{ to: mail.to, content: "your code" }]))).toEqual([
			RULES.delivered,
			RULES.purposes,
		]);
		expect(
			await failing(relaying((mail) => [{ to: "someone@example.com", content: mail.code }])),
		).toEqual([RULES.delivered, RULES.purposes]);
		expect(
			await failing(
				relaying((mail) => [
					{ to: mail.to, content: mail.code },
					{ to: mail.to, content: mail.code },
				]),
			),
		).toEqual([RULES.delivered, RULES.purposes]);
	});

	it("fails a sender that cannot send a purpose of the closed list", async () => {
		expect(
			await failing(
				changed((sender) => ({
					kind: sender.kind,
					send: async (mail) => {
						if (mail.purpose === "account_email_proof") throw new Error("no template");
						return sender.send(mail);
					},
				})),
			),
		).toEqual([RULES.purposes]);
	});

	it("fails a limit answered as an outage, or answered with more than the outcome", async () => {
		const atLimit = (answer: (reply: string) => Promise<unknown>) =>
			changed((sender, refusal, reply) =>
				refusal === "limit" ? { kind: sender.kind, send: () => answer(reply) as never } : sender,
			);
		expect(
			await failing(
				atLimit(async () => {
					throw new Error("rate limited");
				}),
			),
		).toEqual([RULES.limit]);
		expect(
			await failing(atLimit(async (reply) => ({ outcome: "refused_at_limit", reply }))),
		).toEqual([RULES.limit]);
		expect(await failing(atLimit(async () => ({ outcome: "delivered" })))).toEqual([RULES.limit]);
	});

	it("fails an outage answered as sent, or as a limit", async () => {
		for (const answer of [{ outcome: "delivered" }, { outcome: "refused_at_limit" }, undefined]) {
			expect(
				await failing(
					changed((sender, refusal) =>
						refusal === undefined || refusal === "limit"
							? sender
							: { kind: sender.kind, send: async () => answer as never },
					),
				),
				JSON.stringify(answer),
			).toEqual(OUTAGES);
		}
	});

	it("fails a rejection whose message carries the code, the recipient, its local part or the account", async () => {
		for (const leak of [
			(mail: MailSend) => `relay refused ${mail.code}`,
			(mail: MailSend) => `550 <${mail.to}> unknown`,
			(mail: MailSend) => `mailbox ${mail.to.split("@")[0]} is full`,
			(mail: MailSend) => `for ${encodeURIComponent(mail.to)}`,
			(mail: MailSend) => `subject ${mail.subject} refused`,
		]) {
			expect(
				await failing(changed(rejectingWith((mail) => new Error(leak(mail))))),
				leak.toString(),
			).toEqual(OUTAGES);
		}
	});

	it("fails a rejection whose cause carries the relay's reply, under the one refusal it happens for", async () => {
		for (const refusal of MAIL_RELAY_REFUSALS.filter((r) => r !== "limit")) {
			expect(
				await failing(
					changed(
						rejectingWith(
							(_mail, reply) =>
								new Error("the relay refused the mail", { cause: new Error(reply) }),
							refusal,
						),
					),
				),
				refusal,
			).toEqual([RULES[refusal]]);
		}
	});

	it("fails a sender that changes the mail it is handed", async () => {
		expect(
			await failing(
				changed((sender) => ({
					kind: sender.kind,
					send: async (mail) => {
						(mail as { to: string }).to = mail.to.toLowerCase();
						return sender.send(mail);
					},
				})),
			),
		).toContain(RULES.unchanged);
	});

	it("fails a rejection carrying the mail in another case, split by punctuation, or in base64", async () => {
		for (const leak of [
			(mail: MailSend) => `Recipient ${mail.to.toUpperCase()} refused`,
			(mail: MailSend) => `code ${mail.code.toUpperCase().split("").join("-")}`,
			(mail: MailSend) => `payload ${Buffer.from(mail.to).toString("base64")}`,
			(mail: MailSend) => `payload ${Buffer.from(mail.code).toString("base64url")}`,
		]) {
			expect(
				await failing(changed(rejectingWith((mail) => new Error(leak(mail))))),
				leak.toString(),
			).toEqual(OUTAGES);
		}
	});

	it("fails a sender that also delivers the mail to another mailbox, or relays a second mail", async () => {
		const relaying = (extra: (mail: MailSend) => { to: string; content: string }[]) => {
			let held: { to: string; content: string }[] = [];
			return {
				build: () => ({
					sender: {
						kind: "test",
						send: async (mail: MailSend) => {
							held = [...held, { to: mail.to, content: mail.code }, ...extra(mail)];
							return { outcome: "delivered" } as const;
						},
					},
					relayed: async () => held,
				}),
				refusing: conforming.refusing,
			} satisfies MailSenderContractInput;
		};
		for (const extra of [
			(mail: MailSend) => [{ to: "debug@example.com", content: mail.code }],
			(mail: MailSend) => [{ to: mail.to, content: "a second mail" }],
		]) {
			expect(await failing(relaying(extra)), extra.toString()).toEqual([
				RULES.delivered,
				RULES.purposes,
			]);
		}
	});

	it("fails a transient failure answered as a limit: a relay that fails for now is an outage", async () => {
		expect(
			await failing(
				changed((sender, refusal) =>
					refusal === "temporary_failure"
						? { kind: sender.kind, send: async () => ({ outcome: "refused_at_limit" }) as const }
						: sender,
				),
			),
		).toEqual([RULES.temporary_failure]);
	});
});
