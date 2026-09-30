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
 * What an SMTP exchange that failed comes to: a reply to the sender, the
 * recipient or the message that means a sending limit is answered
 * `refused_at_limit`; every other failure is a `MailTransportError` whose
 * reason is one of a closed set, built from the reply's codes alone, never
 * from its text or the transport's.
 */

import { constants } from "node:os";
import { loggableError } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { MailTransportError, readSendFailure } from "#/mail/smtp/failure.mjs";

/** A failure as the SMTP transport reports one: its code, the command it was at, and the relay's reply. */
const failure = (code: string, command?: string, response?: string): Error & { code: string } =>
	Object.assign(new Error(`transport text zq7kx3 ${response ?? ""}`), {
		code,
		...(command === undefined ? {} : { command }),
		...(response === undefined ? {} : { response, responseCode: Number(response.slice(0, 3)) }),
	});

/** What `readSendFailure` answers for a reply at `command`: the limit, or the error's reason. */
const answerTo = (command: string, response: string): string => {
	const read = readSendFailure(
		failure(
			command === "RCPT TO" || command === "MAIL FROM" ? "EENVELOPE" : "EMESSAGE",
			command,
			response,
		),
	);
	return read === "refused_at_limit" ? read : read.reason;
};

describe("readSendFailure: the relay's reply, as the provider answers it", () => {
	it("answers refused_at_limit for a transient reply to the sender, the recipient or the message whose enhanced code means a limit", () => {
		for (const command of ["MAIL FROM", "RCPT TO", "DATA"]) {
			for (const code of [421, 450, 451, 452]) {
				for (const enhanced of ["4.7.1", "4.7.28", "4.5.3"]) {
					const reply = `${code} ${enhanced} zq7kx3 slow down`;
					expect(answerTo(command, reply), `${command} ${reply}`).toBe("refused_at_limit");
				}
			}
		}
		expect(answerTo("RCPT TO", "451-4.7.1 first line\n451 4.7.1 second line")).toBe(
			"refused_at_limit",
		);
	});

	it("rejects every other reply: a transient one whose enhanced code says no limit, one without an enhanced code, and every permanent one", () => {
		for (const reply of [
			"421 4.3.2 service not available",
			"451 4.3.0 temporary system problem",
			"451 4.7.0 temporary server error",
			"450 4.2.1 mailbox busy",
			"452 4.2.2 mailbox full",
			"451 4.4.5 mail system congestion",
			"454 4.7.1 relay access denied for now",
			"451 rate limited, no enhanced code",
			"451 4.7.1rate limited, no space after the code",
			"452 5.5.3 an enhanced class that is not the reply's",
			"550 5.1.1 recipient unknown",
			"550 5.4.5 daily sending quota exceeded",
			"554 5.7.1 message refused",
			"552 5.3.4 message too big",
		]) {
			expect(answerTo("RCPT TO", reply), reply).toBe("rejected");
		}
	});

	it("never reads a reply at the connection, the greeting, EHLO, STARTTLS or AUTH as a limit", () => {
		for (const command of ["CONN", "EHLO", "HELO", "STARTTLS", "AUTH PLAIN", "API", undefined]) {
			const read = readSendFailure(failure("EPROTOCOL", command, "451 4.7.1 zq7kx3 slow down"));
			expect(read, String(command)).toBeInstanceOf(MailTransportError);
		}
	});

	it("reads each failure's reason from the transport's code and the command it was at", () => {
		const reasons: [Error & { code: string }, string][] = [
			[failure("EAUTH", "AUTH PLAIN", "535 5.7.8 zq7kx3 credentials invalid"), "auth_failed"],
			[
				failure("EAUTH", "AUTH PLAIN", "454 4.7.0 zq7kx3 temporary authentication failure"),
				"auth_failed",
			],
			[failure("ETIMEDOUT", "CONN"), "timeout"],
			[failure("ETLS", "STARTTLS", "454 4.7.0 zq7kx3 TLS not available"), "unreachable"],
			[failure("ECONNECTION", "EHLO", "421 4.3.2 zq7kx3 closing"), "unreachable"],
			[failure("EPROTOCOL", "CONN", "554 5.3.2 zq7kx3 no service"), "unreachable"],
			[failure("ESOCKET", "CONN"), "unreachable"],
			[failure("EDNS", "CONN"), "unreachable"],
			[failure("EENVELOPE", "MAIL FROM", "553 5.7.1 zq7kx3 sender refused"), "rejected"],
			[failure("EENVELOPE", "RCPT TO", "550 5.1.1 <zq7kx3@example.com> unknown"), "rejected"],
			[failure("EENVELOPE", "DATA", "554 5.5.1 zq7kx3 no valid recipients"), "rejected"],
			[failure("EMESSAGE", "DATA", "554 5.7.1 zq7kx3 content refused"), "rejected"],
			[failure("ESOMETHINGNEW", "RCPT TO"), "unreachable"],
		];
		for (const [given, reason] of reasons) {
			const read = readSendFailure(given);
			expect(read, given.code).toBeInstanceOf(MailTransportError);
			expect((read as MailTransportError).reason, given.code).toBe(reason);
		}
		for (const given of [undefined, null, "zq7kx3", 42, {}, new Error("zq7kx3")]) {
			expect((readSendFailure(given) as MailTransportError).reason, String(given)).toBe(
				"unreachable",
			);
		}
	});

	it("keeps of a reply its code and enhanced code, and nothing of its text, the transport's text or the failure itself", () => {
		const given = failure(
			"EENVELOPE",
			"RCPT TO",
			"550 5.1.1 <zq7kx3r1@example.com>: zq7kx3 rejected",
		);
		const read = readSendFailure(given) as MailTransportError;
		expect(read).toBeInstanceOf(MailTransportError);
		expect(read.name).toBe("MailTransportError");
		expect(read.replyCode).toBe(550);
		expect(read.enhancedCode).toBe("5.1.1");
		expect(read.message).toBe(
			"standard-smtp-mail-sender: the relay refused the recipient (SMTP 550 5.1.1)",
		);
		expect(read.cause).toBeUndefined();
		expect(Object.keys(read).sort()).toEqual([
			"code",
			"enhancedCode",
			"name",
			"reason",
			"replyCode",
		]);
		for (const text of [read.message, read.stack ?? "", JSON.stringify(loggableError(read))]) {
			expect(text.toLowerCase()).not.toContain("zq7kx3");
			expect(text).not.toContain("transport text");
		}
	});

	it("names the stage a reply refused, with the reply's codes", () => {
		const message = (command: string, response: string): string =>
			(readSendFailure(failure("EENVELOPE", command, response)) as MailTransportError).message;
		expect(message("MAIL FROM", "553 5.7.1 x")).toBe(
			"standard-smtp-mail-sender: the relay refused the sender (SMTP 553 5.7.1)",
		);
		expect(message("DATA", "554 x")).toBe(
			"standard-smtp-mail-sender: the relay refused the message (SMTP 554)",
		);
		expect(message("RCPT TO", "421 4.3.2 x")).toBe(
			"standard-smtp-mail-sender: the relay refused the recipient (SMTP 421 4.3.2)",
		);
	});
	it("says a failure could not be secured where STARTTLS was refused, or the connection was being secured when it failed", () => {
		const refused = readSendFailure(failure("ETLS", "STARTTLS", "454 4.7.0 zq7kx3 no TLS"));
		const whileSecuring = readSendFailure(failure("ESOCKET", "CONN"), true);
		const plain = readSendFailure(failure("ESOCKET", "CONN"), false);
		expect((refused as MailTransportError).message).toContain("could not be secured");
		expect((whileSecuring as MailTransportError).message).toContain("could not be secured");
		expect((whileSecuring as MailTransportError).reason).toBe("unreachable");
		expect((plain as MailTransportError).message).not.toContain("could not be secured");
	});

	it("keeps the system error code of a socket failure where it is one an operator acts on, and none other", () => {
		const socketFailure = (name: keyof typeof constants.errno): Error =>
			Object.assign(failure("ESOCKET", "CONN"), { errno: -constants.errno[name] });
		const reset = readSendFailure(socketFailure("ECONNRESET")) as MailTransportError;
		expect(reset.code).toBe("ECONNRESET");
		expect(reset.message).toMatch(/\(ECONNRESET\)$/);
		expect((readSendFailure(socketFailure("EPIPE")) as MailTransportError).code).toBeUndefined();
		expect(
			(readSendFailure(failure("EENVELOPE", "RCPT TO", "550 5.1.1 x")) as MailTransportError).code,
		).toBeUndefined();
	});
});
