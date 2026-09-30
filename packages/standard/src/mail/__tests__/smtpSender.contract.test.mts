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
 * The test kit's `MailSender` suite, run against the SMTP sender over a relay
 * a test scripts: STARTTLS with the fixture certificate, signed in, the
 * relay answering each refusal with the suite's own reply — marked, and
 * echoing the recipient — at the stage it names; an unreachable relay a
 * connection that fails with the suite's reply as its text.
 */

import { Socket } from "node:net";
import {
	type MailRelayRefusal,
	type MailSenderContractInput,
	mailSenderContract,
} from "@o3co/auth-provider-test-kit";
import { afterAll, beforeAll, describe, it } from "vitest";
import { standardSmtpMailSenderConfigSchema } from "#/mail/smtp/config.mjs";
import { createStandardSmtpMailSender } from "#/mail/smtp/sender.mjs";
import { standardSmtpMailSenderConfigForTests } from "#/testing/index.mjs";
import {
	RELAY_CA,
	type RelayStage,
	type ScriptedRelay,
	startScriptedRelay,
} from "./support/scriptedRelay.mjs";

/** The stage each refusal the relay answers is its reply to. */
const STAGE: Readonly<Record<Exclude<MailRelayRefusal, "unreachable">, RelayStage>> = {
	recipient_refused: "rcpt",
	message_refused: "message",
	auth_failed: "auth",
	temporary_failure: "rcpt",
	limit: "rcpt",
};

let accepting: ScriptedRelay;
let refusing: ScriptedRelay;

beforeAll(async () => {
	accepting = await startScriptedRelay({ security: "starttls", auth: true });
	refusing = await startScriptedRelay({ security: "starttls", auth: true });
});

afterAll(async () => {
	await Promise.all([accepting?.close(), refusing?.close()]);
});

/** The sender over `port`, signed in, over STARTTLS trusting the fixture CA. */
const senderAt = (port: number, connect?: () => Socket) => {
	const [section] = Object.values(
		standardSmtpMailSenderConfigForTests({
			host: "127.0.0.1",
			port,
			secure: "starttls",
			user: "mailer",
			password: "relay-password",
			from: "Sign-in <no-reply@example.com>",
		}),
	);
	return createStandardSmtpMailSender(standardSmtpMailSenderConfigSchema.parse(section), {
		ca: RELAY_CA,
		...(connect === undefined ? {} : { connect }),
	});
};

/** A connection that fails with `reply` as its text, as a refused one does. */
const failingWith = (reply: string) => (): Socket => {
	const socket = new Socket();
	process.nextTick(() => socket.destroy(Object.assign(new Error(reply), { code: "ECONNREFUSED" })));
	return socket;
};

const input: MailSenderContractInput = {
	build: () => ({ sender: senderAt(accepting.port), relayed: accepting.relayed }),
	refusing: (refusal, reply) => {
		if (refusal === "unreachable") return senderAt(refusing.port, failingWith(reply));
		refusing.rescript({ replies: { [STAGE[refusal]]: reply } });
		return senderAt(refusing.port);
	},
};

describe("the SMTP sender, held to the MailSender suite over a scripted relay", () => {
	for (const contractCase of mailSenderContract(input)) {
		it(contractCase.name, contractCase.run);
	}
});
