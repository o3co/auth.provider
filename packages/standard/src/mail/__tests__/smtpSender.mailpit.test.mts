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
 * The SMTP sender against Mailpit, a real relay, in two containers: one
 * offering STARTTLS with the fixture certificate, taking any account, its
 * chaos on; one offering no TLS.
 *
 * The test kit's `MailSender` suite runs with delivery over STARTTLS to the
 * first, each refusal Mailpit's chaos can produce produced by it — the
 * recipient refused (`550`), the credentials refused (`535`), a transient
 * failure (`421` to MAIL FROM) — and an unreachable relay a port nothing
 * listens on. Chaos answers a code with no enhanced code and no text of the
 * suite's, so a limit and a refused message, which the sender reads from the
 * reply's enhanced code and the end of the data, are the scripted relay's
 * (`smtpSender.contract.test.mts` runs the whole suite there). What Mailpit
 * holds is every mailbox its record of a mail names: the `Received` line's
 * recipient, and its `To`, `Cc` and `Bcc`, where it lists an envelope
 * recipient the headers do not.
 */

import { fileURLToPath } from "node:url";
import type { MailSend, MailSender } from "@o3co/auth-provider-core";
import {
	type MailRelayRefusal,
	type MailSenderContractInput,
	mailSenderContract,
	type RelayedMail,
} from "@o3co/auth-provider-test-kit";
import { GenericContainer, type StartedTestContainer, Wait } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { standardSmtpMailSenderConfigSchema } from "#/mail/smtp/config.mjs";
import { MailTransportError } from "#/mail/smtp/failure.mjs";
import { createStandardSmtpMailSender } from "#/mail/smtp/sender.mjs";
import {
	type StandardSmtpMailSenderConfigForTestsOptions,
	standardSmtpMailSenderConfigForTests,
} from "#/testing/index.mjs";
import {
	closedPort,
	RELAY_CA,
	type ScriptedRelay,
	startScriptedRelay,
} from "./support/scriptedRelay.mjs";

const IMAGE = "axllent/mailpit:v1.31.3";
const fixture = (name: string): string =>
	fileURLToPath(new URL(`fixtures/${name}`, import.meta.url));

interface Mailpit {
	readonly container: StartedTestContainer;
	readonly host: string;
	readonly smtpPort: number;
	readonly api: string;
}

/** A Mailpit container with `flags`, serving once its API and SMTP server have started. */
async function startMailpit(flags: readonly string[], certificates: boolean): Promise<Mailpit> {
	const container = await new GenericContainer(IMAGE)
		.withExposedPorts(1025, 8025)
		.withCopyFilesToContainer(
			certificates
				? [
						{ source: fixture("relay-cert.pem"), target: "/certs/relay-cert.pem", mode: 0o644 },
						{ source: fixture("relay-key.pem"), target: "/certs/relay-key.pem", mode: 0o644 },
					]
				: [],
		)
		.withCommand(["--smtp-disable-rdns", ...flags])
		.withWaitStrategy(
			Wait.forAll([
				Wait.forLogMessage(/\[http\] accessible via/),
				Wait.forLogMessage(/\[smtpd\] starting on/),
			]),
		)
		.withStartupTimeout(120_000)
		.start();
	const host = container.getHost();
	return {
		container,
		host,
		smtpPort: container.getMappedPort(1025),
		api: `http://${host}:${container.getMappedPort(8025)}/api/v1`,
	};
}

let tls: Mailpit;
let plain: Mailpit;
let scripted: ScriptedRelay;

beforeAll(async () => {
	[tls, plain, scripted] = await Promise.all([
		startMailpit(
			[
				"--smtp-tls-cert",
				"/certs/relay-cert.pem",
				"--smtp-tls-key",
				"/certs/relay-key.pem",
				"--smtp-auth-accept-any",
				"--enable-chaos",
			],
			true,
		),
		startMailpit([], false),
		startScriptedRelay({ security: "starttls", auth: true }),
	]);
}, 180_000);

afterAll(async () => {
	await Promise.all([tls?.container.stop(), plain?.container.stop(), scripted?.close()]);
}, 60_000);

/** Mailpit's reply to a stage's command, as its chaos sets it: every time, or never. */
type Chaos = Readonly<
	Record<"Sender" | "Recipient" | "Authentication", { ErrorCode: number; Probability: number }>
>;
const CALM: Chaos = {
	Sender: { ErrorCode: 451, Probability: 0 },
	Recipient: { ErrorCode: 451, Probability: 0 },
	Authentication: { ErrorCode: 535, Probability: 0 },
};

async function setChaos(chaos: Chaos): Promise<void> {
	const response = await fetch(`${tls.api}/chaos`, {
		method: "PUT",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(chaos),
	});
	if (!response.ok) throw new Error(`Mailpit's chaos answered ${response.status}`);
}

interface MailpitAddress {
	readonly Address: string;
}
interface MailpitSummary {
	readonly ID: string;
	readonly To: readonly MailpitAddress[] | null;
	readonly Cc: readonly MailpitAddress[] | null;
	readonly Bcc: readonly MailpitAddress[] | null;
}

/** What `mailpit` holds, oldest first: every mailbox its record of each mail names, and the whole message. */
async function held(mailpit: Mailpit): Promise<RelayedMail[]> {
	const { messages } = (await (await fetch(`${mailpit.api}/messages?limit=500`)).json()) as {
		messages: MailpitSummary[];
	};
	return Promise.all(
		[...messages].reverse().map(async (summary) => {
			const content = await (await fetch(`${mailpit.api}/message/${summary.ID}/raw`)).text();
			const headers = (content.split("\r\n\r\n", 1)[0] ?? "").replace(/\r\n[ \t]+/g, " ");
			const received = [...headers.matchAll(/^Received:.*?\bfor <([^>]*)>/gim)].map(
				(match) => match[1] ?? "",
			);
			const listed = [summary.To, summary.Cc, summary.Bcc].flatMap((addresses) =>
				(addresses ?? []).map(({ Address }) => Address),
			);
			return { to: [...new Set([...received, ...listed])], content };
		}),
	);
}

/** The sender to `host:port`, trusting the fixture CA. */
const senderTo = (
	host: string,
	port: number,
	options: StandardSmtpMailSenderConfigForTestsOptions = {},
): MailSender => {
	const [section] = Object.values(
		standardSmtpMailSenderConfigForTests({
			host,
			port,
			secure: "starttls",
			from: "Sign-in <no-reply@example.com>",
			...options,
		}),
	);
	return createStandardSmtpMailSender(standardSmtpMailSenderConfigSchema.parse(section), {
		ca: RELAY_CA,
	});
};

/** `sender`, each send made under `chaos` and Mailpit calm again after it. */
const underChaos = (chaos: Partial<Chaos>, sender: MailSender): MailSender => ({
	kind: sender.kind,
	send: async (mail: MailSend) => {
		await setChaos({ ...CALM, ...chaos });
		try {
			return await sender.send(mail);
		} finally {
			await setChaos(CALM);
		}
	},
});

const ACCOUNT = { user: "mailer", password: "relay-password" } as const;

/** The refusals chaos produces, as it produces each. */
const CHAOS: Partial<Record<MailRelayRefusal, Partial<Chaos>>> = {
	recipient_refused: { Recipient: { ErrorCode: 550, Probability: 100 } },
	auth_failed: { Authentication: { ErrorCode: 535, Probability: 100 } },
	temporary_failure: { Sender: { ErrorCode: 421, Probability: 100 } },
};

/** The stage the scripted relay answers each other refusal at. */
const SCRIPTED = { limit: "rcpt", message_refused: "message" } as const;

let unreachablePort: number;
beforeAll(async () => {
	unreachablePort = await closedPort();
});

const input: MailSenderContractInput = {
	build: () => ({
		sender: senderTo(tls.host, tls.smtpPort, ACCOUNT),
		relayed: () => held(tls),
	}),
	refusing: (refusal, reply) => {
		if (refusal === "unreachable") return senderTo("127.0.0.1", unreachablePort);
		const chaos = CHAOS[refusal];
		if (chaos !== undefined) return underChaos(chaos, senderTo(tls.host, tls.smtpPort, ACCOUNT));
		scripted.rescript({ replies: { [SCRIPTED[refusal as keyof typeof SCRIPTED]]: reply } });
		return senderTo("127.0.0.1", scripted.port, ACCOUNT);
	},
};

describe("the SMTP sender against Mailpit, held to the MailSender suite", () => {
	for (const contractCase of mailSenderContract(input)) {
		it(contractCase.name, contractCase.run);
	}
});

describe("the SMTP sender against Mailpit's TLS rules", () => {
	const mail: MailSend = Object.freeze({
		purpose: "login_code",
		subject: "u-alice",
		to: "alice@example.com",
		code: "482913",
		expiresAtMs: Date.now() + 600_000,
	});

	it("under starttls, refuses a Mailpit that offers no STARTTLS, which then holds nothing", async () => {
		let refused: unknown;
		try {
			await senderTo(plain.host, plain.smtpPort, ACCOUNT).send(mail);
		} catch (error) {
			refused = error;
		}
		expect(refused).toBeInstanceOf(MailTransportError);
		expect((refused as MailTransportError).reason).toBe("unreachable");
		expect(await held(plain)).toEqual([]);
	});

	it("under none, delivers in the clear to a Mailpit on a loopback address", async () => {
		const before = (await held(plain)).length;
		const answer = await senderTo(plain.host, plain.smtpPort, { secure: "none" }).send(mail);
		expect(answer).toEqual({ outcome: "delivered" });
		const after = await held(plain);
		expect(after).toHaveLength(before + 1);
		expect(after.at(-1)?.to).toEqual(["alice@example.com"]);
	});
});
