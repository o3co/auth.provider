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
 * The SMTP sender over a relay a test scripts: it delivers the standard
 * rendering to one envelope recipient, the address as written; it secures
 * the connection as `secure` says and never sends a command a secured
 * connection should carry over a plain one; it answers a limit apart from an
 * outage; it gives up on a relay that does not answer in time; and nothing of
 * the password, the address or the code reaches what it throws or writes.
 */

import { connect, Socket } from "node:net";
import {
	loggableError,
	type MailPurpose,
	type MailSend,
	type MailSender,
	mailSendOutcome,
} from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { standardSmtpMailSenderConfigSchema } from "#/mail/smtp/config.mjs";
import { MailTransportError } from "#/mail/smtp/failure.mjs";
import {
	createStandardSmtpMailSender,
	type StandardSmtpMailSenderDependencies,
} from "#/mail/smtp/sender.mjs";
import {
	type StandardSmtpMailSenderConfigForTestsOptions,
	standardSmtpMailSenderConfigForTests,
} from "#/testing/index.mjs";
import {
	closedPort,
	RELAY_CA,
	type ScriptedRelay,
	type ScriptedRelayOptions,
	startScriptedRelay,
} from "./support/scriptedRelay.mjs";

const NOW = Date.UTC(2026, 8, 30, 12, 0, 0);
const CODE = "482913";
const FROM = "Sign-in <no-reply@example.com>";

const mailTo = (to: string, purpose: MailPurpose = "login_code"): MailSend =>
	Object.freeze({ purpose, subject: "u-alice", to, code: CODE, expiresAtMs: NOW + 10 * 60_000 });

/** The section as the testing entry's builder lays `options` over its defaults, parsed. */
const settingsFor = (options: StandardSmtpMailSenderConfigForTestsOptions) => {
	const [section] = Object.values(standardSmtpMailSenderConfigForTests(options));
	return standardSmtpMailSenderConfigSchema.parse(section);
};

const relays: ScriptedRelay[] = [];
const relayWith = async (options: ScriptedRelayOptions = {}): Promise<ScriptedRelay> => {
	const relay = await startScriptedRelay(options);
	relays.push(relay);
	return relay;
};

afterEach(async () => {
	await Promise.all(relays.splice(0).map((relay) => relay.close()));
	vi.restoreAllMocks();
});

/** The sender over `port` on `127.0.0.1`, trusting the fixture CA, at `NOW`. */
const senderAt = (
	port: number,
	options: StandardSmtpMailSenderConfigForTestsOptions = {},
	dependencies: StandardSmtpMailSenderDependencies = {},
): MailSender =>
	createStandardSmtpMailSender(
		settingsFor({ host: "127.0.0.1", port, secure: "starttls", from: FROM, ...options }),
		{ ca: RELAY_CA, now: () => NOW, ...dependencies },
	);

/** What `sending` rejected with; a failure if it resolved. */
async function rejectionOf(sending: Promise<unknown>): Promise<unknown> {
	try {
		const answer = await sending;
		throw new Error(`resolved ${JSON.stringify(answer)}`);
	} catch (error) {
		return error;
	}
}

/** The verbs of the command lines the relay read. */
const verbs = (relay: ScriptedRelay): string[] =>
	relay
		.commands()
		.map(({ line }) =>
			(/^(MAIL FROM|RCPT TO)/i.exec(line)?.[0] ?? line.split(" ")[0] ?? "").toUpperCase(),
		);

describe("the SMTP sender's delivery", () => {
	it("is of kind standard-smtp", () => {
		expect(senderAt(25).kind).toBe("standard-smtp");
	});

	it("delivers over STARTTLS the standard rendering, from the configured sender, to the one recipient, signing in only on the secured connection", async () => {
		const relay = await relayWith({ security: "starttls", auth: true });
		const sender = senderAt(relay.port, { user: "mailer", password: "relay-password" });
		const answer = await sender.send(mailTo("alice@example.com"));
		expect(mailSendOutcome(answer)).toBe("delivered");
		expect(verbs(relay)).toEqual([
			"EHLO",
			"STARTTLS",
			"EHLO",
			"AUTH",
			"MAIL FROM",
			"RCPT TO",
			"DATA",
		]);
		const commands = relay.commands();
		expect(commands.slice(0, 2).every(({ secure }) => !secure)).toBe(true);
		expect(commands.slice(2).every(({ secure }) => secure)).toBe(true);
		expect(commands.find(({ line }) => line.startsWith("MAIL FROM"))?.line).toBe(
			"MAIL FROM:<no-reply@example.com>",
		);
		const [relayed] = await relay.relayed();
		expect(relayed?.to).toEqual(["alice@example.com"]);
		const content = relayed?.content ?? "";
		expect(content).toMatch(/^Subject: Your sign-in code$/m);
		expect(content).toMatch(/^From: "?Sign-in"? <no-reply@example\.com>$/m);
		expect(content).toContain(`Your sign-in code is ${CODE}.`);
		expect(content).toContain("It expires in 10 minutes.");
		expect(content).not.toContain("u-alice");
	});

	it("delivers over implicit TLS, every command on the secured connection", async () => {
		const relay = await relayWith({ security: "tls" });
		const answer = await senderAt(relay.port, { secure: "tls" }).send(mailTo("alice@example.com"));
		expect(mailSendOutcome(answer)).toBe("delivered");
		expect(relay.commands().every(({ secure }) => secure)).toBe(true);
		expect((await relay.relayed()).map(({ to }) => to)).toEqual([["alice@example.com"]]);
	});

	it("verifies the relay's certificate against its name: localhost over STARTTLS", async () => {
		const relay = await relayWith({ security: "starttls" });
		const answer = await senderAt(
			relay.port,
			{ host: "localhost" },
			{
				connect: ({ port }) => connect({ host: "127.0.0.1", port }),
			},
		).send(mailTo("alice@example.com"));
		expect(mailSendOutcome(answer)).toBe("delivered");
	});

	it("delivers every purpose, each its own subject line", async () => {
		const relay = await relayWith({ security: "starttls" });
		const sender = senderAt(relay.port);
		for (const purpose of [
			"login_code",
			"account_email_proof",
			"email_factor_enrollment",
		] as const) {
			expect(mailSendOutcome(await sender.send(mailTo("alice@example.com", purpose)))).toBe(
				"delivered",
			);
		}
		const subjects = (await relay.relayed()).map(
			({ content }) => /^Subject: (.*)$/m.exec(content)?.[1],
		);
		expect(subjects).toEqual([
			"Your sign-in code",
			"Confirm your email address",
			"Confirm sign-in codes by email",
		]);
	});
});

describe("the SMTP sender's TLS rules", () => {
	it("under starttls, refuses a relay that does not offer STARTTLS: rejects, and nothing after STARTTLS reaches it", async () => {
		const relay = await relayWith({ security: "none", auth: true });
		const error = await rejectionOf(
			senderAt(relay.port, { user: "mailer", password: "relay-password" }).send(
				mailTo("alice@example.com"),
			),
		);
		expect(error).toBeInstanceOf(MailTransportError);
		expect((error as MailTransportError).reason).toBe("unreachable");
		expect(verbs(relay)).toEqual(["EHLO", "STARTTLS"]);
		expect(await relay.relayed()).toEqual([]);
	});

	it("under starttls, refuses a relay that answers STARTTLS with a refusal, and never goes on in the clear", async () => {
		const relay = await relayWith({
			security: "starttls",
			replies: { starttls: "454 4.7.0 TLS not available" },
		});
		const error = await rejectionOf(senderAt(relay.port).send(mailTo("alice@example.com")));
		expect((error as MailTransportError).reason).toBe("unreachable");
		expect(verbs(relay)).toEqual(["EHLO", "STARTTLS"]);
	});

	it("refuses a relay whose certificate chains to no CA it trusts, over STARTTLS and over implicit TLS", async () => {
		for (const security of ["starttls", "tls"] as const) {
			const relay = await relayWith({ security, auth: true });
			const sender = createStandardSmtpMailSender(
				settingsFor({
					host: "127.0.0.1",
					port: relay.port,
					secure: security,
					from: FROM,
					user: "mailer",
					password: "relay-password",
				}),
				{ now: () => NOW },
			);
			const error = await rejectionOf(sender.send(mailTo("alice@example.com")));
			expect((error as MailTransportError).reason, security).toBe("unreachable");
			expect(
				relay.commands().some(({ secure }) => secure),
				security,
			).toBe(false);
			expect(
				verbs(relay).filter((verb) => verb !== "EHLO" && verb !== "STARTTLS"),
				security,
			).toEqual([]);
		}
	});

	it("refuses a certificate that does not name the configured host", async () => {
		const relay = await relayWith({ security: "starttls" });
		const sender = senderAt(
			relay.port,
			{ host: "smtp.example.com" },
			{
				connect: ({ port }) => connect({ host: "127.0.0.1", port }),
			},
		);
		const error = await rejectionOf(sender.send(mailTo("alice@example.com")));
		expect((error as MailTransportError).reason).toBe("unreachable");
		expect(verbs(relay)).toEqual(["EHLO", "STARTTLS"]);
	});

	it("under none, delivers in the clear to a loopback relay, ignoring the STARTTLS it offers", async () => {
		const relay = await relayWith({ security: "starttls" });
		const answer = await senderAt(relay.port, { secure: "none" }).send(mailTo("alice@example.com"));
		expect(mailSendOutcome(answer)).toBe("delivered");
		expect(verbs(relay)).not.toContain("STARTTLS");
		expect(relay.commands().some(({ secure }) => secure)).toBe(false);
	});

	it("under none, refuses when the connected socket's address is not loopback, though the host is, and sends nothing", async () => {
		const relay = await relayWith({ security: "none" });
		const sender = senderAt(
			relay.port,
			{ secure: "none", host: "localhost" },
			{
				connect: ({ port }) => {
					const socket = connect({ host: "127.0.0.1", port });
					Object.defineProperty(socket, "remoteAddress", { value: "192.0.2.10" });
					return socket;
				},
			},
		);
		const error = await rejectionOf(sender.send(mailTo("alice@example.com")));
		expect(error).toBeInstanceOf(MailTransportError);
		expect((error as MailTransportError).reason).toBe("unreachable");
		expect((error as MailTransportError).message).toContain("not loopback");
		expect(relay.commands()).toEqual([]);
	});

	it("under none, takes a loopback address in its IPv4-mapped IPv6 form", async () => {
		const relay = await relayWith({ security: "none" });
		const sender = senderAt(
			relay.port,
			{ secure: "none" },
			{
				connect: ({ port }) => {
					const socket = connect({ host: "127.0.0.1", port });
					Object.defineProperty(socket, "remoteAddress", { value: "::ffff:127.0.0.1" });
					return socket;
				},
			},
		);
		expect(mailSendOutcome(await sender.send(mailTo("alice@example.com")))).toBe("delivered");
	});
});

describe("the SMTP sender's deadlines", () => {
	const SHORT = { connectMs: 200, greetingMs: 200, idleMs: 200 };

	it("gives up on a connection that is not made in time", async () => {
		const started = Date.now();
		const error = await rejectionOf(
			senderAt(25, {}, { timeouts: SHORT, connect: () => new Socket() }).send(
				mailTo("alice@example.com"),
			),
		);
		expect((error as MailTransportError).reason).toBe("timeout");
		expect(Date.now() - started).toBeLessThan(5_000);
	});

	it("gives up on a relay that never greets", async () => {
		const relay = await relayWith({ silent: "greeting" });
		const error = await rejectionOf(
			senderAt(relay.port, {}, { timeouts: SHORT }).send(mailTo("alice@example.com")),
		);
		expect((error as MailTransportError).reason).toBe("timeout");
		expect(relay.commands()).toEqual([]);
	});

	it("gives up on a relay that stops answering", async () => {
		const relay = await relayWith({ silent: "rcpt" });
		const error = await rejectionOf(
			senderAt(relay.port, {}, { timeouts: SHORT }).send(mailTo("alice@example.com")),
		);
		expect((error as MailTransportError).reason).toBe("timeout");
		expect(await relay.relayed()).toEqual([]);
	});

	it("rejects as unreachable where nothing listens", async () => {
		const error = await rejectionOf(senderAt(await closedPort()).send(mailTo("alice@example.com")));
		expect((error as MailTransportError).reason).toBe("unreachable");
	});
});

describe("the SMTP sender's answers", () => {
	it("answers refused_at_limit for a relay refusing the recipient at a limit", async () => {
		const relay = await relayWith({
			replies: { rcpt: "451 4.7.1 <alice@example.com>: rate limited" },
		});
		expect(mailSendOutcome(await senderAt(relay.port).send(mailTo("alice@example.com")))).toBe(
			"refused_at_limit",
		);
		expect(await relay.relayed()).toEqual([]);
	});

	it("rejects with the reason for a relay refusing the credentials, the recipient or the message, or failing for now", async () => {
		const cases: [ScriptedRelayOptions, string][] = [
			[{ auth: true, replies: { auth: "535 5.7.8 credentials invalid" } }, "auth_failed"],
			[{ auth: true, replies: { rcpt: "550 5.1.1 unknown" } }, "rejected"],
			[{ auth: true, replies: { message: "554 5.7.1 refused" } }, "rejected"],
			[{ auth: true, replies: { rcpt: "421 4.3.2 try later" } }, "rejected"],
			[{ auth: true, replies: { mail: "451 4.7.0 temporary" } }, "rejected"],
		];
		for (const [script, reason] of cases) {
			const relay = await relayWith(script);
			const error = await rejectionOf(
				senderAt(relay.port, { user: "mailer", password: "relay-password" }).send(
					mailTo("alice@example.com"),
				),
			);
			expect(error, JSON.stringify(script)).toBeInstanceOf(MailTransportError);
			expect((error as MailTransportError).reason, JSON.stringify(script)).toBe(reason);
		}
	});

	it("signs in with the configured account only where one is configured", async () => {
		const relay = await relayWith({ auth: true });
		await senderAt(relay.port).send(mailTo("alice@example.com"));
		expect(verbs(relay)).not.toContain("AUTH");
	});
});

describe("the SMTP sender's envelope", () => {
	it("names the one recipient as written, a quoted local part holding a separator or an at sign included, and nobody else", async () => {
		for (const to of [
			'"a,b"@example.com',
			'"a;b"@example.com',
			'"bob@evil.example,carol"@example.com',
			'"x@evil.example;y"@example.com',
			'"a:b(c)"@example.com',
		]) {
			const relay = await relayWith();
			expect(mailSendOutcome(await senderAt(relay.port).send(mailTo(to))), to).toBe("delivered");
			expect(
				relay
					.commands()
					.filter(({ line }) => line.startsWith("RCPT TO"))
					.map(({ line }) => line),
				to,
			).toEqual([`RCPT TO:<${to}>`]);
			const [relayed] = await relay.relayed();
			expect(relayed?.to, to).toEqual([to]);
			const headers = (relayed?.content ?? "").split("\r\n\r\n", 1)[0] ?? "";
			expect(headers.match(/^To: .*$/gm), to).toEqual([`To: <${to}>`]);
			expect(headers, to).not.toMatch(/^(Cc|Bcc):/im);
		}
	});

	it("refuses, before any connection, a recipient the envelope cannot carry as written: a quoted local part holding an angle bracket", async () => {
		const relay = await relayWith();
		for (const to of [
			'"a<b"@example.com',
			'"a>b"@example.com',
			'"x>bob@evil.example"@example.com',
		]) {
			const error = await rejectionOf(senderAt(relay.port).send(mailTo(to)));
			expect(error, to).toBeInstanceOf(RangeError);
			expect((error as Error).message, to).not.toContain("example");
		}
		expect(relay.connections()).toBe(0);
	});

	it("refuses, before any connection, a recipient that is not one addr-spec in its normalised spelling", async () => {
		const relay = await relayWith();
		for (const to of [
			"Alice@example.com",
			" alice@example.com",
			"alice@example.com, bob@example.com",
			"Alice <alice@example.com>",
			"alice@example.com\r\nBcc: bob@evil.example",
			"",
		]) {
			const error = await rejectionOf(senderAt(relay.port).send(mailTo(to)));
			expect(error, JSON.stringify(to)).toBeInstanceOf(RangeError);
			expect((error as Error).message, JSON.stringify(to)).not.toContain("alice");
		}
		expect(relay.connections()).toBe(0);
	});
});

describe("what the SMTP sender throws and writes", () => {
	const PASSWORD = "Pw-S3ntinel-9f2c";
	const ADDRESS = "sentinel-addr-7q@example.com";
	const SENTINEL_CODE = "sent1nel-code-4k";

	const failures: [string, ScriptedRelayOptions][] = [
		[
			"credentials refused",
			{ auth: true, replies: { auth: `535 5.7.8 ${PASSWORD} ${ADDRESS} refused` } },
		],
		[
			"recipient refused",
			{ auth: true, replies: { rcpt: `550 5.1.1 <${ADDRESS}>: unknown ${SENTINEL_CODE}` } },
		],
		[
			"message refused",
			{ auth: true, replies: { message: `554 5.7.1 ${SENTINEL_CODE} ${ADDRESS} refused` } },
		],
		["greeting refused", { replies: { greeting: `554 5.3.2 ${ADDRESS} no service` } }],
		["STARTTLS refused", { replies: { starttls: `454 4.7.0 ${ADDRESS} no TLS` } }],
		["stalled", { auth: true, silent: "message" }],
	];

	it("carries none of the password, the address or the code in an error's message, stack, projection or own properties, and writes none to the console or the process's output", async () => {
		const written: string[] = [];
		const capture = (...args: unknown[]) => {
			written.push(
				args.map((arg) => (typeof arg === "string" ? arg : JSON.stringify(arg))).join(" "),
			);
			return true;
		};
		for (const method of ["log", "info", "warn", "error", "debug", "trace"] as const) {
			vi.spyOn(console, method).mockImplementation(capture);
		}
		vi.spyOn(process.stdout, "write").mockImplementation(capture as never);
		vi.spyOn(process.stderr, "write").mockImplementation(capture as never);

		for (const [what, script] of failures) {
			const relay = await relayWith(script);
			const sender = senderAt(
				relay.port,
				{ user: "mailer", password: PASSWORD },
				{
					timeouts: { connectMs: 300, greetingMs: 300, idleMs: 300 },
				},
			);
			const error = (await rejectionOf(
				sender.send({ ...mailTo(ADDRESS), code: SENTINEL_CODE }),
			)) as Error & { cause?: unknown };
			expect(error, what).toBeInstanceOf(MailTransportError);
			expect(error.cause, what).toBeUndefined();
			const seen = [
				error.message,
				error.stack ?? "",
				JSON.stringify(loggableError(error)),
				JSON.stringify(Object.fromEntries(Object.entries(error))),
			].join("\n");
			for (const secret of [
				PASSWORD,
				ADDRESS,
				"sentinel-addr-7q",
				SENTINEL_CODE,
				Buffer.from(PASSWORD).toString("base64"),
			]) {
				expect(seen, `${what}: ${secret}`).not.toContain(secret);
			}
		}
		const refusedUnreachable = await rejectionOf(
			senderAt(await closedPort(), { password: PASSWORD, user: "mailer" }).send({
				...mailTo(ADDRESS),
				code: SENTINEL_CODE,
			}),
		);
		expect(JSON.stringify(loggableError(refusedUnreachable))).not.toContain(ADDRESS);
		vi.restoreAllMocks();
		expect(written.join("\n")).not.toMatch(/Pw-S3ntinel|sentinel-addr|sent1nel-code/);
	});
});

describe("the SMTP sender's settings", () => {
	it("refuses to be built without what sending needs, naming the key and its variable and quoting no value", () => {
		const refusals: [StandardSmtpMailSenderConfigForTestsOptions, string][] = [
			[{ from: FROM }, "standard-smtp-mail-sender.host (STANDARD_SMTP_MAIL_SENDER_HOST)"],
			[
				{ host: "smtp.example.com" },
				"standard-smtp-mail-sender.from (STANDARD_SMTP_MAIL_SENDER_FROM)",
			],
			[
				{ host: "smtp.example.com", from: "no address here" },
				"standard-smtp-mail-sender.from (STANDARD_SMTP_MAIL_SENDER_FROM)",
			],
			[
				{ host: "smtp.example.com", from: "a@example.com, b@example.com" },
				"standard-smtp-mail-sender.from (STANDARD_SMTP_MAIL_SENDER_FROM)",
			],
			[
				{ host: "smtp.example.com", from: "Sign-in <Not An Address>" },
				"standard-smtp-mail-sender.from (STANDARD_SMTP_MAIL_SENDER_FROM)",
			],
			[
				{ host: "smtp.example.com", from: FROM, user: "mailer" },
				"standard-smtp-mail-sender.password (STANDARD_SMTP_MAIL_SENDER_PASSWORD)",
			],
			[
				{ host: "smtp.example.com", from: FROM, password: "Pw-S3ntinel-9f2c" },
				"standard-smtp-mail-sender.user (STANDARD_SMTP_MAIL_SENDER_USER)",
			],
		];
		for (const [options, named] of refusals) {
			let refused: unknown;
			try {
				createStandardSmtpMailSender(settingsFor(options));
			} catch (error) {
				refused = error;
			}
			expect(refused, JSON.stringify(options)).toBeInstanceOf(RangeError);
			expect((refused as Error).message, JSON.stringify(options)).toContain(named);
			expect((refused as Error).message, JSON.stringify(options)).not.toMatch(
				/S3ntinel|Not An Address|b@example/,
			);
		}
	});

	it("is built from a sender address alone, or a name and an address", () => {
		for (const from of [
			"no-reply@example.com",
			FROM,
			'"Sign-in, Example" <no-reply@example.com>',
		]) {
			expect(
				createStandardSmtpMailSender(settingsFor({ host: "smtp.example.com", from })).kind,
				from,
			).toBe("standard-smtp");
		}
	});
});
