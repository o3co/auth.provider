import { getCACertificates, setDefaultCACertificates } from "node:tls";
import { inspect } from "node:util";
import { assemble, BootRefused, kernelConfig, type Module, Unavailable } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { mail } from "@mod/mail";
import mailModule from "@mod/mail/module";
import { contractTemplates, mailConfig, mailContract, remoteWords } from "@mod/mail/testing";
import { afterAll, describe, expect, it } from "vitest";
import smtp from "../src/module.ts";
import { type FakeRelay, fakeRelay, type Script } from "./fake-relay.ts";
import { authority, relay as relayCertificate, stranger } from "./fixtures/certificates.ts";

// The relay's authority is trusted the way an operator adds one to the platform's store.
setDefaultCACertificates([...getCACertificates("default"), authority]);

const recorded = recordingLog();
const runtime = quietRuntime({
	random: { bytes: (n: number) => new Uint8Array(n).fill(7) },
	log: recorded.log,
});

const relays: FakeRelay[] = [];
afterAll(() => Promise.all(relays.map((r) => r.close())));
const started = async (script: Script = {}) => {
	const r = await fakeRelay(script);
	relays.push(r);
	return r;
};

const password = "pa55-not-to-show";
const section = (port: number, more: object = {}) => ({
	host: "127.0.0.1",
	port,
	security: "none",
	from: "Provider <noreply@example.test>",
	deadline: "2s",
	...more,
});
const assembled = (settings: object, modules: readonly Module[] = [contractTemplates]) =>
	assemble({
		modules: [smtp, ...modules],
		config: { ...kernelConfig(), "mail-smtp": settings },
		runtime,
	});
const boot = async (settings: object, modules?: readonly Module[]) =>
	(await assembled(settings, modules)).get(mail);
const notice = (to = "someone@example.test") => ({
	purpose: "contract.notice",
	to,
	values: { value: "1" },
});
const refusingReply = (how: "limit" | "down") =>
	how === "limit" ? `452 4.7.1 ${remoteWords}` : `554 5.7.1 ${remoteWords}`;
const refusals = async (settings: object) => {
	const failure = await assembled(settings).catch((e: unknown) => e);
	expect(failure).toBeInstanceOf(BootRefused);
	return (failure as BootRefused).refusals;
};
const failureOf = (sending: Promise<unknown>) => sending.catch((e: unknown) => e);
const verbs = (r: FakeRelay) => r.lines.map((l) => (l === "(tls)" ? l : l.split(/[ :]/)[0]));

mailContract("SMTP, plaintext to loopback", {
	boot: async (modules) => boot(section((await started()).port), modules),
	refusing: async (how, modules) => {
		const r = await started({ replies: { RCPT: refusingReply(how) } });
		return boot(section(r.port), modules);
	},
});

mailContract("SMTP, STARTTLS", {
	boot: async (modules) => {
		const r = await started({ extensions: ["STARTTLS"], certificate: relayCertificate });
		return boot(section(r.port, { host: "localhost", security: "starttls" }), modules);
	},
	refusing: async (how, modules) => {
		const r = await started({
			extensions: ["STARTTLS"],
			certificate: relayCertificate,
			replies: { MAIL: refusingReply(how) },
		});
		return boot(section(r.port, { host: "localhost", security: "starttls" }), modules);
	},
});

describe("delivery", () => {
	it("sends under none to a loopback address as the section took it, IPv4 mapped into IPv6 too", async () => {
		const r = await started();
		const smtpAt = await boot(section(r.port, { host: "::ffff:127.0.0.1" }));
		await expect(smtpAt.send(notice())).resolves.toBe("sent");
		expect(verbs(r)).toEqual(["EHLO", "MAIL", "RCPT", "DATA", "QUIT"]);
	});

	it("sends one message with one recipient in the envelope and in To, and no AUTH without an account", async () => {
		const r = await started();
		await expect((await boot(section(r.port))).send(notice())).resolves.toBe("sent");
		expect(verbs(r)).toEqual(["EHLO", "MAIL", "RCPT", "DATA", "QUIT"]);
		expect(r.lines[1]).toBe("MAIL FROM:<noreply@example.test>");
		expect(r.lines[2]).toBe("RCPT TO:<someone@example.test>");
		const [message = ""] = r.messages;
		expect(message.split("\r\n").filter((l) => /^to:/i.test(l))).toEqual([
			"To: <someone@example.test>",
		]);
		expect(message).toMatch(/^From: Provider <noreply@example\.test>$/m);
		expect(message).toMatch(/^Subject: Notice$/m);
		expect(message).toContain("Value: 1");
	});

	it("over STARTTLS sends only EHLO and STARTTLS in the clear, and signs in only after TLS", async () => {
		const r = await started({
			extensions: ["STARTTLS", "AUTH PLAIN"],
			certificate: relayCertificate,
		});
		const sender = await boot(
			section(r.port, { host: "localhost", security: "starttls", user: "relay-user", password }),
		);
		await expect(sender.send(notice())).resolves.toBe("sent");
		expect(verbs(r)).toEqual([
			"EHLO",
			"STARTTLS",
			"(tls)",
			"EHLO",
			"AUTH",
			"MAIL",
			"RCPT",
			"DATA",
			"QUIT",
		]);
	});

	it("over TLS from the first byte, checks the certificate's issuer and its name against the host", async () => {
		const r = await started({ implicit: true, certificate: relayCertificate });
		const sender = await boot(section(r.port, { host: "localhost", security: "tls" }));
		await expect(sender.send(notice())).resolves.toBe("sent");
		const s = await started({ implicit: true, certificate: stranger });
		const unknown = await boot(section(s.port, { host: "localhost", security: "tls" }));
		await expect(unknown.send(notice())).rejects.toBeInstanceOf(Unavailable);
		expect(s.lines).toEqual([]);
		// The same trusted certificate, reached by an address it does not name.
		const t = await started({ implicit: true, certificate: relayCertificate });
		const misnamed = await boot(section(t.port, { host: "127.0.0.1", security: "tls" }));
		await expect(misnamed.send(notice())).rejects.toBeInstanceOf(Unavailable);
		expect(t.lines).toEqual([]);
	});

	it("keeps sent when QUIT fails or goes unanswered", async () => {
		for (const QUIT of ["drop", "none"]) {
			const r = await started({ replies: { QUIT } });
			const sender = await boot(section(r.port, { deadline: "400ms" }));
			await expect(sender.send(notice())).resolves.toBe("sent");
		}
	});
});

describe("securing the connection", () => {
	const starttls = (r: FakeRelay, more: object = {}) =>
		boot(section(r.port, { host: "localhost", security: "starttls", ...more }));

	it("sends nothing more when STARTTLS is not offered or is refused", async () => {
		const missing = await started({ extensions: ["AUTH PLAIN"] });
		await expect((await starttls(missing)).send(notice())).rejects.toBeInstanceOf(Unavailable);
		expect(verbs(missing)).toEqual(["EHLO", "STARTTLS"]);
		const refused = await started({
			extensions: ["STARTTLS"],
			certificate: relayCertificate,
			replies: { STARTTLS: "454 4.7.0 not now" },
		});
		await expect((await starttls(refused)).send(notice())).rejects.toBeInstanceOf(Unavailable);
		expect(verbs(refused)).toEqual(["EHLO", "STARTTLS"]);
	});

	it("refuses a certificate no trusted authority issued, or issued for another name", async () => {
		const untrusted = await started({ extensions: ["STARTTLS"], certificate: stranger });
		const sender = await starttls(untrusted, { user: "relay-user", password });
		await expect(sender.send(notice())).rejects.toBeInstanceOf(Unavailable);
		expect(verbs(untrusted)).toEqual(["EHLO", "STARTTLS", "(tls)"]);
		const named = await started({ extensions: ["STARTTLS"], certificate: relayCertificate });
		const byAddress = await starttls(named, { host: "127.0.0.1" });
		await expect(byAddress.send(notice())).rejects.toBeInstanceOf(Unavailable);
		expect(verbs(named)).toEqual(["EHLO", "STARTTLS", "(tls)"]);
	});

	it("checks the certificate whatever the environment says", async () => {
		const before = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
		process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
		try {
			const r = await started({ extensions: ["STARTTLS"], certificate: stranger });
			await expect((await starttls(r)).send(notice())).rejects.toBeInstanceOf(Unavailable);
		} finally {
			if (before === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
			else process.env.NODE_TLS_REJECT_UNAUTHORIZED = before;
		}
	});
});

describe("the relay's answers", () => {
	const answered = async (replies: Record<string, string>, extensions: string[] = []) => {
		const r = await started({ replies, extensions });
		const sender = await boot(section(r.port, { user: "relay-user", password }));
		return failureOf(sender.send(notice()));
	};

	it("is limited only by a limit reply to the sender, the recipient or the message", async () => {
		const limits = [
			{ MAIL: "451 4.7.28 slow down" },
			{ RCPT: "452 4.5.3 too many" },
			{ RCPT: "450 4.7.1 later" },
			{ DATA: "451 4.7.1 later" },
			{ message: "421 4.7.1 later" },
		];
		for (const replies of limits)
			await expect(answered(replies), inspect(replies)).resolves.toBe("limited");
	});

	it("logs a limit with the purpose alone", async () => {
		const from = recorded.lines().length;
		await expect(answered({ RCPT: "450 4.7.1 later" })).resolves.toBe("limited");
		expect(
			recorded
				.lines()
				.slice(from)
				.filter((l) => l.event !== "mail-smtp.plaintext"),
		).toEqual([
			{ level: "info", event: "mail-smtp.limited", fields: { purpose: "contract.notice" } },
		]);
	});

	it("reads an enhanced code only of the reply's own class", async () => {
		const from = recorded.lines().length;
		expect(await answered({ RCPT: "550 4.7.1 no" })).toBeInstanceOf(Unavailable);
		expect(
			recorded
				.lines()
				.slice(from)
				.filter((l) => l.event === "mail-smtp.unsent"),
		).toEqual([
			expect.objectContaining({
				fields: { purpose: "contract.notice", stage: "recipient", reply: 550 },
			}),
		]);
	});

	it("is unavailable for any other reply, and for a limit while connecting or signing in", async () => {
		const others = [
			{ greeting: "421 4.7.1 busy" },
			{ EHLO: "421 4.7.1 busy" },
			{ AUTH: "454 4.7.1 later" },
			{ RCPT: "452 4.2.2 full" },
			{ RCPT: "452 too many" },
			{ RCPT: "550 5.7.1 no" },
			{ message: "554 5.6.0 no" },
		];
		for (const replies of others) {
			expect(await answered(replies, ["AUTH PLAIN"]), inspect(replies)).toBeInstanceOf(Unavailable);
		}
	});

	it("carries neither the relay's words, the address nor the password, in the failure or the log", async () => {
		const r = await started({
			replies: { RCPT: `550 5.1.1 ${remoteWords}` },
			extensions: ["AUTH PLAIN"],
		});
		const sender = await boot(section(r.port, { user: "relay-user", password }));
		const from = recorded.lines().length;
		const failure = await failureOf(sender.send(notice()));
		expect(failure).toBeInstanceOf(Unavailable);
		const logLines = recorded.lines().slice(from);
		const shown = `${inspect(failure)} ${JSON.stringify(logLines)}`;
		for (const secret of [remoteWords, "someone@example.test", password]) {
			expect(shown).not.toContain(secret);
		}
		expect(logLines).toEqual([
			{
				level: "warn",
				event: "mail-smtp.unsent",
				fields: { purpose: "contract.notice", stage: "recipient", reply: 550, enhanced: "5.1.1" },
			},
		]);
	});

	it("is unavailable when the relay cannot be reached, logging the connection's code", async () => {
		const r = await started();
		await r.close();
		const sender = await boot(section(r.port));
		const from = recorded.lines().length;
		await expect(sender.send(notice())).rejects.toBeInstanceOf(Unavailable);
		expect(recorded.lines()[from]?.fields).toMatchObject({
			stage: "connection",
			code: "ECONNREFUSED",
		});
	});
});

describe("addresses", () => {
	it("never takes an address mail refuses to the relay", async () => {
		const r = await started();
		const sender = await boot(section(r.port));
		const refused = [
			"a%b@example.test",
			"someone@ｅxample.test",
			"someone@example.test/x",
			"someone@xn--a.example",
			"=?utf-8?q?a?=@example.test",
		];
		for (const to of refused) {
			await expect(sender.send(notice(to)), to).rejects.toBeInstanceOf(TypeError);
		}
		expect(r.lines).toEqual([]);
	});
});

describe("addresses beyond ASCII", () => {
	it("sends the domain in its ASCII form", async () => {
		const r = await started();
		const sender = await boot(section(r.port));
		for (const to of ["someone@bücher.example", "someone@Bücher.Example"]) {
			await expect(sender.send(notice(to)), to).resolves.toBe("sent");
		}
		expect(r.lines.filter((l) => l.startsWith("RCPT"))).toEqual([
			"RCPT TO:<someone@xn--bcher-kva.example>",
			"RCPT TO:<someone@xn--bcher-kva.example>",
		]);
	});

	it("sends from a domain beyond ASCII in its ASCII form, to a relay offering no SMTPUTF8", async () => {
		const r = await started();
		const sender = await boot(section(r.port, { from: "Provider <noreply@bücher.example>" }));
		await expect(sender.send(notice())).resolves.toBe("sent");
		expect(r.lines[1]).toBe("MAIL FROM:<noreply@xn--bcher-kva.example>");
	});

	it("sends a local part beyond ASCII only to a relay offering SMTPUTF8", async () => {
		const to = "jörg@example.test";
		const plain = await started();
		await expect((await boot(section(plain.port))).send(notice(to))).rejects.toBeInstanceOf(
			Unavailable,
		);
		expect(verbs(plain)).not.toContain("MAIL");
		const utf8 = await started({ extensions: ["SMTPUTF8"] });
		await expect((await boot(section(utf8.port))).send(notice(to))).resolves.toBe("sent");
		expect(utf8.lines[1]).toBe("MAIL FROM:<noreply@example.test> SMTPUTF8");
		expect(utf8.lines[2]).toBe(`RCPT TO:<${to}>`);
	});
});

describe("deadlines", () => {
	/** What the log names as having ended a send that failed; no wall time is read. */
	const endedBy = async (script: Script) => {
		const r = await started(script);
		const sender = await boot(section(r.port, { deadline: "1s" }));
		const from = recorded.lines().length;
		await expect(sender.send(notice())).rejects.toBeInstanceOf(Unavailable);
		return recorded.lines()[from]?.fields;
	};

	it("gives up on a relay that never greets, at the greeting's deadline", async () => {
		// The greeting's own deadline, a quarter of the whole send's, ends it before the whole one.
		expect(await endedBy({ replies: { greeting: "none" } })).toMatchObject({
			stage: "greeting",
			code: "ETIMEDOUT",
		});
	});
	it("gives up on a relay that answers bit by bit, at the whole send's deadline", async () => {
		// A line every 20 ms keeps each silence far below its own deadline: only the whole one can end it.
		expect(await endedBy({ trickleMs: 20 })).toMatchObject({ stage: "deadline" });
	});
});

describe("sends at once", () => {
	it("answers unavailable past concurrent-sends, opening no connection, and takes another once one ends", async () => {
		const r = await started({ replies: { greeting: "none" } });
		const sender = await boot(section(r.port, { deadline: "400ms", "concurrent-sends": 1 }));
		const from = recorded.lines().length;
		const first = failureOf(sender.send(notice()));
		await expect(sender.send(notice())).rejects.toBeInstanceOf(Unavailable);
		expect(await first).toBeInstanceOf(Unavailable);
		await expect(sender.send(notice())).rejects.toBeInstanceOf(Unavailable);
		const events = recorded
			.lines()
			.slice(from)
			.map((l) => [l.event, l.fields.stage]);
		expect(events).toEqual([
			["mail-smtp.busy", undefined],
			["mail-smtp.unsent", "greeting"],
			["mail-smtp.unsent", "greeting"],
		]);
	});
});

describe("settings", () => {
	it("refuses to boot on a setting out of its form, naming the key and never the value", async () => {
		const wrong: Record<string, [object, string]> = {
			"no host": [{ host: undefined }, "mail-smtp.host"],
			"two mailboxes": [{ from: "a@example.test, b@example.test" }, "mail-smtp.from"],
			"no mailbox": [{ from: "nobody" }, "mail-smtp.from"],
			// Addresses mail refuses, after the display name is split off.
			"a % in the address": [{ from: "Provider <a%b@example.test>" }, "mail-smtp.from"],
			"a full-width letter": [{ from: "Provider <noreply@ｅxample.test>" }, "mail-smtp.from"],
			"a path after the domain": [{ from: "noreply@example.test/x" }, "mail-smtp.from"],
			"a user without a password": [{ user: "relay-user" }, "mail-smtp.password"],
			"a password without a user": [{ password }, "mail-smtp.user"],
			"a control character": [
				{ password: `${password}\r\n`, user: "relay-user" },
				"mail-smtp.password",
			],
			"plaintext beyond loopback": [{ host: "relay.example" }, "mail-smtp.security"],
			"plaintext to an address isIP does not read": [{ host: "127.0.0.08" }, "mail-smtp.security"],
			"port 0": [{ port: 0 }, "mail-smtp.port"],
			"a port past 65535": [{ port: 70_000 }, "mail-smtp.port"],
			"a deadline under 100 ms": [{ deadline: "99ms" }, "mail-smtp.deadline"],
			"a deadline past 10 minutes": [{ deadline: "601s" }, "mail-smtp.deadline"],
			"a deadline with no unit": [{ deadline: 2000 }, "mail-smtp.deadline"],
			"the deadline by its name in milliseconds": [{ "deadline-ms": 2000 }, "mail-smtp"],
			"a security it does not know": [{ security: "ssl" }, "mail-smtp.security"],
			"a key it does not know": [{ retries: 3 }, "mail-smtp"],
			"no send at once": [{ "concurrent-sends": 0 }, "mail-smtp.concurrent-sends"],
			"past 1000 sends at once": [{ "concurrent-sends": 1001 }, "mail-smtp.concurrent-sends"],
		};
		for (const [name, [more, where]] of Object.entries(wrong)) {
			const found = await refusals(section(25, more));
			expect(
				found.map((f) => f.where),
				name,
			).toEqual([where]);
			expect(JSON.stringify(found), name).not.toContain(password);
		}
	});

	it("allows plaintext to a host url-setting's isLoopbackName takes, and to no other", async () => {
		for (const host of [
			"LocalHost",
			"a.localhost",
			"localhost.",
			"127.0.0.1",
			"::1",
			"::ffff:127.0.0.1",
		]) {
			await expect(boot(section(25, { host })), host).resolves.toBeDefined();
		}
		for (const host of [
			"localhost.example",
			"127.0.0.08",
			"2130706433",
			"10.0.0.1",
			"::ffff:a00:1",
			// The connection takes the host as written, and Node reads a bracketed one as a name.
			"[::1]",
			"[::ffff:7f00:1]",
		]) {
			const found = await refusals(section(25, { host }));
			expect(
				found.map((f) => f.where),
				host,
			).toEqual(["mail-smtp.security"]);
		}
	});

	it("allows plaintext by the host alone, whatever NODE_ENV says", async () => {
		const before = process.env.NODE_ENV;
		try {
			for (const name of ["production", "development", "test"]) {
				process.env.NODE_ENV = name;
				await expect(boot(section(25, { host: "localhost" }))).resolves.toBeDefined();
				await expect(refusals(section(25, { host: "relay.example" }))).resolves.toHaveLength(1);
			}
		} finally {
			// Assigning undefined would leave the string "undefined".
			if (before === undefined) delete process.env.NODE_ENV;
			else process.env.NODE_ENV = before;
		}
	});

	it("warns once at boot when it sends in plaintext, with no value", async () => {
		const bootLines = async (more: object) => {
			const from = recorded.lines().length;
			await boot(section(25, more));
			return recorded.lines().slice(from);
		};
		const plaintext = await bootLines({ user: "relay-user", password });
		expect(plaintext).toEqual([{ level: "warn", event: "mail-smtp.plaintext", fields: {} }]);
		await expect(bootLines({ host: "localhost", security: "starttls" })).resolves.toEqual([]);
		await expect(bootLines({ host: "localhost", security: "tls" })).resolves.toEqual([]);
	});

	it("cannot be composed beside the logging-only sender", async () => {
		const both = assemble({
			modules: [smtp, mailModule, contractTemplates],
			config: { ...kernelConfig(), ...mailConfig(), "mail-smtp": section(25) },
			runtime,
		});
		await expect(both).rejects.toBeInstanceOf(BootRefused);
	});
});
