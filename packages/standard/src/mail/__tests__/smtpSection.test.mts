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
 * The SMTP mail sender's section, `standard-smtp-mail-sender`: named after
 * its module, its keys camelCase, its defaults in the package's
 * `reference.conf` alone, each key read from the variable its path names, an
 * unknown key refused by its name, plaintext only to localhost or a loopback
 * address in its canonical form, and no password quoted in any refusal. The
 * module declares the section and provides the SMTP sender, built only where
 * a module reads the slot; the testing entry's builder carries the section as
 * the reference defaults it.
 */

import { fileURLToPath } from "node:url";
import { BootError, createApp, defineModule, type MailSender } from "@o3co/auth-provider-core";
import {
	makeValidAppConfig,
	packageReferenceProblems,
	unreadableModuleLeaves,
} from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { afterEach, describe, expect, it } from "vitest";
import { standardSmtpMailSenderConfigSchema } from "#/mail/smtp/config.mjs";
import { standardSmtpMailSenderModule } from "#/mail/smtp/module.mjs";
import { standardSmtpMailSenderConfigForTests } from "#/testing/index.mjs";

const REFERENCE = new URL("../../../config/reference.conf", import.meta.url);

/** The section as the package's reference.conf resolves it under `env`, as a composition root layers it. */
const referenceSection = (env: Record<string, string> = {}): unknown =>
	(parseFile(fileURLToPath(REFERENCE), { env }).toObject() as Record<string, unknown>)[
		standardSmtpMailSenderModule.name
	];

const DEFAULTS = { port: 587, secure: "starttls" };

/** The issues' paths and codes the schema answers for `value`, or none. */
const refusedAt = (value: unknown): string[] =>
	(standardSmtpMailSenderConfigSchema.safeParse(value).error?.issues ?? []).map(
		(issue) => `${issue.path.map(String).join(".")}:${issue.code}`,
	);

describe("standard-smtp-mail-sender, the SMTP mail sender's section", () => {
	it("defaults to port 587 with STARTTLS, and to no host, account, password or sender address", () => {
		expect(standardSmtpMailSenderConfigSchema.parse(referenceSection())).toEqual(DEFAULTS);
	});

	it("reads each key from the variable its path names", () => {
		expect(
			standardSmtpMailSenderConfigSchema.parse(
				referenceSection({
					STANDARD_SMTP_MAIL_SENDER_HOST: "smtp.example.com",
					STANDARD_SMTP_MAIL_SENDER_PORT: "465",
					STANDARD_SMTP_MAIL_SENDER_SECURE: "tls",
					STANDARD_SMTP_MAIL_SENDER_USER: "mailer",
					STANDARD_SMTP_MAIL_SENDER_PASSWORD: "relay-password",
					STANDARD_SMTP_MAIL_SENDER_FROM: "Sign-in <no-reply@example.com>",
				}),
			),
		).toEqual({
			host: "smtp.example.com",
			port: 465,
			secure: "tls",
			user: "mailer",
			password: "relay-password",
			from: "Sign-in <no-reply@example.com>",
		});
	});

	it("refuses a key it does not know, at the section", () => {
		expect(refusedAt({ ...DEFAULTS, tls: true })).toEqual([":unrecognized_keys"]);
	});

	it("refuses a port outside 1-65535, and a mode other than starttls, tls or none", () => {
		for (const port of [1, 65_535, "25"]) {
			expect(refusedAt({ ...DEFAULTS, port }), String(port)).toEqual([]);
		}
		for (const port of [0, 65_536, 25.5, "0x19", "", null]) {
			expect(refusedAt({ ...DEFAULTS, port }), String(port)).not.toEqual([]);
		}
		expect(refusedAt({ ...DEFAULTS, secure: "ssl" })).toEqual(["secure:invalid_value"]);
	});

	it("takes plaintext only to localhost or a loopback address in its canonical form, and refuses it with no host", () => {
		for (const host of ["localhost", "LocalHost", "127.0.0.1", "127.0.0.2", "::1"]) {
			expect(refusedAt({ ...DEFAULTS, secure: "none", host }), host).toEqual([]);
		}
		// A resolver reads a spelling that is not an address's canonical form
		// as a name, which may resolve anywhere.
		for (const host of [
			"smtp.example.com",
			"127.0.0.08",
			"127.0.0.099",
			"127.000.000.001",
			"2130706433",
			"0x7f.0.0.1",
			"[::1]",
			"localhost.example.com",
		]) {
			expect(refusedAt({ ...DEFAULTS, secure: "none", host }), host).toEqual(["secure:custom"]);
		}
		expect(refusedAt({ ...DEFAULTS, secure: "none" })).toEqual(["secure:custom"]);
	});

	it("refuses a host, an account or a sender address that is blank or carries a control character", () => {
		for (const key of ["host", "user", "from"]) {
			for (const value of ["", "  ", "a\r\nb", "a\u0000b", "a\u0085b", 7]) {
				expect(
					refusedAt({ ...DEFAULTS, [key]: value }),
					`${key} ${JSON.stringify(value)}`,
				).not.toEqual([]);
			}
		}
	});

	it("quotes no password in any refusal the schema makes", () => {
		const password = "hunter2-relay-S3CRET";
		const section = {
			host: "\r\n",
			port: 0,
			secure: "none",
			user: "",
			password,
			from: 5,
			hostname: password,
		};
		const issues = standardSmtpMailSenderConfigSchema.safeParse(section).error?.issues ?? [];
		expect(issues.length).toBeGreaterThan(3);
		expect(JSON.stringify(issues.map((issue) => [issue.path, issue.message]))).not.toContain(
			"S3CRET",
		);
		const notAString = standardSmtpMailSenderConfigSchema.safeParse({
			...DEFAULTS,
			password: 123456789,
		});
		expect(JSON.stringify(notAString.error?.issues.map((issue) => issue.message))).not.toContain(
			"123456789",
		);
	});
});

describe("standardSmtpMailSenderConfigForTests, the testing entry's builder", () => {
	it("carries the section as the package's reference.conf defaults it, under the module's name", () => {
		expect(standardSmtpMailSenderConfigForTests()).toEqual({
			[standardSmtpMailSenderModule.name]: standardSmtpMailSenderConfigSchema.parse(
				referenceSection(),
			),
		});
	});

	it("lays the keys it is given over those defaults", () => {
		expect(standardSmtpMailSenderConfigForTests({ host: "localhost", secure: "none" })).toEqual({
			[standardSmtpMailSenderModule.name]: { ...DEFAULTS, host: "localhost", secure: "none" },
		});
	});
});

describe("standardSmtpMailSenderModule, which declares the section", () => {
	let disposable: { dispose(): Promise<void> } | undefined;
	afterEach(async () => {
		await disposable?.dispose();
		disposable = undefined;
	});

	/** A module that reads the slot, and the sender it was handed once a boot built it. */
	const readerOfTheSlot = () => {
		const seen: { sender?: MailSender } = {};
		const module = defineModule({
			name: "test:mail-reader",
			requires: ["mailSender"] as const,
			contributes: {
				routes: [
					(deps) => {
						seen.sender = deps.mailSender;
						return {
							id: "test-mail-reader",
							mountPath: "/__test_mail_reader__",
							handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
						};
					},
				],
			},
		});
		return { module, seen };
	};

	/** Boots the module, and `also`, over core's valid configuration with `section`, answering the refusal if any. */
	const boot = async (
		section: Record<string, unknown>,
		also: readonly ReturnType<typeof defineModule>[] = [],
	): Promise<unknown> => {
		try {
			disposable = await createApp({
				modules: [standardSmtpMailSenderModule, ...also],
				bootstrapComponents: {
					config: { ...makeValidAppConfig(), ...section },
					pathResolver: (p: string) => p,
				} as never,
			});
			return undefined;
		} catch (error) {
			return error;
		}
	};

	it("is named after its section, reads it at its name, and declares the package's reference.conf, which holds only its section", () => {
		expect(standardSmtpMailSenderModule.name).toBe("standard-smtp-mail-sender");
		expect(standardSmtpMailSenderModule.section).not.toHaveProperty("at");
		expect(standardSmtpMailSenderModule.section?.reference?.href).toBe(REFERENCE.href);
		expect(
			packageReferenceProblems({
				reference: REFERENCE,
				modules: [standardSmtpMailSenderModule],
				read: (path, env) => parseFile(path, { env: { ...env } }).toObject(),
			}),
		).toEqual([]);
		expect(unreadableModuleLeaves([standardSmtpMailSenderModule])).toEqual([]);
	});

	it("provides the mail sender, built only where something reads the slot, requires nothing and holds no state", () => {
		expect(Object.keys(standardSmtpMailSenderModule.provides ?? {})).toEqual(["mailSender"]);
		expect(standardSmtpMailSenderModule.lifecycle?.mailSender?.eager).not.toBe(true);
		expect(standardSmtpMailSenderModule.contributes).toBeUndefined();
		expect(standardSmtpMailSenderModule.requires ?? []).toEqual([]);
		expect(standardSmtpMailSenderModule.replicaSafety).toBeUndefined();
	});

	it("boots with the section as the reference defaults it where nothing reads the slot", async () => {
		expect(await boot(standardSmtpMailSenderConfigForTests())).toBeUndefined();
	});

	it("fills the slot with the SMTP sender where a module reads it", async () => {
		const reader = readerOfTheSlot();
		expect(
			await boot(
				standardSmtpMailSenderConfigForTests({
					host: "smtp.example.com",
					from: "Sign-in <no-reply@example.com>",
				}),
				[reader.module],
			),
		).toBeUndefined();
		expect(reader.seen.sender?.kind).toBe("standard-smtp");
	});

	it("refuses the boot where a module reads the slot and the section cannot send, naming the key and its variable and quoting no password", async () => {
		const refused = await boot(
			standardSmtpMailSenderConfigForTests({
				from: "Sign-in <no-reply@example.com>",
				user: "mailer",
				password: "hunter2-relay-S3CRET",
			}),
			[readerOfTheSlot().module],
		);
		expect(refused).toBeInstanceOf(BootError);
		expect((refused as BootError).message).toContain(
			"standard-smtp-mail-sender.host (STANDARD_SMTP_MAIL_SENDER_HOST)",
		);
		expect((refused as BootError).message).not.toContain("S3CRET");
	});

	it("refuses the boot for a key its section does not know, naming the section and the key, and quoting no password", async () => {
		const refused = await boot(
			standardSmtpMailSenderConfigForTests({
				hostname: "smtp.example.com",
				password: "hunter2-relay-S3CRET",
				port: 0,
			} as never),
		);
		expect(refused).toBeInstanceOf(BootError);
		expect((refused as BootError).reason).toBe("config-validation-failed");
		expect((refused as BootError).message).toContain(
			"standard-smtp-mail-sender: has a key it does not know: hostname",
		);
		expect((refused as BootError).message).not.toContain("S3CRET");
	});

	it("refuses the boot where a module reads the slot and the password is empty, as though it were not set, naming the password's key", async () => {
		const refused = await boot(
			standardSmtpMailSenderConfigForTests({
				host: "smtp.example.com",
				from: "Sign-in <no-reply@example.com>",
				user: "mailer",
				password: "",
			}),
			[readerOfTheSlot().module],
		);
		expect(refused).toBeInstanceOf(BootError);
		expect((refused as BootError).message).toContain(
			"standard-smtp-mail-sender.password (STANDARD_SMTP_MAIL_SENDER_PASSWORD)",
		);
	});
});
