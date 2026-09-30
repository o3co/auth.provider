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
 * The SMTP mail sender's section, `smtp-mail-sender` (the MFA ADR's D5, D19
 * and D20, in #728's shape): named after its module, its keys camelCase, its
 * defaults in the package's `reference.conf` alone, each key read from the
 * variable its path names, an unknown key refused, and plaintext only to a
 * loopback host. The module is declared before its sender is built: it
 * provides nothing.
 */

import { fileURLToPath } from "node:url";
import { BootError, createApp } from "@o3co/auth-provider-core";
import {
	makeValidAppConfig,
	packageReferenceProblems,
	unreadableModuleLeaves,
} from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { afterEach, describe, expect, it } from "vitest";
import { smtpMailSenderConfigSchema } from "#/config.mjs";
import * as entry from "#/index.mjs";
import { smtpMailSenderModule } from "#/module.mjs";

const REFERENCE = new URL("../../config/reference.conf", import.meta.url);

/** The package's reference.conf resolved under `env`, as a composition root layers it. */
const resolved = (env: Record<string, string> = {}) =>
	parseFile(fileURLToPath(REFERENCE), { env }).toObject() as Record<
		string,
		Record<string, unknown>
	>;

const DEFAULTS = { port: 587, secure: "starttls" };

/** The issues' paths and codes the schema answers for `value`, or none. */
const refusedAt = (value: unknown): string[] =>
	(smtpMailSenderConfigSchema.safeParse(value).error?.issues ?? []).map(
		(issue) => `${issue.path.map(String).join(".")}:${issue.code}`,
	);

describe("smtp-mail-sender, the SMTP mail sender's section", () => {
	it("defaults to port 587 with STARTTLS, and to no host, account or sender address", () => {
		expect(smtpMailSenderConfigSchema.parse(resolved()["smtp-mail-sender"])).toEqual(DEFAULTS);
	});

	it("reads each key from the variable its path names", () => {
		const section = resolved({
			SMTP_MAIL_SENDER_HOST: "smtp.example.com",
			SMTP_MAIL_SENDER_PORT: "465",
			SMTP_MAIL_SENDER_SECURE: "tls",
			SMTP_MAIL_SENDER_USER: "mailer",
			SMTP_MAIL_SENDER_PASSWORD: "relay-password",
			SMTP_MAIL_SENDER_FROM: "Sign-in <no-reply@example.com>",
		})["smtp-mail-sender"];
		expect(smtpMailSenderConfigSchema.parse(section)).toEqual({
			host: "smtp.example.com",
			port: 465,
			secure: "tls",
			user: "mailer",
			password: "relay-password",
			from: "Sign-in <no-reply@example.com>",
		});
	});

	it("refuses a key it does not know, at its path", () => {
		expect(refusedAt({ ...DEFAULTS, tls: true })).toEqual([":unrecognized_keys"]);
	});

	it("refuses a port outside 1-65535, and a mode other than starttls, tls or none", () => {
		for (const port of [0, 65_536, 25.5, "0x19"]) {
			expect(refusedAt({ ...DEFAULTS, port }), String(port)).not.toEqual([]);
		}
		expect(refusedAt({ ...DEFAULTS, secure: "ssl" })).not.toEqual([]);
	});

	it("takes plaintext only to localhost or a loopback address in its canonical form, and refuses it with no host", () => {
		for (const host of ["localhost", "127.0.0.1", "127.0.0.2", "::1"]) {
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
			for (const value of ["", "  ", "a\r\nb", "a\u0000b"]) {
				expect(
					refusedAt({ ...DEFAULTS, [key]: value }),
					`${key} ${JSON.stringify(value)}`,
				).not.toEqual([]);
			}
		}
	});
});

describe("smtpMailSenderModule, declared before its sender is built", () => {
	let disposable: { dispose(): Promise<void> } | undefined;
	afterEach(async () => {
		await disposable?.dispose();
		disposable = undefined;
	});

	const configWith = (section: Record<string, unknown>) => ({
		...makeValidAppConfig(),
		"smtp-mail-sender": section,
	});

	it("is named after its section, reads it at its name, and declares the package's reference.conf, which holds only its section", () => {
		expect(smtpMailSenderModule.name).toBe("smtp-mail-sender");
		expect(smtpMailSenderModule.section?.at).toBeUndefined();
		expect(smtpMailSenderModule.section?.reference?.href).toBe(REFERENCE.href);
		expect(
			packageReferenceProblems({
				reference: REFERENCE,
				modules: [smtpMailSenderModule],
				read: (path, env) => parseFile(path, { env: { ...env } }).toObject(),
			}),
		).toEqual([]);
		expect(unreadableModuleLeaves([smtpMailSenderModule])).toEqual([]);
	});

	it("provides nothing, requires nothing and holds no state", () => {
		expect(smtpMailSenderModule.provides).toBeUndefined();
		expect(smtpMailSenderModule.contributes).toBeUndefined();
		expect(smtpMailSenderModule.requires ?? []).toEqual([]);
		expect(smtpMailSenderModule.replicaSafety).toBeUndefined();
	});

	it("boots with its defaults, and refuses the boot for a key its section does not know, naming its path", async () => {
		disposable = await createApp({
			modules: [smtpMailSenderModule],
			bootstrapComponents: {
				config: configWith(DEFAULTS),
				pathResolver: (p: string) => p,
			} as never,
		});
		await disposable.dispose();
		disposable = undefined;
		let refused: unknown;
		try {
			disposable = await createApp({
				modules: [smtpMailSenderModule],
				bootstrapComponents: {
					config: configWith({ ...DEFAULTS, hostname: "smtp.example.com" }),
					pathResolver: (p: string) => p,
				} as never,
			});
		} catch (error) {
			refused = error;
		}
		expect(refused).toBeInstanceOf(BootError);
		expect((refused as BootError).reason).toBe("config-validation-failed");
		expect((refused as BootError).message).toContain(
			"smtp-mail-sender: has a key it does not know: hostname",
		);
	});

	it("is the package's entry: the module and its section's schema, and nothing else", () => {
		expect(Object.keys(entry).sort()).toEqual([
			"smtpMailSenderConfigSchema",
			"smtpMailSenderModule",
		]);
	});
});
