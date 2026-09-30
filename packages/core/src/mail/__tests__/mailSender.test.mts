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
 * The `MailSender` port and its `mailSender` slot (the MFA ADR's D5), and
 * the recording sender tests use in its place.
 *
 * The port carries what a mail means — its purpose, the account, the
 * recipient, the code and its expiry — never rendered text. A send answers
 * `delivered` or `refused_at_limit`; an outage rejects.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import { createApp, defineModule, MAIL_PURPOSES } from "#/index.mjs";
import type { MailPurpose, MailSend, MailSender, MailSendResult } from "#/mail/types.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { createRecordingMailSender } from "#/testing/index.mjs";

const SEND: MailSend = {
	purpose: "login_code",
	subject: "user-1",
	to: "alice@example.com",
	code: "123456",
	expiresAtMs: Date.UTC(2026, 0, 1, 0, 10),
};

describe("the MailSender port", () => {
	it("hands a sender the purpose, the account, the recipient, the code and its expiry, and nothing rendered", () => {
		expectTypeOf<MailSend>().toEqualTypeOf<{
			readonly purpose: MailPurpose;
			readonly subject: string;
			readonly to: string;
			readonly code: string;
			readonly expiresAtMs: number;
		}>();
		expectTypeOf<MailSender["send"]>().toEqualTypeOf<(mail: MailSend) => Promise<MailSendResult>>();
		expect(true).toBe(true);
	});

	it("has three purposes, a closed list: the login code, the account-email proof and the email factor's enrollment code", () => {
		expect(MAIL_PURPOSES).toEqual(["login_code", "account_email_proof", "email_factor_enrollment"]);
		expect(Object.isFrozen(MAIL_PURPOSES)).toBe(true);
		expectTypeOf<MailPurpose>().toEqualTypeOf<
			"login_code" | "account_email_proof" | "email_factor_enrollment"
		>();
	});

	it("answers delivered or refused at a limit; an outage is a rejection, not an answer", () => {
		expectTypeOf<MailSendResult>().toEqualTypeOf<
			{ readonly outcome: "delivered" } | { readonly outcome: "refused_at_limit" }
		>();
		expect(true).toBe(true);
	});
});

describe("the mailSender slot", () => {
	it("is optional, and holds a MailSender", () => {
		expectTypeOf<ComponentMap["mailSender"]>().toEqualTypeOf<MailSender | undefined>();
		expect(true).toBe(true);
	});

	it("is filled by a module, and read by one", async () => {
		const sender = createRecordingMailSender();
		let seen: MailSender | undefined;
		const provider = defineModule({
			name: "test:mail-sender",
			provides: { mailSender: () => sender },
		});
		const reader = defineModule({
			name: "test:mail-reader",
			requires: ["mailSender"] as const,
			contributes: {
				routes: [
					(deps) => {
						seen = deps.mailSender;
						return {
							id: "test-mail-reader",
							mountPath: "/__test_mail_reader__",
							handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
						};
					},
				],
			},
		});
		const handle = await createApp({
			modules: [provider, reader],
			bootstrapComponents: {
				config: makeValidCoreConfig(),
				pathResolver: (p: string) => p,
			} as never,
		});
		try {
			expect(seen).toBe(sender);
		} finally {
			await handle.dispose();
		}
	});
});

describe("createRecordingMailSender", () => {
	it("delivers every send, keeping each, oldest first, as a frozen copy", async () => {
		const sender = createRecordingMailSender();
		expect(sender.kind).toBe("recording");
		const second = { ...SEND, to: "bob@example.com" };
		expect(await sender.send(SEND)).toEqual({ outcome: "delivered" });
		expect(await sender.send(second)).toEqual({ outcome: "delivered" });
		second.to = "mallory@example.com";
		expect(sender.sent).toStrictEqual([SEND, { ...SEND, to: "bob@example.com" }]);
		expect(Object.isFrozen(sender.sent)).toBe(true);
		expect(Object.isFrozen(sender.sent[0])).toBe(true);
	});

	it("stands in for a sender at a limit: answers refused_at_limit, and keeps nothing", async () => {
		const sender = createRecordingMailSender();
		sender.refuseAtLimit();
		expect(await sender.send(SEND)).toEqual({ outcome: "refused_at_limit" });
		expect(sender.sent).toEqual([]);
		sender.recover();
		expect(await sender.send(SEND)).toEqual({ outcome: "delivered" });
		expect(sender.sent).toStrictEqual([SEND]);
	});

	it("stands in for a relay that is down: rejects with the error it was given, and keeps nothing", async () => {
		const sender = createRecordingMailSender();
		const outage = new Error("relay unreachable");
		sender.failWith(outage);
		await expect(sender.send(SEND)).rejects.toBe(outage);
		await expect(sender.send(SEND)).rejects.toBe(outage);
		expect(sender.sent).toEqual([]);
		sender.recover();
		expect(await sender.send(SEND)).toEqual({ outcome: "delivered" });
		expect(sender.sent).toStrictEqual([SEND]);
	});

	it("follows the last instruction: a limit after a failure answers the limit, and a failure after a limit rejects", async () => {
		const sender = createRecordingMailSender();
		const outage = new Error("relay unreachable");
		sender.failWith(outage);
		sender.refuseAtLimit();
		expect(await sender.send(SEND)).toEqual({ outcome: "refused_at_limit" });
		sender.failWith(outage);
		await expect(sender.send(SEND)).rejects.toBe(outage);
		expect(sender.sent).toEqual([]);
	});
});
