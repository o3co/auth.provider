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
 * The port is in core because its implementer (an SMTP package) and its
 * consumer (the MFA package) must not depend on each other. It takes a
 * rendered message and resolves only when the relay accepted it: a delivery
 * that failed is never "sent".
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import { createApp, defineModule } from "#/index.mjs";
import type { MailMessage, MailSender } from "#/mail/types.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { createRecordingMailSender } from "#/testing/index.mjs";

const MESSAGE: MailMessage = {
	to: "alice@example.com",
	subject: "Your sign-in code",
	text: "Your code is 123456. It expires in 10 minutes.",
};

describe("the mailSender slot (D5)", () => {
	it("is optional, and holds a MailSender", () => {
		expectTypeOf<ComponentMap["mailSender"]>().toEqualTypeOf<MailSender | undefined>();
		expectTypeOf<MailSender["send"]>().toEqualTypeOf<(message: MailMessage) => Promise<void>>();
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
	it("records every message it accepts, oldest first, as copies", async () => {
		const sender = createRecordingMailSender();
		expect(sender.kind).toBe("recording");
		const second = { ...MESSAGE, to: "bob@example.com" };
		await sender.send(MESSAGE);
		await sender.send(second);
		second.to = "mallory@example.com";
		expect(sender.sent).toStrictEqual([MESSAGE, { ...MESSAGE, to: "bob@example.com" }]);
		expect(Object.isFrozen(sender.sent)).toBe(true);
	});

	it("stands in for a relay that is down: rejects with the error it was given, and records nothing", async () => {
		const sender = createRecordingMailSender();
		const outage = new Error("relay unreachable");
		sender.failWith(outage);
		await expect(sender.send(MESSAGE)).rejects.toBe(outage);
		await expect(sender.send(MESSAGE)).rejects.toBe(outage);
		expect(sender.sent).toEqual([]);
		sender.recover();
		await sender.send(MESSAGE);
		expect(sender.sent).toStrictEqual([MESSAGE]);
	});
});
