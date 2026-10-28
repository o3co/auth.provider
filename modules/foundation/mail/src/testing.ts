import { inspect } from "node:util";
import { BootRefused, defineModule, isUnavailable, type Module } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { z } from "zod";
import { type Mail, type Message, mailPurposes, mailTemplates, plainText } from "./contract.ts";
import type { section } from "./section.ts";

export type MailSettings = z.input<typeof section>;

/** The mail part of a test's configuration: the logging-only sender, accepted. */
export function mailConfig(settings: Partial<MailSettings> = {}) {
	return { mail: { "accept-unsent": true, ...settings } };
}

/** Declares the purposes the contract tests send, with their templates. */
export const contractTemplates: Module = defineModule(
	{ name: "mail-contract", replicaSafe: true, takes: [] },
	(m) => [
		m.contribute(mailPurposes).by(() => ({ purpose: "contract.notice" })),
		m.contribute(mailPurposes).by(() => ({ purpose: "contract.broken" })),
		m.contribute(mailPurposes).by(() => ({ purpose: "contract.broken-text" })),
		m
			.contribute(mailTemplates)
			.by(() => plainText("contract.notice", { subject: "Notice", text: "Value: {value}\n" })),
		m.contribute(mailTemplates).by(() => ({
			purpose: "contract.broken",
			render: () => ({ subject: "two\nlines", text: "" }),
		})),
		m.contribute(mailTemplates).by(() => ({
			purpose: "contract.broken-text",
			render: () => ({ subject: "Notice", text: "one\rtwo" }),
		})),
	],
);

/** What a refusing remote side says; no failure may carry it. */
export const remoteWords = "mail-contract-remote-words";

export interface MailHarness {
	/** The sender, assembled with `modules` beside it. */
	boot(modules: readonly Module[]): Promise<Mail>;
	/**
	 * The same, but its remote side answers every send with a limit or fails ("down"), saying
	 * `remoteWords`. A sender with no remote side leaves it out.
	 */
	refusing?(how: "limit" | "down", modules: readonly Module[]): Promise<Mail>;
}

/** The mail contract, run against any sender. */
export function mailContract(name: string, harness: MailHarness): void {
	const notice = (more: Partial<Message> = {}): Message => ({
		purpose: "contract.notice",
		to: "someone@example.test",
		values: { value: "1" },
		...more,
	});
	const open = () => harness.boot([contractTemplates]);
	const refused = (sender: Mail, more: Partial<Message>, label?: string) =>
		expect(sender.send(notice(more)), label).rejects.toBeInstanceOf(TypeError);

	describe(`mail contract: ${name}`, () => {
		it("sends one message to one address for a declared purpose", async () => {
			const sender = await open();
			await expect(sender.send(notice())).resolves.toMatch(/^(sent|limited)$/);
		});

		it("sends a message whose expiry is ahead", async () => {
			const sender = await open();
			await expect(sender.send(notice({ expiresAt: Number.MAX_SAFE_INTEGER }))).resolves.toMatch(
				/^(sent|limited)$/,
			);
		});

		it("is unavailable once the message has expired", async () => {
			const sender = await open();
			await expect(sender.send(notice({ expiresAt: 1 }))).rejects.toSatisfy(isUnavailable);
		});

		it("refuses anything but one address", async () => {
			const sender = await open();
			const notOneAddress: Record<string, string> = {
				"a list": "a@example.test, b@example.test",
				"a header after a line break": "a@example.test\r\nBcc: b@example.test",
				empty: "",
				"no local part": "example.test",
				"two at signs": "a@b@example.test",
				"a display form": "<a@example.test>",
			};
			for (const [label, to] of Object.entries(notOneAddress)) await refused(sender, { to }, label);
		});

		it("refuses a domain that IDNA reads as another string", async () => {
			const sender = await open();
			const misread: Record<string, string> = {
				"a path": "a@victim.test/x",
				"a query": "a@victim.test?x",
				"a fragment": "a@victim.test#x",
				"a backslash": "a@victim.test\\x",
				"a port": "a@victim.test:25",
				"full-width letters and dot":
					"a@\uff56\uff49\uff43\uff54\uff49\uff4d\uff0e\uff54\uff45\uff53\uff54",
				"a full-width dot": "a@victim\uff0etest",
				"a compatibility letter": "a@\u212fxample.test",
				"a ligature": "a@\ufb01.test",
				"decomposed letters": "a@u\u0308ber.test",
				"a character IDNA drops": "a@ex\u034fample.test",
				"an underscore": "a@ex_ample.test",
				"a trailing dot": "a@example.test.",
				"an empty label": "a@example..test",
			};
			for (const [label, to] of Object.entries(misread)) await refused(sender, { to }, label);
		});

		it("refuses an address that could reach another mailbox or hide a character", async () => {
			const sender = await open();
			const unsafe: Record<string, string> = {
				"a percent route": "a%b@example.test",
				"a bang route": "b!a@example.test",
				"an encoded word": "=?utf-8?b?YUBiLnRlc3Q=?=@example.test",
				"a zero-width space": "a\u200b@example.test",
				"a direction override": "a\u202e@example.test",
				"a lone surrogate": "a\ud800@example.test",
				"over 254 bytes in UTF-8": `${"\u00fc".repeat(121)}@example.test`,
			};
			for (const [label, to] of Object.entries(unsafe)) await refused(sender, { to }, label);
		});

		it("refuses values that are not plain strings and a locale that is not a string", async () => {
			const sender = await open();
			const odd: Record<string, unknown> = {
				"a value that is not a string": { values: { value: 1 } },
				"values with a prototype": {
					values: Object.assign(Object.create({ inherited: "1" }), { value: "1" }),
				},
				"a locale that is not a string": { locale: 7 },
			};
			for (const [label, more] of Object.entries(odd)) {
				await refused(sender, more as Partial<Message>, label);
			}
		});

		it("refuses an undeclared purpose and a template whose subject is not one line", async () => {
			const sender = await open();
			await refused(sender, { purpose: "contract.other" });
			await refused(sender, { purpose: "contract.broken" });
		});

		it("refuses a template whose text holds control characters", async () => {
			const sender = await open();
			await refused(sender, { purpose: "contract.broken-text" });
		});

		it.skipIf(!harness.refusing)(
			"answers limited at a limit and Unavailable otherwise, never with the remote side's words",
			async () => {
				const refusing = async (how: "limit" | "down") => {
					// skipIf keeps this from running without the hook; the check only narrows the type.
					if (!harness.refusing) throw new Error("the harness injects no failure");
					return harness.refusing(how, [contractTemplates]);
				};
				await expect((await refusing("limit")).send(notice())).resolves.toBe("limited");
				const failure = await (await refusing("down")).send(notice()).catch((e: unknown) => e);
				expect(isUnavailable(failure)).toBe(true);
				expect(inspect(failure)).not.toContain(remoteWords);
			},
		);

		it("refuses to boot when a declared purpose has no template", async () => {
			const bare = defineModule(
				{ name: "mail-contract-bare", replicaSafe: true, takes: [] },
				(m) => [m.contribute(mailPurposes).by(() => ({ purpose: "contract.bare" }))],
			);
			await expect(harness.boot([bare])).rejects.toSatisfy(BootRefused.is);
		});
	});
}
