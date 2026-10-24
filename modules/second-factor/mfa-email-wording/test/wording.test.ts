import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { type MailTemplate, mailTemplates } from "@mod/mail";
import { purposes } from "@mod/mfa-email";
import { expect, it } from "vitest";
import wordingModule from "../src/module.ts";

const templates = contract<readonly MailTemplate[]>("templates");
const reader = defineModule({ name: "reader", takes: [mailTemplates] }, (m) => [
	m.provide(templates).by((c) => c.collect(mailTemplates)),
]);

it("words each purpose mfa-email sends, in English plain text taking the code and the minutes", async () => {
	const app = await assemble({
		modules: [wordingModule, reader],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	const given = app.get(templates);
	expect(given.map((t) => t.purpose).sort()).toEqual(Object.values(purposes).sort());
	for (const template of given) {
		const rendered = template.render({ code: "C0DE", minutes: "7" });
		expect(rendered.text, template.purpose).toContain("C0DE");
		expect(rendered.text, template.purpose).toContain("7 minute");
		expect(rendered.subject.length, template.purpose).toBeGreaterThan(0);
	}
});

it("takes all it names", async () => {
	const input = {
		modules: [wordingModule, reader],
		config: kernelConfig(),
		runtime: quietRuntime(),
	};
	expect(await takesUnused(input)).toEqual({});
});
