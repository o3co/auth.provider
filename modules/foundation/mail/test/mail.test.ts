import {
	assemble,
	BootRefused,
	defineModule,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, recordingLog, takesUnused } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import {
	canonicalAddress,
	isAddress,
	mail,
	mailPurposes,
	mailTemplates,
	plainText,
	preparer,
	preparerTakes,
} from "../src/contract.ts";
import mailModule from "../src/module.ts";
import { section } from "../src/section.ts";
import { contractTemplates, mailConfig, mailContract, remoteWords } from "../src/testing.ts";

const recorded = recordingLog();
const runtime = quietRuntime({
	random: { bytes: (n: number) => new Uint8Array(n).fill(7) },
	log: recorded.log,
});
const bootWith = async (sender: Module, modules: readonly Module[], config: object) =>
	(
		await assemble({
			modules: [sender, ...modules],
			config: { ...kernelConfig(), ...config },
			runtime,
		})
	).get(mail);
const boot = (modules: readonly Module[], config: object = mailConfig()) =>
	bootWith(mailModule, modules, config);

mailContract("logging only", { boot });

/** A stand-in relay: it accepts, answers with a limit, or fails saying the remote words. */
async function relay(how?: "limit" | "down"): Promise<"accepted" | "limit"> {
	if (how === "down") throw new Error(`554 ${remoteWords}`);
	return how ?? "accepted";
}

/** A sender through the stand-in relay that allows one mail per address and then answers limited. */
const onePerAddress = (how?: "limit" | "down") =>
	defineModule({ name: "one-per-address", takes: preparerTakes }, (m) => [
		m.provide(mail).by(async (c) => {
			const prepare = await preparer(c);
			const reached = new Set<string>();
			return {
				send: async (input) => {
					const { message } = prepare(input);
					const answer = await relay(how).catch(() => {
						throw new Unavailable("mail");
					});
					if (answer === "limit" || reached.has(message.to)) return "limited";
					reached.add(message.to);
					return "sent";
				},
			};
		}),
	]);

mailContract("one mail per address", {
	boot: (modules) => bootWith(onePerAddress(), modules, {}),
	refusing: (how, modules) => bootWith(onePerAddress(how), modules, {}),
});

const reset = defineModule({ name: "reset-owner", takes: [] }, (m) => [
	m.contribute(mailPurposes).by(() => ({ purpose: "reset" })),
	m
		.contribute(mailTemplates)
		.by(() => plainText("reset", { subject: "Reset", text: "Your code is {code}." })),
]);

it("logs the purpose, a hash of the address and the value names, never the values", async () => {
	const sender = await boot([reset]);
	const from = recorded.lines().length;
	await expect(
		sender.send({ purpose: "reset", to: "someone@example.test", values: { code: "424242" } }),
	).resolves.toBe("sent");
	const lines = recorded.lines().slice(from);
	expect(lines).toHaveLength(1);
	const [line] = lines;
	expect([line?.level, line?.event]).toEqual(["info", "mail.not_sent"]);
	expect(line?.fields).toMatchObject({ purpose: "reset", values: "code" });
	expect(line?.fields?.to).toMatch(/^[0-9a-f]{16}$/);
	expect(JSON.stringify(line)).not.toMatch(/424242|someone|example/);
});

it("takes a domain in IDNA's ASCII form or its Unicode form, in either case", async () => {
	const sender = await boot([reset]);
	const send = (to: string) => sender.send({ purpose: "reset", to, values: { code: "1" } });
	for (const to of [
		"a@Example.TEST",
		"a@\u4f8b\u3048.jp",
		"a@xn--r8jz45g.jp",
		"a@stra\u00dfe.de",
		"a@1.2.3.4",
	]) {
		await expect(send(to), to).resolves.toBe("sent");
	}
});

it("accepts letters beyond ASCII and up to 254 bytes in UTF-8, and refuses one byte more", async () => {
	const sender = await boot([reset]);
	const send = (to: string) => sender.send({ purpose: "reset", to, values: { code: "1" } });
	await expect(send("\u00fc@\u4f8b\u3048.jp")).resolves.toBe("sent");
	await expect(send(`${"\u00fc".repeat(32)}@example.test`)).resolves.toBe("sent");
	const domain = (last: number) => [..."bcd"].map((c) => c.repeat(61)).concat("e".repeat(last));
	// 64 + 1 + 61 * 3 + 3 + 3 = 254 bytes.
	await expect(send(`${"a".repeat(64)}@${domain(3).join(".")}`)).resolves.toBe("sent");
	await expect(send(`${"a".repeat(64)}@${domain(4).join(".")}`)).rejects.toBeInstanceOf(TypeError);
});

it("holds a local part to 64 bytes, and a domain's ASCII form to 63 octets a label and 253 in all", () => {
	expect(isAddress(`${"\u00fc".repeat(32)}@example.test`)).toBe(true);
	expect(isAddress(`${"\u00fc".repeat(32)}a@example.test`)).toBe(false);
	expect(isAddress(`a@${"b".repeat(63)}.test`)).toBe(true);
	expect(isAddress(`a@${"b".repeat(64)}.test`)).toBe(false);
	// A label beyond ASCII is longer in its ASCII form: 55 letters and one more make 63 octets there.
	const label = (n: number) => `${"a".repeat(n)}\u00fc`;
	expect(isAddress(`a@${label(55)}.test`)).toBe(true);
	expect(isAddress(`a@${label(56)}.test`)).toBe(false);
	// Labels of 63 octets each: 63 * 3 + 3 + 61 = 253 in ASCII form, one more past it.
	const three = [label(55), label(55), label(55)];
	expect(isAddress(`a@${[...three, "f".repeat(61)].join(".")}`)).toBe(true);
	const past = `a@${[...three, "f".repeat(62)].join(".")}`;
	expect(Buffer.byteLength(past)).toBeLessThan(254);
	expect(isAddress(past)).toBe(false);
});

it("refuses to boot unless the operator accepts that nothing is sent, and on many instances", async () => {
	await expect(boot([reset], { mail: {} })).rejects.toBeInstanceOf(BootRefused);
	await expect(
		boot([reset], { ...kernelConfig({ deployment: "multi" }), ...mailConfig() }),
	).rejects.toBeInstanceOf(BootRefused);
	await expect(boot([contractTemplates])).resolves.toBeDefined();
});

it("names the purpose that has no template when it refuses to boot", async () => {
	const bare = defineModule({ name: "bare-owner", takes: [] }, (m) => [
		m.contribute(mailPurposes).by(() => ({ purpose: "bare" })),
	]);
	const booting = boot([bare]);
	await expect(booting).rejects.toBeInstanceOf(BootRefused);
	await expect(booting).rejects.toMatchObject({
		refusals: [{ where: "mail.templates", reason: expect.stringContaining("bare") }],
	});
});

it("fills the plain-text wording literally, the same for every locale", () => {
	const t = plainText("p", { subject: "Code {code}", text: "Use {code} before {until}.\n" });
	const values = { code: "{until}", until: "noon" };
	expect(t.render(values)).toEqual({ subject: "Code {until}", text: "Use {until} before noon.\n" });
	expect(t.render(values, "ja")).toEqual(t.render(values));
});

it("refuses a missing value and a value that breaks a line", () => {
	const t = plainText("p", { subject: "Code {code}", text: "Use {code} before {until}.\n" });
	expect(() => t.render({ code: "1" })).toThrow(TypeError);
	expect(() => t.render({ code: "1\r\nBcc: x", until: "noon" })).toThrow(TypeError);
});

it("answers by the same rule for a sender's own addresses", () => {
	expect(["a@example.test", "a@\u4f8b\u3048.jp"].map(isAddress)).toEqual([true, true]);
	const refused = [
		"a@victim.test/x",
		"Name <a@example.test>",
		"a@example.test, b@example.test",
		7,
		"a@xn--a.example",
	];
	expect(refused.map(isAddress)).toEqual([false, false, false, false, false]);
});

it("puts an address in one form: its domain in IDNA's ASCII form, lowercase, its local part as given", () => {
	expect(canonicalAddress("Ann.B@Example.TEST")).toBe("Ann.B@example.test");
	expect(canonicalAddress("a@\u4f8b\u3048.JP")).toBe("a@xn--r8jz45g.jp");
	expect(canonicalAddress("a@xn--r8jz45g.jp")).toBe(canonicalAddress("a@\u4f8b\u3048.jp"));
	for (const refused of ["a@victim.test/x", "Name <a@example.test>", "no-at-sign"]) {
		expect(canonicalAddress(refused), refused).toBeUndefined();
	}
});

it("refuses the logging-only sender unless the operator accepts that it sends nothing", () => {
	expect(section.parse({})).toEqual({ "accept-unsent": false });
});

it("takes every handle its takes name", async () => {
	const config = { ...kernelConfig(), ...mailConfig() };
	expect(
		(await takesUnused({ modules: [mailModule, contractTemplates], config })).mail,
	).toBeUndefined();
});
