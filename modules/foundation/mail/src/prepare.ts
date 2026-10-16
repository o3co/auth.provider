import { type BuildContext, Unavailable } from "@mod/kernel";
import { isAddress } from "./address.ts";
import { type Message, mailPurposes, mailTemplates } from "./contract.ts";
import { bodyControls, controls } from "./lines.ts";

export interface Prepared {
	readonly message: Message;
	readonly subject: string;
	readonly text: string;
}

function fail(reason: string): never {
	throw new TypeError(`mail: ${reason}`);
}

/** An object whose prototype is Object.prototype or null. */
function isPlainObject(value: unknown): value is object {
	if (value === null || typeof value !== "object") return false;
	const proto = Object.getPrototypeOf(value);
	return proto === Object.prototype || proto === null;
}

/** A frozen copy of the message, or a TypeError when it is not one address and string values. */
function checkedCopy(message: Message): Message {
	const { purpose, to, values, locale, expiresAt } = message;
	if (typeof purpose !== "string") fail("the purpose is a string");
	if (!isAddress(to)) fail("to is one address");
	if (locale !== undefined && typeof locale !== "string") fail("the locale is a string");
	if (expiresAt !== undefined && !Number.isFinite(expiresAt)) fail("expiresAt is a time");
	if (!isPlainObject(values)) fail("values are a plain object");
	const entries = Object.entries(values);
	if (entries.some(([, v]) => typeof v !== "string")) fail("values are strings");
	return Object.freeze({
		purpose,
		to,
		values: Object.freeze(Object.fromEntries(entries)),
		...(locale !== undefined && { locale }),
		...(expiresAt !== undefined && { expiresAt }),
	});
}

/**
 * For a sender, at build: refuses boot when a declared purpose has no template. The function it
 * gives copies and checks a message, and renders it; it throws a TypeError for a bad message and
 * Unavailable once expired, synchronously, so call it inside the async send.
 * Every sender sends only what it returns.
 */
export async function preparer<S>(c: BuildContext<S>): Promise<(message: Message) => Prepared> {
	const templates = new Map((await c.collect(mailTemplates)).map((t) => [t.purpose, t]));
	const declared = new Set((await c.collect(mailPurposes)).map((p) => p.purpose));
	const missing = [...declared].filter((p) => !templates.has(p));
	if (missing.length > 0) {
		c.refuse("mail.templates", `no template for ${missing.join(", ")}`);
	}
	return (input) => {
		const message = checkedCopy(input);
		const template = declared.has(message.purpose) ? templates.get(message.purpose) : undefined;
		if (!template) fail(`the purpose ${message.purpose} is not declared`);
		if (message.expiresAt !== undefined && c.clock.now() >= message.expiresAt) {
			throw new Unavailable("mail");
		}
		const { subject, text } = template.render(message.values, message.locale);
		if (typeof subject !== "string" || subject === "" || controls.test(subject)) {
			fail(`the template for ${message.purpose} gave a subject that is not one line`);
		}
		if (typeof text !== "string" || bodyControls.test(text)) {
			fail(`the template for ${message.purpose} gave text with control characters`);
		}
		return Object.freeze({ message, subject, text });
	};
}
