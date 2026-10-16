import type { MailTemplate, MailValues, Rendered } from "./contract.ts";
import { controls } from "./lines.ts";

const placeholder = /\{([A-Za-z][A-Za-z0-9_-]*)\}/g;

function fill(pattern: string, values: MailValues): string {
	return pattern.replace(placeholder, (_, name: string) => {
		const value = Object.hasOwn(values, name) ? values[name] : undefined;
		if (value === undefined) throw new TypeError(`mail: no value for {${name}}`);
		if (controls.test(value)) throw new TypeError(`mail: the value for {${name}} breaks a line`);
		return value;
	});
}

/**
 * A plain-text template with one wording (English by default) for every locale. Each `{name}` is
 * replaced by that value as it is, in one pass.
 */
export function plainText(purpose: string, wording: Rendered): MailTemplate {
	const { subject, text } = wording;
	return Object.freeze({
		purpose,
		render: (values: MailValues) => ({ subject: fill(subject, values), text: fill(text, values) }),
	});
}
