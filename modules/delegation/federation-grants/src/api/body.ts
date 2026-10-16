import type { HttpRequest } from "@mod/http";

/** Names a client's authentication may send in the body, which every route lets through. */
const credentials = ["client_id", "client_secret", "client_assertion", "client_assertion_type"];

export type Body =
	| {
			readonly kind: "read";
			text(name: string): string | undefined;
			number(name: string): number | undefined;
	  }
	| { readonly kind: "refused"; readonly description: string };

/** A whole number of at least zero, as JSON or as the digits of a form. */
const whole = (value: unknown) => {
	const n = typeof value === "string" && /^[0-9]{1,15}$/.test(value) ? Number(value) : value;
	return typeof n === "number" && Number.isSafeInteger(n) && n >= 0 ? n : undefined;
};

/**
 * A route's body, as a client's form or JSON object: only the names the route takes, each once,
 * text where it is text and a whole number where it is a number. The description names the field.
 */
export function bodyOf(
	request: HttpRequest,
	texts: readonly string[],
	numbers: readonly string[] = [],
): Body {
	const refused = (description: string) => ({ kind: "refused", description }) as const;
	// A JSON object's members are its fields and its mistyped names.
	const named = new Set([...request.fields.keys(), ...(request.mistyped ?? [])]);
	const allowed = new Set([...texts, ...numbers, ...credentials]);
	for (const name of named) {
		if (!allowed.has(name)) return refused("unexpected_parameter");
	}
	for (const name of request.fields.repeated()) {
		if (named.has(name)) return refused(`duplicate_${name}`);
	}
	for (const name of texts) {
		if (request.mistyped?.has(name)) return refused(`invalid_${name}`);
	}
	const read = new Map<string, number>();
	for (const name of numbers) {
		if (!named.has(name)) continue;
		const n = whole(request.json?.[name] ?? request.fields.single(name));
		if (n === undefined) return refused(`invalid_${name}`);
		read.set(name, n);
	}
	return {
		kind: "read",
		text: (name) => {
			const value = request.fields.single(name);
			return value === "" ? undefined : value;
		},
		number: (name) => read.get(name),
	};
}
