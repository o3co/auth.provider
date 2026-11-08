import { Unavailable } from "@mod/kernel";

/** cjson turns empty or sparse Lua arrays into objects; rebuild them by count. */
export function list<T>(value: unknown, n: number): T[] {
	return Array.from({ length: n }, (_, i) => (value as Record<number, T>)[i] as T);
}

/** A whole number as a script writes one: a string of digits, or a number cjson wrote; undefined for anything else. */
const whole = (value: unknown) => {
	const n =
		typeof value === "string" && /^-?\d+$/.test(value)
			? Number(value)
			: typeof value === "number"
				? value
				: undefined;
	return n !== undefined && Number.isSafeInteger(n) ? n : undefined;
};

/**
 * Script answers carry numbers as strings; turn the known ones back into numbers (the fields
 * the store scripts answer). One that is no whole number makes the answer none: the store is unavailable.
 */
function numbers<A extends Record<string, unknown>>(answer: A): A {
	const out: Record<string, unknown> = { ...answer };
	for (const field of ["now", "remainingMs", "resetAt", "count"]) {
		if (!Object.hasOwn(out, field) || out[field] === null) continue;
		const n = whole(out[field]);
		if (n === undefined) throw new Unavailable("store");
		out[field] = n;
	}
	return out as A;
}

/** The JSON a text holds, or undefined where it holds none. */
const parsed = (text: string) => {
	try {
		return JSON.parse(text);
	} catch {
		return undefined;
	}
};

/**
 * A script's reply, the server's run id, a line feed, then the answer as a JSON object: the
 * server, and the answer with its numbers read, in the shape its script writes. Any other reply
 * is none: the store is unavailable.
 */
export function answerOf(reply: string) {
	const split = reply.indexOf("\n");
	const answer = split < 0 ? undefined : parsed(reply.slice(split + 1));
	if (answer === null || typeof answer !== "object" || Array.isArray(answer)) {
		throw new Unavailable("store");
	}
	return { server: reply.slice(0, split), answer: numbers(answer) };
}
