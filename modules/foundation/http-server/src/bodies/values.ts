import { type Values, valuesOf } from "../contract.ts";

/**
 * Form encoding's decoding, `+` a space and a `%` without two hex digits kept, but fatal: undefined
 * when the escaped bytes are not well-formed UTF-8, where URLSearchParams would put U+FFFD.
 */
function decoded(text: string): string | undefined {
	try {
		return decodeURIComponent(text.replaceAll("+", " ").replace(/%(?![0-9A-Fa-f]{2})/g, "%25"));
	} catch {
		return undefined;
	}
}

/** A query's or a form's values, grouped by name in the order sent; undefined when one is not UTF-8. */
export function paramsOf(text: string): Values | undefined {
	const pairs: [string, string][] = [];
	for (const sequence of text.split("&")) {
		if (sequence === "") continue;
		const at = sequence.indexOf("=");
		const name = decoded(at === -1 ? sequence : sequence.slice(0, at));
		const value = decoded(at === -1 ? "" : sequence.slice(at + 1));
		if (name === undefined || value === undefined) return undefined;
		pairs.push([name, value]);
	}
	const grouped = Map.groupBy(pairs, ([name]) => name);
	return valuesOf(new Map([...grouped].map(([name, named]) => [name, named.map(([, v]) => v)])));
}
