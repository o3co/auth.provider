const throwOnWrite = () => {
	throw new TypeError("a request is read-only");
};

/** A map whose writes throw; freezing a Map does not stop them. */
export function readOnly<K, V>(map: Map<K, V>): ReadonlyMap<K, V> {
	return Object.freeze(
		Object.assign(map, { set: throwOnWrite, delete: throwOnWrite, clear: throwOnWrite }),
	);
}

/** Values received under names (query, form, fields): read-only, in the order sent. */
export interface Values extends ReadonlyMap<string, readonly string[]> {
	/** The value when the name holds exactly one; undefined when it is absent or repeated. */
	single(name: string): string | undefined;
	/** The names holding more than one value, in order; empty when none. */
	repeated(): readonly string[];
}

export function valuesOf(map: ReadonlyMap<string, readonly string[]>): Values {
	const values = new Map([...map].map(([name, list]) => [name, Object.freeze([...list])]));
	const single = (name: string) => {
		const list = values.get(name);
		return list?.length === 1 ? list[0] : undefined;
	};
	const repeated = () =>
		Object.freeze([...values].filter(([, list]) => list.length > 1).map(([name]) => name));
	return Object.freeze(
		Object.assign(values, {
			set: throwOnWrite,
			delete: throwOnWrite,
			clear: throwOnWrite,
			single,
			repeated,
		}),
	);
}

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

/**
 * A JSON object's string members, as fields, and the names of its other members, as mistyped (none
 * when every member is a string). Neither can be written to.
 */
export function fieldsOf(json: Readonly<Record<string, unknown>>) {
	const members = Object.entries(json);
	const strings = members.flatMap(([name, value]) =>
		typeof value === "string" ? [[name, [value]] as const] : [],
	);
	const others = members.filter(([, value]) => typeof value !== "string").map(([name]) => name);
	const fields = valuesOf(new Map(strings));
	const mistyped: ReadonlySet<string> | undefined =
		others.length === 0
			? undefined
			: Object.freeze(
					Object.assign(new Set(others), {
						add: throwOnWrite,
						delete: throwOnWrite,
						clear: throwOnWrite,
					}),
				);
	return { fields, ...(mistyped ? { mistyped } : {}) };
}
