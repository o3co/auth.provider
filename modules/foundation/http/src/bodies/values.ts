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

/** A query's or a form's values, grouped by name in the order sent. */
export function paramsOf(search: URLSearchParams): Values {
	const grouped = Map.groupBy(search, ([name]) => name);
	return valuesOf(new Map([...grouped].map(([name, pairs]) => [name, pairs.map(([, v]) => v)])));
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
