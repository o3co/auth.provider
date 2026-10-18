/** A zod schema as far as the walk reads its definition, and the Standard Schema it validates through. */
export interface Node {
	readonly _zod: { readonly def: Def };
	readonly "~standard": {
		validate(value: unknown): Result | Promise<Result>;
	};
}

interface Result {
	readonly value?: unknown;
	readonly issues?: readonly { readonly params?: { readonly problem?: string } }[];
}

interface Def {
	readonly type: string;
	readonly shape?: Readonly<Record<string, Node>>;
	readonly innerType?: Node;
	readonly in?: Node;
	readonly out?: Node;
	readonly left?: Node;
	readonly right?: Node;
	readonly element?: Node;
	readonly valueType?: Node;
	readonly options?: readonly Node[];
	readonly defaultValue?: unknown;
}

/** One node of a section's schema: the key path it is under, and whether it is the key's own schema. */
export interface Placed {
	readonly node: Node;
	readonly path: readonly string[];
	readonly key: boolean;
}

/** Every node of a schema; a list's element and a map's value are under `*`. A lazy schema is not walked into. */
export function nodesOf(node: Node, path: readonly string[], key = false): Placed[] {
	const d = node._zod.def;
	const keys = Object.entries(d.shape ?? {}).flatMap(([name, child]) =>
		nodesOf(child, [...path, name], true),
	);
	const items = [d.element, d.valueType].flatMap((child) =>
		child ? nodesOf(child, [...path, "*"]) : [],
	);
	const inner = [d.innerType, d.in, d.out, d.left, d.right, ...(d.options ?? [])].flatMap(
		(child) => (child ? nodesOf(child, path) : []),
	);
	return [{ node, path, key }, ...keys, ...items, ...inner];
}

/** What a node makes of a value; a check that throws on it, rather than reporting, refuses it. */
const resultOf = async (node: Node, value: unknown): Promise<Result> => {
	try {
		return await node["~standard"].validate(value);
	} catch {
		return { issues: [{}] };
	}
};

/** Whether a value passes the node's validation. */
export const accepts = async (node: Node, value: unknown) =>
	(await resultOf(node, value)).issues === undefined;

/** Whether the node reads a time or a size written with its unit into a number, as kernel's `setting` does. */
export async function readsUnits(node: Node): Promise<boolean> {
	for (const written of ["1s", "1KiB", "1d"]) {
		const read = await resultOf(node, written);
		if (read.issues === undefined && typeof read.value === "number") return true;
	}
	return false;
}

/** Whether the node refuses a value naming no unit: a bare number, or a string of one as an environment variable gives. */
export const refusesUnitless = async (node: Node) =>
	!(await accepts(node, 1)) && !(await accepts(node, "1"));
