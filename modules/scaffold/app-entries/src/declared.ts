/**
 * The entries a package declares in its manifest's `appEntries`, read and checked: each names its
 * script, the shape it boots as, and the contract and member of the package's main entry the shape
 * drives. A declaration that cannot be read as one is refused, naming the package.
 */

/** What a package's manifest declares, as the caller read it. */
export interface Declaring {
	readonly name: string;
	readonly appEntries: unknown;
}

/** The shapes an entry may boot as, and the keys each takes beside `script`, `shape`, `contract` and `member`. */
const shapes = {
	call: [],
	"settle-subjects": ["answers"],
	"name-subjects": [],
} as const satisfies Record<string, readonly string[]>;

export type Shape = keyof typeof shapes;

/** An entry a package declares, checked. */
export interface Declared {
	readonly package: string;
	readonly script: string;
	readonly shape: Shape;
	readonly contract: string;
	readonly member: string;
	readonly answers?: readonly string[];
}

const scriptName = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/;
const identifier = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
const word = /^[a-z]+$/;
/** The names a settling shape counts by itself, beside the answers. */
const counted = ["unknown", "failed"];
const common = ["script", "shape", "contract", "member"];

const refused = (name: string, why: string): never => {
	throw new TypeError(`${name} declares appEntries that cannot be read: ${why}`);
};

function checked(name: string, item: unknown): Declared {
	if (typeof item !== "object" || item === null || Array.isArray(item)) {
		return refused(name, "an entry is not an object");
	}
	const given = item as Record<string, unknown>;
	const { script, shape, contract, member } = given;
	if (typeof script !== "string" || !scriptName.test(script) || script === "start") {
		return refused(name, "a script is not a lowercase name other than start");
	}
	if (typeof shape !== "string" || !Object.hasOwn(shapes, shape)) {
		return refused(name, `${script}'s shape is not one of ${Object.keys(shapes).join(", ")}`);
	}
	const keys: readonly string[] = [...common, ...shapes[shape as Shape]];
	const unknown = Object.keys(given).filter((key) => !keys.includes(key));
	if (unknown.length > 0) {
		return refused(name, `${script} has keys its shape does not take: ${unknown.join(", ")}`);
	}
	for (const [key, value] of [
		["contract", contract],
		["member", member],
	] as const) {
		if (typeof value !== "string" || !identifier.test(value)) {
			return refused(name, `${script}'s ${key} is not a name`);
		}
	}
	const entry = {
		package: name,
		script,
		shape: shape as Shape,
		contract: contract as string,
		member: member as string,
	};
	if (shape !== "settle-subjects") return entry;
	const { answers } = given;
	if (!Array.isArray(answers) || answers.length === 0) {
		return refused(name, `${script}'s answers are not a list of at least one`);
	}
	if (!answers.every((a): a is string => typeof a === "string" && word.test(a))) {
		return refused(name, `${script}'s answers are not each a lowercase word`);
	}
	if (new Set(answers).size < answers.length) {
		return refused(name, `${script} names an answer twice`);
	}
	if (answers.some((a) => counted.includes(a))) {
		return refused(
			name,
			`${script} names an answer the script counts itself (${counted.join(", ")})`,
		);
	}
	return { ...entry, answers: [...answers] };
}

/** The entries the packages declare, checked; a script declared twice is refused, naming both. */
export function declaredEntries(packages: readonly Declaring[]): Declared[] {
	const entries: Declared[] = [];
	for (const { name, appEntries } of packages) {
		if (appEntries === undefined) continue;
		if (!Array.isArray(appEntries)) refused(name, "appEntries is not a list");
		for (const item of appEntries as unknown[]) {
			const entry = checked(name, item);
			const twice = entries.find((e) => e.script === entry.script);
			if (twice !== undefined) {
				refused(name, `${entry.script} is declared by ${twice.package} too`);
			}
			entries.push(entry);
		}
	}
	return entries;
}
