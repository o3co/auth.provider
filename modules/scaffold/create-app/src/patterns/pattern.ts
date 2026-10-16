import type { Selection } from "@mod/combinations";

/** The groups a pattern's features fall in, each overridden whole by the operator's flag of that name. */
export const groups = ["login", "second-factor", "grants", "client-auth", "binding"] as const;
export type Group = (typeof groups)[number];
const isGroup = (name: string): name is Group => (groups as readonly string[]).includes(name);

/** A deployment's use, and the selection that composes it. */
export interface Pattern {
	readonly name: string;
	/** One paragraph: the generated guide opens with it. */
	readonly use: string;
	/** Axis owner → its adapter, or the owner itself; an axis left out keeps full's default. */
	readonly axes: Readonly<Record<string, string>>;
	/** The features that decide the use; what they need comes with them. */
	readonly features: Readonly<Partial<Record<Group, readonly string[]>>>;
	/** The conformance areas run against the pattern's app. */
	readonly areas: readonly string[];
	/** Features conformance adds for the pattern's run alone, so its core is under test; reviewed, kept small. */
	readonly conformanceAdd: readonly string[];
}

/** What the operator changes: axes over the pattern's, groups in place of its, features added. */
export interface Choice {
	readonly axes?: Readonly<Record<string, string>>;
	readonly features?: Readonly<Record<string, readonly string[]>>;
	readonly add?: readonly string[];
}

/** The features every pattern composes; the foundations come with what needs them. */
const common = [
	"@mod/issuer",
	"@mod/discovery",
	"@mod/tokens",
	"@mod/sender-binding",
	"@mod/token-endpoint",
	"@mod/token-control",
	"@mod/clients",
	"@mod/subject-revocation",
	"@mod/subject-tokens",
];

/** The store kept in this process: safe on one instance only. */
const memoryStore = "@mod/store";

/** The pattern's selection with the operator's choice; a group not known is refused, naming it. */
export function selectionOf(pattern: Pattern, choice: Choice = {}): Selection {
	const unknown = Object.keys(choice.features ?? {}).filter((group) => !isGroup(group));
	if (unknown.length > 0) {
		throw new Error(`${unknown.join(", ")}: not a group (${groups.join(", ")})`);
	}
	return {
		features: { common, ...pattern.features, ...choice.features },
		axes: { ...pattern.axes, ...choice.axes },
		add: choice.add ?? [],
	};
}

/** Whether the selection's store lives in the process, so the deployment runs as one instance. */
export const oneInstance = (selection: Selection) => selection.axes?.[memoryStore] === memoryStore;
