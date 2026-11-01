import type { Constraint, Target } from "@mod/claims-selection";
import { type UserAttributes, userAttribute } from "@mod/users";
import type { Claim } from "../contract.ts";

/** One claim: users' attribute it is read from, and the value it takes from it (undefined: left out). */
interface Row {
	readonly claim: string;
	readonly attribute: keyof UserAttributes;
	readonly read: (value: unknown) => Claim | undefined;
}

const text = (value: unknown) => (typeof value === "string" ? value : undefined);
const flag = (value: unknown) => (typeof value === "boolean" ? value : undefined);
const texts = (value: unknown) =>
	Array.isArray(value)
		? Object.freeze(value.filter((item): item is string => typeof item === "string"))
		: undefined;

const table = new Map<string, readonly Row[]>([
	[
		"profile",
		[
			{ claim: "name", attribute: userAttribute.name, read: text },
			{ claim: "picture", attribute: userAttribute.picture, read: text },
		],
	],
	[
		"email",
		[
			{ claim: "email", attribute: userAttribute.email, read: text },
			{ claim: "email_verified", attribute: userAttribute.emailVerified, read: flag },
		],
	],
	["groups", [{ claim: "groups", attribute: userAttribute.groups, read: texts }]],
]);

/** The scopes the table releases claims for, in the table's order. */
export const tableScopes: readonly string[] = Object.freeze([...table.keys()]);

/** The claims the table can release, in the table's order. */
export const tableClaims: readonly string[] = Object.freeze(
	[...table.values()].flatMap((rows) => rows.map((row) => row.claim)),
);

/** Each table claim's scope, by claim. */
const scopeByClaim = new Map(
	[...table].flatMap(([scope, rows]) => rows.map((row) => [row.claim, scope] as const)),
);

/** The scope a table claim belongs to; none for a claim outside the table. */
export const scopeOfClaim = (claim: string): string | undefined => scopeByClaim.get(claim);

/** Whether a released value holds its constraint: equal, type and all, to the value or one of the values; a list never does. */
const holds = (value: Claim, constraint: Constraint) =>
	!Array.isArray(value) &&
	(constraint.value !== undefined
		? value === constraint.value
		: (constraint.values ?? []).includes(value as string | boolean));

/**
 * The claims the table releases from `attributes` for the scope words that match a row exactly,
 * and for the table claims `asked` names; then, of all of them, those its constraints do not hold
 * back (OpenID Connect Core §5.5.1).
 */
export function claimsOf(
	attributes: Readonly<Record<string, unknown>>,
	scope: readonly string[],
	asked?: Target,
): Readonly<Record<string, Claim>> {
	const named = (asked?.names ?? [])
		.map(({ name }) => name)
		.filter((claim) => scopeByClaim.has(claim));
	const rows = [
		...[...new Set(scope)].flatMap((word) => table.get(word) ?? []),
		...[...table.values()].flat().filter((row) => named.includes(row.claim)),
	];
	const released: Record<string, Claim> = {};
	for (const row of rows) {
		const value = Object.hasOwn(attributes, row.attribute)
			? row.read(attributes[row.attribute])
			: undefined;
		if (value !== undefined) released[row.claim] = value;
	}
	for (const constraint of asked?.constraints ?? []) {
		const value = Object.hasOwn(released, constraint.name) ? released[constraint.name] : undefined;
		if (value !== undefined && !holds(value, constraint)) delete released[constraint.name];
	}
	return Object.freeze(released);
}
