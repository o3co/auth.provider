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

/** The claims the table releases from `attributes` for the scope words that match a row exactly. */
export function claimsOf(
	attributes: Readonly<Record<string, unknown>>,
	scope: readonly string[],
): Readonly<Record<string, Claim>> {
	const released: Record<string, Claim> = {};
	for (const row of [...new Set(scope)].flatMap((word) => table.get(word) ?? [])) {
		const value = Object.hasOwn(attributes, row.attribute)
			? row.read(attributes[row.attribute])
			: undefined;
		if (value !== undefined) released[row.claim] = value;
	}
	return Object.freeze(released);
}
