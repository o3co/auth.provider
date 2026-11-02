import { z } from "zod";

/** The claims the grant's own policy decides, which no condition names. */
const decided = ["iss", "aud", "exp", "nbf", "iat", "jti"];

const value = z.union([z.string(), z.number(), z.boolean()]);

/** An issuer's conditions on an assertion's verified claims, each predicate to hold. */
export const conditionsSetting = z
	.strictObject({
		"subject-prefix": z
			.string()
			.regex(/^[\x21-\x7e]{1,255}$/, "1 to 255 printable ASCII characters")
			.refine((prefix) => !prefix.startsWith("REPLACE-"), "a sample left in place")
			.optional()
			.describe("A prefix the verified `sub` starts with, compared as written."),
		claims: z
			.record(z.string(), z.union([value, z.array(value).min(1)]))
			.refine((claims) => Object.keys(claims).length > 0, "names no claim")
			.refine(
				(claims) => Object.keys(claims).every((name) => !decided.includes(name)),
				`names a claim the grant's policy decides (${decided.join(", ")})`,
			)
			.optional()
			.describe(
				"Each claim's value, or a list of values one of which it holds: a string, a number or a boolean, compared by kind and as written.",
			),
	})
	.refine((c) => c["subject-prefix"] !== undefined || c.claims !== undefined, "holds no condition")
	.describe(
		"Conditions an assertion's verified claims meet, all of them: `subject-prefix` and `claims`.",
	);

export type Conditions = z.output<typeof conditionsSetting>;

/** Whether verified claims meet every condition; a claim is read as the claims' own alone. */
export function meets(conditions: Conditions, claims: Readonly<Record<string, unknown>>): boolean {
	const prefix = conditions["subject-prefix"];
	if (prefix !== undefined) {
		const sub = Object.hasOwn(claims, "sub") ? claims.sub : undefined;
		if (typeof sub !== "string" || !sub.startsWith(prefix)) return false;
	}
	for (const [name, wanted] of Object.entries(conditions.claims ?? {})) {
		if (!Object.hasOwn(claims, name)) return false;
		const held = claims[name];
		if (!(Array.isArray(wanted) ? wanted : [wanted]).some((w) => w === held)) return false;
	}
	return true;
}
