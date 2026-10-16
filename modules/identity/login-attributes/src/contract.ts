import { type UserAttributes, userAttribute } from "@mod/users";
import { z } from "zod";

/** Attributes in the namespace of who stated them, named by the login that passes them. */
export interface SourcedAttributes {
	readonly source: string;
	/** Users' named set, by those names, and nothing else; an `email` alone is not verified. */
	readonly values: UserAttributes;
}

/** The sources logins name their attributes by: users' ledger, and an upstream by its IdP. */
export const loginSource = Object.freeze({
	users: "users",
	/** Never equal to `users`, whatever the IdP's name. */
	upstream: (idp: string) => `upstream:${idp}` as const,
} as const);

/** What keeping a login's attributes gives: the kept copy, or none, and what it left out. */
export interface AttributesKept {
	readonly kept: SourcedAttributes | undefined;
	/** The named attributes dropped, and `source` when the source dropped them all; never a value. */
	readonly dropped: readonly string[];
	/** How many names outside the named set were given. */
	readonly others: number;
}

export { keptAttributes } from "./keeping/keeping.ts";

/** The form a kept copy is read back in, by name and type only: its caps are judged by keeping it again. */
export const sourcedAttributesShape = z.strictObject({
	source: z.string(),
	values: z.strictObject({
		[userAttribute.email]: z.string().optional(),
		[userAttribute.emailVerified]: z.boolean().optional(),
		[userAttribute.name]: z.string().optional(),
		[userAttribute.picture]: z.string().optional(),
		[userAttribute.groups]: z.array(z.string()).optional(),
	}),
});
