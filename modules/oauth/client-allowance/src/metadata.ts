import type { Section } from "@mod/clients";
import { z } from "zod";

export interface Allowances {
	readonly grants: readonly string[];
	readonly scopes: readonly string[];
	readonly "default-scopes"?: readonly string[] | undefined;
	readonly audiences: readonly string[];
}

export const allowances: Section<Allowances> = {
	name: "client-allowance",
	schema: z.strictObject({
		grants: z.array(z.string()).default([]),
		scopes: z.array(z.string()).default([]),
		"default-scopes": z.array(z.string()).optional(),
		audiences: z.array(z.string()).default([]),
	}),
};
