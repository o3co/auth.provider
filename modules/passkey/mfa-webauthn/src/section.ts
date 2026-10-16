import { z } from "zod";
import { showable } from "./name.ts";

export const section = z.strictObject({
	"user-verification": z.enum(["required", "preferred", "discouraged"]).default("preferred"),
	/** The name an authenticator shows for an account with no name to show; it names no one. */
	"display-name": z
		.string()
		.refine(
			(name) => showable(name) !== undefined,
			"1 to 64 code points, no control or format character",
		)
		.default("Account"),
});

export type Settings = z.output<typeof section>;
