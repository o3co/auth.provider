import { z } from "zod";
import { showable } from "./name.ts";

export const section = z.strictObject({
	"user-verification": z
		.enum(["required", "preferred", "discouraged"])
		.prefault("preferred")
		.describe("Whether the authenticator is asked to verify its user, as WebAuthn says it."),
	"display-name": z
		.string()
		.refine(
			(name) => showable(name) !== undefined,
			"1 to 64 code points, no control or format character",
		)
		.prefault("Account")
		.describe(
			"The name an authenticator shows for an account with no name to show; it names no one.",
		),
});

export type Settings = z.output<typeof section>;
