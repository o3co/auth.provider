import { z } from "zod";

export const section = z.strictObject({
	"user-verification": z
		.enum(["required", "preferred", "discouraged"])
		.prefault("preferred")
		.describe("Whether the authenticator is asked to verify its user, as WebAuthn says it."),
	"max-credentials": z
		.number()
		.int()
		.min(1)
		.max(100)
		.prefault(10)
		.describe("The most passkeys a subject may hold, from 1 to 100."),
});

export type Settings = z.output<typeof section>;
