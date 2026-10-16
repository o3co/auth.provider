import { z } from "zod";

export const section = z.strictObject({
	"lifetime-seconds": z
		.number()
		.int()
		.min(1)
		.max(31_536_000)
		.default(86_400)
		.describe(
			"How long a refresh token family lives, in seconds. Shorter is only safer, so the floor is a second, which lets tests watch a family run out.",
		),
	"sweep-seconds": z
		.number()
		.int()
		.min(1)
		.max(3600)
		.default(30)
		.describe("How often the sweep finishes revocations that stopped halfway, in seconds."),
	"bind-confidential-clients": z
		.boolean()
		.default(false)
		.describe(
			"Whether a confidential client's family is bound to its sender too. As 0.17's default: a confidential client already proves itself, so only a public one's is bound.",
		),
});

export type Settings = z.output<typeof section>;
