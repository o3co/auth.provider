import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	lifetime: setting
		.duration("s")
		.pipe(z.number().int().min(1).max(31_536_000))
		.prefault("1d")
		.describe(
			"How long a refresh token family lives, from `1s` to `365d` in whole seconds. Shorter is only safer, so the floor is a second, which lets tests watch a family run out.",
		),
	"sweep-interval": setting
		.duration("s")
		.pipe(z.number().int().min(1).max(3600))
		.prefault("30s")
		.describe(
			"How often the sweep finishes revocations that stopped halfway, from `1s` to `1h` in whole seconds.",
		),
	"bind-confidential-clients": z
		.boolean()
		.prefault(false)
		.describe(
			"Whether a confidential client's family is bound to its sender too. As 0.17's default: a confidential client already proves itself, so only a public one's is bound.",
		),
});

export type Settings = z.output<typeof section>;
