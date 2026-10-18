import { setting } from "@mod/kernel";
import { z } from "zod";

const lifetime = z.number().int().min(1).max(31_536_000);
/** A family's lifetime where the section names neither key, in seconds. */
const lifetimeDefault = 86_400;

export const section = z
	.strictObject({
		lifetime: setting
			.duration("s")
			.pipe(lifetime)
			.optional()
			.describe(
				"How long a refresh token family lives, from `1s` to `365d` in whole seconds; `1d` unless set. Shorter is only safer, so the floor is a second, which lets tests watch a family run out.",
			),
		// Read until every writer names lifetime, then removed.
		"lifetime-seconds": lifetime.optional().describe("Replaced by `lifetime`; read until 0.18.0."),
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
	})
	.refine((s) => s.lifetime === undefined || s["lifetime-seconds"] === undefined, {
		message: "lifetime replaces lifetime-seconds: write one",
	})
	.transform(({ "lifetime-seconds": old, ...s }) => ({
		...s,
		lifetime: s.lifetime ?? old ?? lifetimeDefault,
	}));

export type Settings = z.output<typeof section>;
