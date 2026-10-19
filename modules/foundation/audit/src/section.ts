import { z } from "zod";

/** Missing, empty or neither a list nor `none`: what to write instead. */
const nameOne =
	"name at least one receiver: `log`, one a composed module contributes (a generated app's README names them), or `none` to state that events go nowhere";

export const section = z.strictObject({
	receivers: z
		.union(
			[
				z.literal("none"),
				z
					.array(z.string().min(1))
					.min(1, nameOne)
					.refine((names) => new Set(names).size === names.length, "names must differ"),
			],
			{ error: nameOne },
		)
		.describe("The receivers events go to, by name, or `none` to state that events go nowhere."),
	"max-pending": z
		.number()
		.int()
		.min(1)
		.max(1_000_000)
		.prefault(1000)
		.describe("Each receiver's deliveries under way at once; an event past it is lost."),
});
