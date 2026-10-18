import { z } from "zod";

export const section = z.strictObject({
	receivers: z
		.union([
			z.literal("none"),
			z
				.array(z.string().min(1))
				.min(1)
				.refine((names) => new Set(names).size === names.length, "names must differ"),
		])
		.describe("The receivers events go to, by name, or `none` to state that events go nowhere."),
	"max-pending": z
		.number()
		.int()
		.min(1)
		.max(1_000_000)
		.prefault(1000)
		.describe("Each receiver's deliveries under way at once; an event past it is lost."),
});
