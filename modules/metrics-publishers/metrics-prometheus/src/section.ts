import { z } from "zod";

export const section = z.strictObject({
	path: z
		.string()
		.regex(/^\/[^\s?#\p{Cc}]*$/u, "a path from /, with no query, fragment, space or control")
		.refine((path) => !path.endsWith("/*"), "a single path, not one ending in /*")
		.prefault("/metrics")
		.describe(
			"Where the scrape route answers: a path from `/`, not ending in `/*`, with no query, fragment, whitespace or control character.",
		),
});
