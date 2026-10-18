import { z } from "zod";

export const section = z.strictObject({
	"accept-unsent": z
		.boolean()
		.prefault(false)
		.describe(
			"Whether to accept that the logging-only sender sends nothing; without it, boot is refused.",
		),
});
