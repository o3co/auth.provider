import { z } from "zod";

export const section = z.strictObject({
	mode: z
		.enum(["off", "draining", "on"])
		.prefault("off")
		.describe(
			"off takes no claims request and touches no store; draining keeps holding back what was kept, but keeps nothing new; on takes claims requests.",
		),
});

export type Settings = z.output<typeof section>;
