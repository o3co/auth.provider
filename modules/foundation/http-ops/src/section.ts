import { z } from "zod";

export const section = z.strictObject({
	"readiness-deadline-ms": z
		.number()
		.int()
		.min(1)
		.max(2 ** 31 - 1)
		.default(1000)
		.describe(
			"How long `GET /readyz` waits for the probes before it answers unready, in whole milliseconds; set it below the orchestrator's own timeout for the check.",
		),
});
