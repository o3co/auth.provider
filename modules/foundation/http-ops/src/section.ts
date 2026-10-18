import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	"readiness-deadline": setting
		.duration("ms")
		.pipe(
			z
				.number()
				.int()
				.min(1)
				.max(2 ** 31 - 1),
		)
		.prefault("1s")
		.describe(
			"How long `GET /readyz` waits for the probes before it answers unready, in whole milliseconds (`1s`); set it below the orchestrator's own timeout for the check.",
		),
});
