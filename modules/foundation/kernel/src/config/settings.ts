import { z } from "zod";
import { thresholds } from "../runtime/log.ts";
import { setting } from "../setting/setting.ts";

const stopRange = { error: "whole seconds from 1 to 3600" };

export const kernelSection = z.strictObject(
	{
		deployment: z
			.enum(["single", "multi"], { error: "single or multi" })
			.describe("single or multi; multi refuses a module unsafe on multiple instances"),
		logging: z
			.strictObject(
				{
					level: z
						.enum(thresholds, { error: thresholds.join(", ") })
						.prefault("info")
						.describe("the lowest level logged (trace to fatal), or silent for none"),
				},
				{ error: "holds only level" },
			)
			.prefault({})
			.describe("the log"),
		"stop-deadline": setting
			.duration("s")
			.pipe(z.int(stopRange).min(1, stopRange).max(3600, stopRange))
			.prefault("30s")
			.describe(
				"how long a stop given no deadline waits for its hooks, from `1s` to `1h` in whole seconds; an orchestrator's grace period must be longer",
			),
	},
	{ error: "needs a section holding only deployment, logging and stop-deadline" },
);

export type KernelSettings = z.output<typeof kernelSection>;
