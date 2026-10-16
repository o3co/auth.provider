import { z } from "zod";
import { thresholds } from "./log.ts";

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
						.default("info")
						.describe("the lowest level logged (trace to fatal), or silent for none"),
				},
				{ error: "holds only level" },
			)
			.default({ level: "info" })
			.describe("the log"),
		"stop-seconds": z
			.int(stopRange)
			.min(1, stopRange)
			.max(3600, stopRange)
			.default(30)
			.describe(
				"whole seconds a stop given no deadline waits for its hooks; an orchestrator's grace period must be longer",
			),
	},
	{ error: "needs a section holding only deployment, logging and stop-seconds" },
);

export type KernelSettings = z.output<typeof kernelSection>;
