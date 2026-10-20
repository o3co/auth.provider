import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	"adds-second-factor": z
		.boolean()
		.prefault(false)
		.describe(
			"Whether a code by mail adds `mfa` and so meets a required second factor; by default it is a way back of its own amr only.",
		),
	"code-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(60).max(1800))
		.prefault("10m")
		.describe(
			"How long a code by mail lives, from 1m to 30m, for an enrolment or a sign-in; the proof before a first binding keeps its ten minutes.",
		),
});

export type Settings = z.output<typeof section>;
