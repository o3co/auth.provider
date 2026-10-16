import { z } from "zod";

export const section = z.strictObject({
	/** Whether a code by mail adds `mfa`; by default it is a second factor of its own amr only. */
	"adds-second-factor": z.boolean().default(false),
	/** How long a code by mail lives, for an enrolment or a sign-in; the proof before a first binding keeps its ten minutes. */
	"code-seconds": z.number().int().min(60).max(1800).default(600),
});

export type Settings = z.output<typeof section>;
