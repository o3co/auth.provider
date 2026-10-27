import { z } from "zod";

/** Unset or another value: the choice an operator makes, through an upgrade and after it. */
const chooseOne =
	"set `off` while any host runs a release before 0.19, which cannot hold a claims request's constraints, then `on` once every host runs 0.19; `draining` before going back";

export const section = z.strictObject({
	mode: z
		.enum(["off", "draining", "on"], { error: chooseOne })
		.describe(
			"off takes no claims request and touches no store; draining keeps holding back what was kept, but keeps nothing new; on takes claims requests.",
		),
});

export type Settings = z.output<typeof section>;
