import { z } from "zod";

/** Unset or another value: the choice an operator makes, each step taken once every host has taken the last. */
const chooseOne =
	"set `off` while any host runs a release before 0.19, which cannot hold a claims request's constraints, `draining` once every host runs 0.19, then `on` once every host is draining";

export const section = z.strictObject({
	mode: z
		.enum(["off", "draining", "on"], { error: chooseOne })
		.describe(
			"off takes no claims request and touches no store; draining keeps holding back what was kept, but keeps nothing new; on takes claims requests.",
		),
});

export type Settings = z.output<typeof section>;
