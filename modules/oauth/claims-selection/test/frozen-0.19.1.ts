// Frozen from v0.19.1, modules/oauth/claims-selection/src/stored.ts (its record shapes and reads),
// with its limits.ts as literals: how a 0.19.x instance reads a record, for the mixed-fleet test.
// Never updated with claims-selection's own shapes; deleted with format 1's reads.
import { Unavailable } from "@mod/kernel";
import { z } from "zod";

const scalar = z.union([z.string().max(256), z.boolean(), z.number().refine(Number.isFinite)]);
const constraint = z
	.strictObject({
		name: z.string(),
		value: scalar.optional(),
		values: z.array(scalar).min(1).max(16).optional(),
	})
	.refine((c) => (c.value === undefined) !== (c.values === undefined));
const target = z.strictObject({
	names: z.array(z.strictObject({ name: z.string(), scope: z.string() })),
	constraints: z.array(constraint),
});
const selection = z.strictObject({ idToken: target, userinfo: target });

const opened = <T>(shape: z.ZodType<T>, kept: unknown): T => {
	const read = shape.safeParse(kept);
	if (!read.success) throw new Unavailable("claims-selection: a record it cannot read");
	return read.data;
};

/** v0.19.1's reads of a code's selection, a pin and a token's or family's target. */
export const readAt0191 = {
	code: (kept: unknown) => opened(z.strictObject({ format: z.literal(1), selection }), kept),
	pin: (kept: unknown) =>
		opened(z.strictObject({ format: z.literal(1), selection: selection.optional() }), kept),
	target: (kept: unknown) => opened(z.strictObject({ format: z.literal(1), target }), kept),
};
