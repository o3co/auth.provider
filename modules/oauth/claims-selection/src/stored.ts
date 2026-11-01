import { Unavailable } from "@mod/kernel";
import { z } from "zod";
import type { Selection, Target } from "./contract.ts";
import { selectionLimits } from "./limits.ts";
import type { StoredSelection } from "./store.ts";

const scalar = z.union([
	z.string().max(selectionLimits.valueLength),
	z.boolean(),
	z.number().refine(Number.isFinite),
]);
const constraint = z
	.strictObject({
		name: z.string(),
		value: scalar.optional(),
		values: z.array(scalar).min(1).max(selectionLimits.values).optional(),
	})
	// Exactly one: with neither, it would hold back its claim whatever the claim holds.
	.refine((c) => (c.value === undefined) !== (c.values === undefined));
const target = z.strictObject({
	names: z.array(z.strictObject({ name: z.string(), scope: z.string() })),
	constraints: z.array(constraint),
});
const selection = z.strictObject({ idToken: target, userinfo: target });

/** Whether a selection holds only scalar values within the bounds, and is small enough whole. */
export function withinLimits(asked: Selection): boolean {
	return (
		selection.safeParse(asked).success &&
		Buffer.byteLength(JSON.stringify(asked)) <= selectionLimits.bytes
	);
}

/** Whether a target asks for anything: a name to release or a constraint to hold. */
export const holds = (t: Target) => t.names.length > 0 || t.constraints.length > 0;

// Each record writes format 1, and reads only it: one of another format or shape fails the read.
const codeRecord = z.strictObject({ format: z.literal(1), selection });
const pinRecord = z.strictObject({ format: z.literal(1), selection: selection.optional() });
const targetRecord = z.strictObject({ format: z.literal(1), target });

const opened = <T>(shape: z.ZodType<T>, kept: StoredSelection): T => {
	const read = shape.safeParse(kept);
	// One it cannot read holds back what it may constrain: never taken for none, and answered as
	// one the place cannot tell, as a read that fails is.
	if (!read.success) throw new Unavailable("claims-selection: a record it cannot read");
	return read.data;
};

export const stored = {
	code: (s: Selection) => ({ format: 1, selection: s }) as unknown as StoredSelection,
	pin: (s: Selection | undefined) =>
		({ format: 1, ...(s ? { selection: s } : {}) }) as unknown as StoredSelection,
	target: (t: Target) => ({ format: 1, target: t }) as unknown as StoredSelection,
};

export const read = {
	code: (kept: StoredSelection): Selection => opened(codeRecord, kept).selection as Selection,
	pin: (kept: StoredSelection): Selection | undefined =>
		opened(pinRecord, kept).selection as Selection | undefined,
	target: (kept: StoredSelection): Target => opened(targetRecord, kept).target as Target,
};
