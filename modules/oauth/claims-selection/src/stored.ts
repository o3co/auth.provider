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

/** Each record's name, by its kind: a code's selection, a pin, a family's target, a token's. */
export const nameOf = {
	code: (redemption: string) => `c.${redemption}`,
	pin: (redemption: string) => `p.${redemption}`,
	family: (familyId: string) => `f.${familyId}`,
	token: (tokenId: string) => `t.${tokenId}`,
};

/** A record's kind and what it was named for, from its name; none for a name of no kind. */
export const kindOf = (name: string) => {
	const kind = (Object.keys(nameOf) as (keyof typeof nameOf)[]).find((k) =>
		name.startsWith(nameOf[k]("")),
	);
	return kind === undefined ? undefined : { kind, of: name.slice(nameOf[kind]("").length) };
};

/**
 * A record's shape in either format: 2 keeps its subject, so erasure finds whose it is; 1, as 0.19
 * wrote it, keeps none. One of another format or shape fails the read.
 * TODO(0.22): drop format 1 for a code, a pin and a token. A family's target keeps reading it until
 * the first release past refresh's family-lifetime ceiling after the last 0.19 instance stopped.
 */
const recordOf = <S extends z.ZodRawShape>(shape: S) =>
	z.union([
		z.strictObject({ format: z.literal(1), ...shape }),
		z.strictObject({ format: z.literal(2), subject: z.string(), ...shape }),
	]);
const codeRecord = recordOf({ selection });
const pinRecord = recordOf({ selection: selection.optional() });
const targetRecord = recordOf({ target });

const opened = <T>(shape: z.ZodType<T>, kept: StoredSelection): T => {
	const read = shape.safeParse(kept);
	// One it cannot read holds back what it may constrain: never taken for none, and answered as
	// one the place cannot tell, as a read that fails is.
	if (!read.success) throw new Unavailable("claims-selection: a record it cannot read");
	return read.data;
};

/** Each record written in format 2, with its subject. */
export const stored = {
	code: (s: Selection, subject: string) =>
		({ format: 2, subject, selection: s }) as unknown as StoredSelection,
	pin: (s: Selection | undefined, subject: string) =>
		({ format: 2, subject, ...(s ? { selection: s } : {}) }) as unknown as StoredSelection,
	target: (t: Target, subject: string) =>
		({ format: 2, subject, target: t }) as unknown as StoredSelection,
};

/** A record's own subject: format 2's; none for format 1. */
const subjectOf = (r: { readonly format: 1 } | { readonly format: 2; readonly subject: string }) =>
	r.format === 2 ? r.subject : undefined;

/** Each record read, with its own subject where it keeps one. */
export const read = {
	code: (kept: StoredSelection) => {
		const r = opened(codeRecord, kept);
		return { selection: r.selection as Selection, subject: subjectOf(r) };
	},
	pin: (kept: StoredSelection) => {
		const r = opened(pinRecord, kept);
		return { selection: r.selection as Selection | undefined, subject: subjectOf(r) };
	},
	target: (kept: StoredSelection) => {
		const r = opened(targetRecord, kept);
		return { target: r.target as Target, subject: subjectOf(r) };
	},
};
