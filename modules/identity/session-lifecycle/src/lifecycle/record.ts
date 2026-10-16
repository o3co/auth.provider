import { sourcedAttributesShape } from "@mod/login-attributes";
import type { AuthContext } from "@mod/session";
import { z } from "zod";
import type { StoredSession } from "../store.ts";

type Full = AuthContext & {
	readonly openedAt: number;
	/** When closing began, and when a sweep may next go on with it (epoch ms). */
	readonly closingSince?: number;
	readonly retryAt?: number;
};

/** What a session keeps from its login to its end, by state. */
export type SessionRecord = {
	/** The record's format; one of format 1 is read too, opened at its authentication time, which it reads as unknown, and of any other not. */
	readonly format: 2;
} & (
	| (Full & { readonly state: "open" })
	| (Full & { readonly state: "closing" })
	| (Full & { readonly state: "closed" })
	/** The mark a close leaves where there was no record. */
	| { readonly state: "closed" }
);

const fullShapeBefore = z.strictObject({
	format: z.literal(1),
	state: z.enum(["open", "closing", "closed"]),
	subject: z.string(),
	amr: z.array(z.string()),
	authenticatedAt: z.number(),
	raisedAt: z.number().optional(),
	raisedAmr: z.array(z.string()).optional(),
	attributes: sourcedAttributesShape.optional(),
	closingSince: z.number().optional(),
	retryAt: z.number().optional(),
});
const fullShape = fullShapeBefore.extend({
	format: z.literal(2),
	openedAt: z.number(),
	authenticatedAtUnknown: z.literal(true).optional(),
});
const markShape = z.strictObject({ format: z.literal([1, 2]), state: z.literal("closed") });
const recordShape = z.union([fullShape, fullShapeBefore, markShape]);

export const toStored = (record: SessionRecord) => record as unknown as StoredSession;
/** The record a kept value holds, checked on every read; nothing for a format or shape this does not know. */
export const fromStored = (stored: StoredSession | undefined): SessionRecord | undefined => {
	const read = recordShape.safeParse(stored);
	if (!read.success) return undefined;
	const data = read.data;
	if (data.format === 2 || !("authenticatedAt" in data))
		return { ...data, format: 2 } as SessionRecord;
	// A record that kept no opening cannot tell whether its time was reported or stood in for one.
	return {
		...data,
		format: 2,
		openedAt: data.authenticatedAt,
		authenticatedAtUnknown: true,
	} as SessionRecord;
};
