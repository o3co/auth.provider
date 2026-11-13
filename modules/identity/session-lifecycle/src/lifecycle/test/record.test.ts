import { expect, it } from "vitest";
import { z } from "zod";
import type { StoredSession } from "../../store.ts";
import { closedFrom, fromStored, type SessionRecord, toStored } from "../record.ts";

const at = 1_800_000_000_000;
const stored = (value: Record<string, unknown>) => value as unknown as StoredSession;

it("reads a record of the format before as opened at its authentication time, which it reads as unknown", () => {
	const before = { state: "open", subject: "alice", amr: ["pwd"], authenticatedAt: at };
	expect(fromStored(stored({ format: 1, ...before }))).toEqual({
		...before,
		format: 2,
		openedAt: at,
		authenticatedAtUnknown: true,
	});
});

it("reads a record of its own format as it is", () => {
	const known = {
		format: 2,
		state: "open",
		subject: "alice",
		amr: ["pwd"],
		authenticatedAt: at - 60_000,
		openedAt: at,
	};
	expect(fromStored(stored(known))).toEqual(known);
	const unknown = { ...known, authenticatedAt: at, authenticatedAtUnknown: true };
	expect(fromStored(stored(unknown))).toEqual(unknown);
});

/**
 * v0.19.1's reader, frozen: the shapes of `modules/identity/session-lifecycle/src/lifecycle/record.ts`
 * at the tag v0.19.1, copied as they were, `attributes` (login-attributes' `sourcedAttributesShape`
 * there) read as anything, as a closed record holds none. Whoever lifts N−1 to 0.20 replaces this
 * copy with 0.20's shapes; it is never edited to follow 0.20.
 */
const before019 = z.strictObject({
	format: z.literal(1),
	state: z.enum(["open", "closing", "closed"]),
	subject: z.string(),
	amr: z.array(z.string()),
	authenticatedAt: z.number(),
	raisedAt: z.number().optional(),
	raisedAmr: z.array(z.string()).optional(),
	attributes: z.unknown().optional(),
	closingSince: z.number().optional(),
	retryAt: z.number().optional(),
});
const reader019 = z.union([
	before019.extend({
		format: z.literal(2),
		openedAt: z.number(),
		authenticatedAtUnknown: z.literal(true).optional(),
	}),
	before019,
	z.strictObject({ format: z.literal([1, 2]), state: z.literal("closed") }),
]);

it("closes a record to its subject and what 0.19 reads, dropping a login's attributes, amr, raise and times", () => {
	const closing = {
		format: 2,
		state: "closing",
		subject: "alice",
		amr: ["pwd", "otp"],
		authenticatedAt: at - 60_000,
		raisedAt: at + 1000,
		raisedAmr: ["otp"],
		attributes: { source: "idp", values: { email: "a@example.com" } },
		openedAt: at,
		closingSince: at + 2000,
		retryAt: at + 3000,
	};
	const read = fromStored(stored(closing));
	expect(read).toMatchObject({ state: "closing", attributes: closing.attributes });
	const closed = closedFrom(read as SessionRecord);
	expect(closed).toEqual({
		format: 2,
		state: "closed",
		subject: "alice",
		amr: [],
		authenticatedAt: at,
		authenticatedAtUnknown: true,
		openedAt: at,
	});
	// A 0.19 host reads it, so a login over its cookie is not unavailable there; and 0.20 reads it.
	expect(reader019.safeParse(closed).success).toBe(true);
	expect(fromStored(toStored(closed))).toEqual(closed);
	// A 0.19 closed mark stays one.
	expect(closedFrom({ format: 2, state: "closed" })).toEqual({ format: 2, state: "closed" });
});
