import { expect, it } from "vitest";
import type { StoredSession } from "../../store.ts";
import { fromStored } from "../record.ts";

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
