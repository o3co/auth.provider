import { createHash } from "node:crypto";
import {
	type Command,
	keysOf,
	type Match,
	storeRead,
	storeWrite,
	writtenValues,
} from "@mod/conformance/testing";

// The store's own names a scene matches its writes by: the space, its records' fields, the
// operations, and how a recovery code is kept, as mfa-store, mfa and mfa-recovery keep them. Nothing
// else in the area names them.

/** The deployment's `redis.prefix`: the adapter's own, as no scene sets one. */
export const prefix = "store";

/** Whether a command is a store call: the adapter sends each as a script. */
export const isStoreCall = (command: Command) => command.name === "EVAL";

/** A recovery code as mfa-recovery keeps it: read whatever the case and hyphens, unsalted. */
const digest = (code: string) =>
	createHash("sha256").update(code.toUpperCase().replaceAll("-", "")).digest("base64url");

/** A subject's factor list as the store holds it: the fields a scene tells its writes by. */
interface FactorList {
	readonly factors?: readonly { readonly kind?: unknown; readonly state?: unknown }[];
}

/**
 * The write that uses the recovery code up: the subject's factor list with the code's digest last
 * among the recovery codes used. A later code's use puts its own last, so it is never this one's; a
 * rewrite of the list for another reason (another factor's state) would match too, and no scene
 * makes one.
 */
export const useOf = (code: string): Match =>
	storeWrite({
		prefix,
		space: "mfa-store.factors",
		operations: ["replaceIf"],
		value: (v) =>
			((v as FactorList).factors ?? []).some(
				(f) =>
					f.kind === "recovery_code" && Array.isArray(f.state) && f.state.at(-1) === digest(code),
			),
	});

/**
 * Any write to a subject's factor list: a factor bound or removed, recovery codes reissued, and the
 * fence a revocation moves (mfa-revocation, a follower), each written on what was read, so a change
 * read before a fence moved finds the list changed and decides again. Not the mark that confirms a
 * read, which changes nothing.
 */
export const factorListWritten: Match = storeWrite({
	prefix,
	space: "mfa-store.factors",
	name: "record",
	operations: ["putIfAbsent", "replaceIf"],
});

/** A read of a subject's revocation boundary: a session's check, comparing its authentication with it. */
export const boundaryRead = (subject: string): Match => {
	const read = storeRead({ prefix, space: "subject-revocation-store.boundaries" });
	return {
		request: (command) =>
			read.request(command) && keysOf(command).some((k) => k.partition === subject),
		succeeded: read.succeeded,
	};
};

/**
 * The writes of a subject's revocation boundary: its record created, or written from what it holds; not
 * the mark that confirms, before the first, that the subject holds none.
 */
export const boundaryOf = (subject: string): Match =>
	storeWrite({
		prefix,
		space: "subject-revocation-store.boundaries",
		partition: subject,
		operations: ["putIfAbsent", "replaceIf"],
	});

/** The boundaries a write of a subject's boundary puts, each a time: its sessions' and its delegations'. */
export const boundariesPut = (command: Command): number[] => {
	const put = writtenValues(command).find(
		(w) => w.key.space === "subject-revocation-store.boundaries" && w.key.name === "record",
	)?.value;
	const value = put && typeof put === "object" && "value" in put ? put.value : put;
	if (typeof value === "number") return [value];
	return value && typeof value === "object"
		? Object.values(value).filter((v): v is number => typeof v === "number")
		: [];
};
